import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  powerMonitor,
  shell,
  Tray,
} from "electron";
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createIntegrationManager } from "./integrations.mjs";

const APP_TITLE = "BlindDrop";
const HELP_URL = "https://github.com/IluvatarLabs/blinddrop";
const RELEASE_URL = "https://github.com/IluvatarLabs/blinddrop/releases/latest";
const VAULT_OPTION = "--vault";
const SETTINGS_FILE = "settings.json";
const VAULT_FILE = "vault.enc";
const PRELOAD = fileURLToPath(new URL("preload.cjs", import.meta.url));
const TRAY_ICON = fileURLToPath(new URL("assets/trayTemplate.png", import.meta.url));
const PLUGIN_ROOT = app.isPackaged
  ? join(process.resourcesPath, "plugin")
  : fileURLToPath(new URL("node_modules/blinddrop/plugin/", import.meta.url));
const START_FAILED_MESSAGE =
  "BlindDrop could not start the owner interface. Quit BlindDrop and start it again.";
const SHUTDOWN_FAILED_LOG = "BlindDrop: the owner interface did not shut down cleanly.";
const LOCK_FAILED_LOG = "BlindDrop: the owner interface could not lock every vault.";
const ABSOLUTE_PATH_REQUIRED = "A file path must be absolute.";

// The page's `--surface` token, resolved to sRGB. Light `oklch(100% 0 0)`,
// dark `oklch(26% 0.01 250)` (`html[data-theme="dark"]`), both from the
// `styles.css` block of the prototypes in `docs/mockups/`. Only the flash the
// window shows before the page paints; the page owns every other colour.
const SURFACE_LIGHT = "#ffffff";
const SURFACE_DARK = "#202429";

/**
 * Window geometry per screen. The page names the screen; the app owns the size.
 *
 * @type {Record<string, { width: number, height: number, resizable: boolean, minWidth: number, minHeight: number }>}
 */
const SCREENS = {
  welcome: { width: 760, height: 560, resizable: false, minWidth: 0, minHeight: 0 },
  unlock: { width: 460, height: 520, resizable: false, minWidth: 0, minHeight: 0 },
  vault: { width: 1236, height: 818, resizable: true, minWidth: 980, minHeight: 640 },
  settings: { width: 720, height: 470, resizable: false, minWidth: 0, minHeight: 0 },
};

/** @type {import("blinddrop/dist/ui.js").OwnerUi | null} */
let ui = null;
/** @type {Promise<void> | null} */
let shutdownPromise = null;
let shutdownComplete = false;
/** @type {import("electron").BrowserWindow | null} */
let mainWindow = null;
/** @type {import("electron").BrowserWindow | null} */
let settingsWindow = null;
/**
 * The menu-bar presence that keeps the app reachable while no window is open.
 * @type {import("electron").Tray | null}
 */
let tray = null;
/** The directory the owner server keeps `settings.json` and `session.json` in. */
let configDir = "";
/** @type {import("./integrations.mjs").IntegrationManager | null} */
let integrations = null;
let appliedSessionPort = null;
/** Power events currently bound to app-global Lock All, by event name. */
const powerListeners = new Map();

/**
 * Deny every new window and every navigation that leaves `allowedOrigin`.
 * `allowedOrigin` of `null` denies all navigation.
 *
 * @param {import("electron").WebContents} contents
 * @param {string | null} allowedOrigin
 */
function restrictNavigation(contents, allowedOrigin) {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event, navigationUrl) => {
    let origin = null;
    try {
      origin = new URL(navigationUrl).origin;
    } catch {
      origin = null;
    }
    if (allowedOrigin === null || origin !== allowedOrigin) event.preventDefault();
  });
}

/**
 * Read the archive path from `--vault <path>` or `--vault=<path>`, mirroring the
 * command-line runtime's global option.
 *
 * Returns `undefined` when the option is absent, so the recorded or default
 * archive applies, and `null` when it is present without a usable value. A
 * malformed option is never treated as absent: falling back would open the
 * owner's real archive when another one was asked for.
 *
 * @param {string[]} argv
 * @returns {string | null | undefined}
 */
function parseVaultPath(argv) {
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === VAULT_OPTION) {
      const value = argv[index + 1];
      if (typeof value !== "string" || value === "" || value.startsWith("-")) return null;
      return value;
    }
    if (argument.startsWith(`${VAULT_OPTION}=`)) {
      const value = argument.slice(VAULT_OPTION.length + 1);
      return value === "" ? null : value;
    }
  }
  return undefined;
}

/**
 * The archive the owner last had open, from the same settings file the owner
 * server writes. Any failure — no file yet, unreadable, not JSON, no record —
 * means the default archive, which is what a first launch needs anyway.
 *
 * @param {string} settingsPath
 * @returns {string | undefined}
 */
function recordedVaultPath(settingsPath) {
  try {
    const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
    const recorded = settings?.lastVault;
    if (typeof recorded === "string" && recorded.length > 0) return recorded;
  } catch {
    // No usable record; the caller falls back.
  }
  return undefined;
}

/**
 * Apply a screen's geometry to one window. The minimum comes first: macOS
 * clamps a smaller `setSize` to the minimum still in force from the last screen.
 *
 * @param {import("electron").BrowserWindow | null} window
 * @param {unknown} name
 */
function applyScreen(window, name) {
  if (window === null || window.isDestroyed()) return;
  const screen = typeof name === "string" ? SCREENS[name] : undefined;
  if (screen === undefined) return;
  window.setMinimumSize(screen.minWidth, screen.minHeight);
  window.setResizable(screen.resizable);
  window.setSize(screen.width, screen.height);
  window.center();
}

/**
 * @param {keyof typeof SCREENS} screenName
 * @returns {import("electron").BrowserWindow}
 */
function createWindow(screenName) {
  const screen = SCREENS[screenName];
  const window = new BrowserWindow({
    width: screen.width,
    height: screen.height,
    minWidth: screen.minWidth,
    minHeight: screen.minHeight,
    resizable: screen.resizable,
    title: APP_TITLE,
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 14, y: 20 },
    backgroundColor: nativeTheme.shouldUseDarkColors ? SURFACE_DARK : SURFACE_LIGHT,
    webPreferences: {
      preload: PRELOAD,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  restrictNavigation(window.webContents, ui === null ? null : new URL(ui.url).origin);
  return window;
}

/**
 * Create the single owner window, wire its lifecycle, and load the owner page.
 * The `closed` handler leaves the app and the owner server running: closing the
 * window is not quitting, so the session keeps working from the menu bar.
 *
 * @returns {Promise<void>}
 */
function createMainWindow() {
  mainWindow = createWindow("welcome");
  mainWindow.on("closed", () => {
    mainWindow = null;
    if (settingsWindow !== null && !settingsWindow.isDestroyed()) settingsWindow.close();
  });
  return mainWindow.loadURL(ui.launchUrl);
}

/**
 * Reopen the owner window: focus the one already open, else create it exactly as
 * the first launch did. One window at a time. A no-op until the owner server is
 * ready, so an early `activate` at launch cannot make a second window.
 */
function showWindow() {
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    return;
  }
  if (ui === null) return;
  void createMainWindow();
}

/**
 * Open the settings window, or focus the one already open. It has no parent:
 * closing it leaves the session and the main window alone.
 *
 * @param {unknown} tab
 */
function openSettings(tab) {
  if (settingsWindow !== null && !settingsWindow.isDestroyed()) {
    settingsWindow.focus();
    return;
  }
  if (ui === null) return;
  const name = typeof tab === "string" && tab !== "" ? tab : "general";
  settingsWindow = createWindow("settings");
  settingsWindow.on("closed", () => {
    settingsWindow = null;
  });
  void settingsWindow.loadURL(
    `${ui.launchUrl}&screen=settings&tab=${encodeURIComponent(name)}`,
  );
}

/**
 * Deliver a workspace command to the one main page. If the app is resident
 * with no main window, recreate it and wait for its page before dispatching.
 * Settings never becomes an accidental command target.
 *
 * @param {string} name
 */
async function sendMainCommand(name) {
  if (ui === null) return;
  if (mainWindow === null || mainWindow.isDestroyed()) await createMainWindow();
  const target = mainWindow;
  if (target === null || target.isDestroyed()) return;
  if (target.isMinimized()) target.restore();
  target.show();
  target.focus();
  if (target.webContents.isLoadingMainFrame()) {
    await new Promise(resolve => target.webContents.once("did-finish-load", resolve));
  }
  if (target === mainWindow && !target.isDestroyed()) target.webContents.send("command", name);
}

/** Refresh every owner view from the runtime's authoritative state. */
function refreshWindows() {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send("command", "refresh-state");
  }
}

/**
 * Lock every vault through the owner runtime, independent of window/focus.
 * Session synchronization completes before any open view is told to reload.
 */
async function lockAll() {
  const session = ui;
  if (session === null) return;
  try {
    await session.lockAll();
    refreshWindows();
  } catch {
    console.error(LOCK_FAILED_LOG);
  }
}

/**
 * @param {string} label
 * @param {string} command
 * @param {string} [accelerator]
 * @returns {import("electron").MenuItemConstructorOptions}
 */
function item(label, command, accelerator) {
  return {
    label,
    ...(accelerator === undefined ? {} : { accelerator }),
    click: () => {
      void sendMainCommand(command);
    },
  };
}

/** Build the one application menu. Roles keep their macOS labels and shortcuts. */
function buildMenu() {
  /** @type {import("electron").MenuItemConstructorOptions[]} */
  const template = [
    {
      label: APP_TITLE,
      submenu: [
        item(`About ${APP_TITLE}`, "about"),
        { type: "separator" },
        {
          label: "Settings…",
          accelerator: "Command+,",
          click: () => openSettings(),
        },
        { type: "separator" },
        {
          label: "Lock All",
          accelerator: "Command+L",
          click: () => {
            void lockAll();
          },
        },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "File",
      submenu: [
        item("New connection…", "new-connection", "Command+N"),
        item("New secret…", "new-secret", "Shift+Command+N"),
        { type: "separator" },
        item("Import .env file…", "import-env"),
        item("Import connection definition…", "import-json"),
        { type: "separator" },
        item("Open vault…", "open-vault", "Command+O"),
        item("Export Encrypted Vault…", "backup"),
        { type: "separator" },
        { role: "close", label: "Close window" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
        { type: "separator" },
        item("Find", "focus-search", "Command+F"),
      ],
    },
    {
      label: "View",
      submenu: [
        item("As list", "mode-list", "Command+1"),
        item("As table", "mode-table", "Command+2"),
        { type: "separator" },
        item("Show sidebar", "toggle-sidebar", "Control+Command+S"),
        { type: "separator" },
        item("Connections", "view-connections"),
        item("Secrets", "view-secrets"),
        item("Activity", "view-activity"),
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        { type: "separator" },
        { role: "front" },
      ],
    },
    {
      role: "help",
      submenu: [
        {
          label: `${APP_TITLE} Help`,
          click: () => {
            void shell.openExternal(HELP_URL);
          },
        },
        item("Keyboard shortcuts", "shortcuts", "Command+/"),
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

/**
 * The menu-bar (status bar) presence that keeps the app reachable with no
 * window. Its bundled template image renders as a monochrome icon that adapts
 * to light and dark menu bars.
 * Exactly two items: open the window, or quit everything. Left-clicking the
 * icon also opens or focuses the window.
 */
function createTray() {
  const image = nativeImage.createFromPath(TRAY_ICON);
  image.setTemplateImage(true);
  tray = new Tray(image);
  tray.setToolTip(APP_TITLE);
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: `Open ${APP_TITLE}`, click: () => showWindow() },
      { type: "separator" },
      { label: `Quit ${APP_TITLE}`, click: () => app.quit() },
    ]),
  );
  tray.on("click", () => showWindow());
}

/**
 * Turn one power event into app-global Lock All, or stop forwarding it. Registering
 * the same event twice is a no-op, so the page may call `applySettings` after
 * every settings write.
 *
 * @param {"suspend" | "lock-screen"} event
 * @param {boolean} on
 */
function forwardPowerEvent(event, on) {
  const registered = powerListeners.get(event);
  if (on && registered === undefined) {
    const listener = () => {
      void lockAll();
    };
    powerMonitor.on(event, listener);
    powerListeners.set(event, listener);
  } else if (!on && registered !== undefined) {
    powerMonitor.removeListener(event, registered);
    powerListeners.delete(event);
  }
}

/**
 * @param {unknown} settings
 */
async function applySettings(settings, refreshIntegrations = true) {
  const value = typeof settings === "object" && settings !== null ? settings : {};
  // Only touch the login item when the setting differs: macOS refuses the call for an
  // unsigned build and logs an error even when nothing would change.
  const openAtLogin = value.openAtLogin === true;
  if (app.getLoginItemSettings().openAtLogin !== openAtLogin) {
    app.setLoginItemSettings({ openAtLogin });
  }
  forwardPowerEvent("suspend", value.lockOnSleep === true);
  forwardPowerEvent("lock-screen", value.lockOnScreenLock === true);
  const sessionPort = Number.isInteger(value.sessionPort) ? value.sessionPort : 8787;
  if (
    integrations !== null &&
    refreshIntegrations &&
    sessionPort !== appliedSessionPort
  ) {
    await integrations.applyEndpoint(sessionPort);
  }
  appliedSessionPort = sessionPort;
}

/**
 * @param {unknown} kind
 * @returns {Promise<string | null>}
 */
async function chooseVault(kind) {
  if (kind === "open") {
    const result = await dialog.showOpenDialog({
      filters: [{ name: "Vault", extensions: ["enc"] }],
      properties: ["openFile"],
    });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  }
  if (kind === "create") {
    const result = await dialog.showSaveDialog({ defaultPath: join(configDir, VAULT_FILE) });
    return result.canceled ? null : (result.filePath || null);
  }
  if (kind === "backup") {
    const today = new Date().toISOString().slice(0, 10);
    const result = await dialog.showSaveDialog({
      defaultPath: join(app.getPath("documents"), `vault-${today}.enc`),
    });
    return result.canceled ? null : (result.filePath || null);
  }
  return null;
}

/**
 * Pick the one setup-backup folder. Backup may create a new folder; restore
 * only selects an existing source. The owner API validates its contents.
 *
 * @param {unknown} kind
 * @returns {Promise<string | null>}
 */
async function chooseSetupFolder(kind) {
  if (kind === "backup") {
    const today = new Date().toISOString().slice(0, 10);
    const result = await dialog.showSaveDialog({
      title: "Back Up Setup",
      defaultPath: join(app.getPath("documents"), `BlindDrop Setup ${today}`),
      buttonLabel: "Back Up",
    });
    return result.canceled ? null : (result.filePath || null);
  }
  if (kind === "restore") {
    const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  }
  return null;
}

/**
 * @param {unknown} target
 * @returns {string}
 */
function absolutePath(target) {
  if (typeof target !== "string" || !isAbsolute(target)) throw new Error(ABSOLUTE_PATH_REQUIRED);
  return target;
}

/** The whole bridge. Nothing else crosses from the page into the app. */
function registerBridge() {
  ipcMain.handle("desktop:choose-vault", (_event, kind) => chooseVault(kind));
  ipcMain.handle("desktop:choose-setup-folder", (_event, kind) => chooseSetupFolder(kind));
  ipcMain.handle("desktop:reveal-path", (_event, target) => {
    shell.showItemInFolder(absolutePath(target));
  });
  ipcMain.handle("desktop:trash-path", (_event, target) => shell.trashItem(absolutePath(target)));
  ipcMain.handle("desktop:set-screen", (event, name) => {
    applyScreen(BrowserWindow.fromWebContents(event.sender), name);
  });
  ipcMain.handle("desktop:open-settings", (_event, tab) => {
    openSettings(tab);
  });
  ipcMain.handle("desktop:apply-settings", (_event, settings) => applySettings(settings));
  ipcMain.handle("desktop:open-release-page", () => shell.openExternal(RELEASE_URL));
  ipcMain.handle("desktop:get-integrations", () => integrations?.getIntegrations());
  ipcMain.handle("desktop:manage-integration", (_event, input) =>
    integrations?.manageIntegration(input),
  );
}

/** Show a static message and quit. Never reports the cause, which can carry the URL. */
function failStartup() {
  dialog.showErrorBox(APP_TITLE, START_FAILED_MESSAGE);
  app.quit();
}

/**
 * Close the owner interface exactly once. Resolves even when close fails, so a
 * failed shutdown cannot trap the app open.
 *
 * @returns {Promise<void>}
 */
function shutdown() {
  if (shutdownPromise === null) {
    const session = ui;
    ui = null;
    shutdownPromise = (session === null ? Promise.resolve() : session.close()).catch(() => {
      console.error(SHUTDOWN_FAILED_LOG);
    });
  }
  return shutdownPromise;
}

/**
 * Stop the owner interface, then quit. Re-entrant: the second pass, raised by
 * `app.quit()` itself, lets the quit through.
 *
 * @param {import("electron").Event | undefined} event
 */
function quit(event) {
  if (shutdownComplete) return;
  event?.preventDefault();
  void shutdown().then(() => {
    shutdownComplete = true;
    if (tray !== null && !tray.isDestroyed()) {
      tray.destroy();
      tray = null;
    }
    app.quit();
  });
}

// Electron quits when the last window closes unless this event is handled.
// BlindDrop stays resident with its owner runtime and menu-bar item; Quit is
// the only path that tears the runtime down.
app.on("window-all-closed", () => {});

app.on("activate", () => {
  showWindow();
});

app.on("before-quit", event => {
  quit(event);
});

app.whenReady().then(async () => {
  const requestedVaultPath = parseVaultPath(process.argv);
  if (requestedVaultPath === null) {
    failStartup();
    return;
  }

  let startOwnerUi;
  let defaultVaultPath;
  let readSettings;
  try {
    ({ startOwnerUi } = await import("blinddrop/dist/ui.js"));
    ({ defaultVaultPath } = await import("blinddrop/dist/vault.js"));
    ({ readSettings } = await import("blinddrop/dist/owner-files.js"));
  } catch {
    failStartup();
    return;
  }

  let vaultPath;
  try {
    const defaultPath = defaultVaultPath();
    configDir = dirname(defaultPath);
    vaultPath =
      requestedVaultPath ??
      recordedVaultPath(join(configDir, SETTINGS_FILE)) ??
      defaultPath;
  } catch {
    failStartup();
    return;
  }

  try {
    ui = await startOwnerUi({ vaultPath });
  } catch {
    failStartup();
    return;
  }

  // Quit from the page stops the server; the app follows it.
  void ui.closed.then(() => quit(undefined));

  try {
    let settings;
    try {
      settings = readSettings(configDir);
    } catch {
      settings = {
        openAtLogin: false,
        lockOnSleep: true,
        lockOnScreenLock: false,
        sessionPort: 8787,
      };
    }
    integrations = createIntegrationManager({
      configDir,
      pluginRoot: PLUGIN_ROOT,
      executablePath: process.execPath,
      endpointPort: settings.sessionPort,
    });
    appliedSessionPort = settings.sessionPort;
    await applySettings(settings, false);
    registerBridge();
    buildMenu();
    createTray();
    // The page decides which screen to show and calls `setScreen` for its size.
    await createMainWindow();
  } catch {
    failStartup();
  }
});
