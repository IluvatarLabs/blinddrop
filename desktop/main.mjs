import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  powerMonitor,
  screen,
  shell,
  Tray,
} from "electron";
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createIntegrationManager } from "./integrations.mjs";

const APP_TITLE = "BlindDrop";
const HELP_URL = "https://github.com/IluvatarLabs/blinddrop";
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

// The page's current `--surface` tokens. This is only the native frame and the
// flash before the page paints; the page owns every other colour.
const SURFACE_LIGHT = "#f6f6f7";
const SURFACE_DARK = "#292b2f";

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
const SETTINGS_TABS = new Set(["general", "security", "sessions", "vault", "advanced"]);
const IDLE_LOCK_MINUTES = new Set([1, 5, 15, 30, 60]);
const LOCK_REQUIRED_COMMANDS = new Set([
  "new-connection",
  "new-secret",
  "import-env",
  "import-json",
  "backup",
  "focus-search",
  "mode-list",
  "mode-table",
  "toggle-sidebar",
  "view-connections",
  "view-secrets",
  "view-activity",
]);

/** @type {import("blinddrop/dist/ui.js").OwnerUi | null} */
let ui = null;
/** @type {Promise<void> | null} */
let shutdownPromise = null;
let shutdownComplete = false;
/** @type {import("electron").BrowserWindow | null} */
let mainWindow = null;
/** @type {Promise<void> | null} */
let mainWindowLoad = null;
/** @type {import("electron").BrowserWindow | null} */
let settingsWindow = null;
/** The screen currently occupying each native window. */
const windowScreens = new WeakMap();
/**
 * The owner's workspace placement for this app run. Compact lock/welcome
 * screens must not erase it, and closing the UI while the app remains resident
 * must not either.
 *
 * @type {{ bounds: import("electron").Rectangle, maximized: boolean } | null}
 */
let workspacePlacement = null;
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
let integrationOperations = Promise.resolve();
/** Power events currently bound to app-global Lock All, by event name. */
const powerListeners = new Map();
/** @type {ReturnType<typeof setInterval> | null} */
let idleLockTimer = null;
let appliedIdleLockMinutes = 0;

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
  const next = typeof name === "string" ? SCREENS[name] : undefined;
  if (next === undefined || windowScreens.get(window) === name) return;

  if (windowScreens.get(window) === "vault") rememberWorkspace(window);

  if (name === "vault" && workspacePlacement !== null) {
    if (window.isMaximized()) window.unmaximize();
    window.setMinimumSize(next.minWidth, next.minHeight);
    window.setResizable(next.resizable);
    window.setBounds(workspacePlacement.bounds);
    if (workspacePlacement.maximized) window.maximize();
  } else {
    if (window.isMaximized()) window.unmaximize();
    window.setMinimumSize(next.minWidth, next.minHeight);
    window.setResizable(next.resizable);
    resizeAroundCurrentCenter(window, next.width, next.height);
  }
  windowScreens.set(window, name);
}

/** Remember a user-sized workspace without replacing it with compact bounds. */
function rememberWorkspace(window) {
  if (window.isDestroyed() || windowScreens.get(window) !== "vault") return;
  workspacePlacement = {
    bounds: window.getNormalBounds(),
    maximized: window.isMaximized(),
  };
}

/**
 * Resize around the window's current centre and clamp only when the result
 * would leave the display work area. New windows are centred once by
 * `createWindow`; later screen changes preserve the owner's placement.
 */
function resizeAroundCurrentCenter(window, width, height) {
  const current = window.getBounds();
  const workArea = screen.getDisplayMatching(current).workArea;
  const desiredX = Math.round(current.x + (current.width - width) / 2);
  const desiredY = Math.round(current.y + (current.height - height) / 2);
  const maxX = workArea.x + Math.max(0, workArea.width - width);
  const maxY = workArea.y + Math.max(0, workArea.height - height);
  window.setBounds({
    x: Math.min(Math.max(desiredX, workArea.x), maxX),
    y: Math.min(Math.max(desiredY, workArea.y), maxY),
    width,
    height,
  });
}

function nativeBackgroundColor() {
  return nativeTheme.shouldUseDarkColors ? SURFACE_DARK : SURFACE_LIGHT;
}

/** Keep the native frame and pre-paint background aligned with the page. */
function refreshNativeAppearance() {
  const background = nativeBackgroundColor();
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.setBackgroundColor(background);
  }
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
    backgroundColor: nativeBackgroundColor(),
    webPreferences: {
      preload: PRELOAD,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  window.center();
  windowScreens.set(window, screenName);
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
  mainWindow.on("close", () => {
    rememberWorkspace(mainWindow);
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
    if (settingsWindow !== null && !settingsWindow.isDestroyed()) settingsWindow.close();
  });
  mainWindowLoad = mainWindow.loadURL(ui.launchUrl);
  return mainWindowLoad;
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
  const requestedTab = typeof tab === "string" && SETTINGS_TABS.has(tab) ? tab : null;
  if (settingsWindow !== null && !settingsWindow.isDestroyed()) {
    const target = settingsWindow;
    const selectTab = () => {
      if (!target.isDestroyed() && requestedTab !== null) {
        target.webContents.send("command", "settings-tab", requestedTab);
      }
    };
    if (requestedTab !== null && target.webContents.isLoadingMainFrame()) {
      target.webContents.once("did-finish-load", selectTab);
    } else if (requestedTab !== null) {
      selectTab();
    }
    if (target.isMinimized()) target.restore();
    target.show();
    target.focus();
    return;
  }
  if (ui === null) return;
  const name = requestedTab ?? "general";
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
  let target = mainWindow;
  let load = mainWindowLoad;
  if (target === null || target.isDestroyed()) {
    load = createMainWindow();
    target = mainWindow;
  }
  if (load !== null) await load;
  if (target === null || target.isDestroyed()) return;
  if (target.isMinimized()) target.restore();
  target.show();
  target.focus();
  if (target === mainWindow && !target.isDestroyed()) target.webContents.send("command", name);
}

/** Refresh every owner view from the runtime's authoritative state. */
function refreshWindows() {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send("command", "refresh-state");
  }
}

/** The owner runtime, rather than a renderer or window, owns lock state. */
function hasUnlockedVaults() {
  return ui?.hasUnlockedVaults() === true;
}

/** Keep native commands aligned with the owner runtime's current lock state. */
function refreshLockRequiredMenuItems() {
  const menu = Menu.getApplicationMenu();
  if (menu === null) return;
  const enabled = hasUnlockedVaults();
  const lock = menu.getMenuItemById("command:lock");
  if (lock !== null) lock.enabled = enabled;
  for (const command of LOCK_REQUIRED_COMMANDS) {
    const item = menu.getMenuItemById(`command:${command}`);
    if (item !== null) item.enabled = enabled;
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
    refreshLockRequiredMenuItems();
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
  const requiresUnlocked = LOCK_REQUIRED_COMMANDS.has(command);
  return {
    id: `command:${command}`,
    label,
    enabled: !requiresUnlocked || hasUnlockedVaults(),
    ...(accelerator === undefined ? {} : { accelerator }),
    click: () => {
      if (requiresUnlocked && !hasUnlockedVaults()) {
        refreshLockRequiredMenuItems();
        return;
      }
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
          id: "command:lock",
          label: "Lock All",
          accelerator: "Command+L",
          enabled: hasUnlockedVaults(),
          click: () => {
            if (hasUnlockedVaults()) void lockAll();
            else refreshLockRequiredMenuItems();
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
  refreshLockRequiredMenuItems();
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
  const contextMenu = Menu.buildFromTemplate([
    { label: `Open ${APP_TITLE}`, click: () => showWindow() },
    { type: "separator" },
    { label: `Quit ${APP_TITLE}`, click: () => app.quit() },
  ]);
  if (process.platform === "darwin") {
    tray.on("right-click", () => tray?.popUpContextMenu(contextMenu));
  } else {
    tray.setContextMenu(contextMenu);
  }
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
 * Apply the saved idle-lock threshold to Electron's system-wide idle clock.
 * The timer lives in the main process, so closing every window does not stop it.
 *
 * @param {unknown} minutes
 */
function applyIdleLock(minutes) {
  const next = IDLE_LOCK_MINUTES.has(minutes) ? minutes : 0;
  if (next === appliedIdleLockMinutes) return;
  if (idleLockTimer !== null) {
    clearInterval(idleLockTimer);
    idleLockTimer = null;
  }
  appliedIdleLockMinutes = next;
  if (next === 0) return;
  idleLockTimer = setInterval(() => {
    const thresholdSeconds = appliedIdleLockMinutes * 60;
    if (
      thresholdSeconds > 0 &&
      hasUnlockedVaults() &&
      powerMonitor.getSystemIdleTime() >= thresholdSeconds
    ) {
      void lockAll();
    }
  }, 1000);
}

/**
 * @param {unknown} settings
 */
async function applySettings(settings) {
  const value = typeof settings === "object" && settings !== null ? settings : {};
  nativeTheme.themeSource = ["system", "light", "dark"].includes(value.appearance)
    ? value.appearance
    : "system";
  refreshNativeAppearance();
  // Only touch the login item when the setting differs: macOS refuses the call for an
  // unsigned build and logs an error even when nothing would change.
  const openAtLogin = value.openAtLogin === true;
  if (app.getLoginItemSettings().openAtLogin !== openAtLogin) {
    app.setLoginItemSettings({ openAtLogin });
  }
  const showDockIcon = value.showDockIcon !== false;
  if (app.dock !== undefined && app.dock.isVisible() !== showDockIcon) {
    if (showDockIcon) await app.dock.show();
    else app.dock.hide();
  }
  forwardPowerEvent("suspend", value.lockOnSleep === true);
  forwardPowerEvent("lock-screen", value.lockOnScreenLock === true);
  applyIdleLock(value.idleLockMinutes);
  refreshLockRequiredMenuItems();
}

/**
 * Serialize native host CLI work. A separate settled tail keeps one failed host
 * command from poisoning later status, update or endpoint operations.
 *
 * @template T
 * @param {() => T | Promise<T>} operation
 * @returns {Promise<T>}
 */
function serializeIntegration(operation) {
  const result = integrationOperations.then(operation, operation);
  integrationOperations = result.then(() => undefined, () => undefined);
  return result;
}

/**
 * Keep native host configuration ordered without making owner lock/session work
 * wait for a host CLI. The owner runtime persists and binds the port first.
 *
 * @param {number} port
 */
function queueIntegrationEndpoint(port) {
  if (
    integrations === null ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    port === appliedSessionPort
  ) return;
  appliedSessionPort = port;
  void serializeIntegration(() => integrations.applyEndpoint(port)).catch(() => {
    integrations?.markEndpointRefreshFailed();
  });
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
  ipcMain.handle("desktop:send-main-command", (_event, name) => sendMainCommand(name));
  ipcMain.handle("desktop:apply-settings", (_event, settings) => applySettings(settings));
  ipcMain.handle("desktop:get-integrations", () =>
    serializeIntegration(() => integrations?.getIntegrations()),
  );
  ipcMain.handle("desktop:manage-integration", (_event, input) =>
    serializeIntegration(() => integrations?.manageIntegration(input)),
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
    applyIdleLock(0);
    const session = ui;
    ui = null;
    shutdownPromise = (session === null ? Promise.resolve() : session.close()).catch(() => {
      console.error(SHUTDOWN_FAILED_LOG);
    });
  }
  return shutdownPromise;
}

/**
 * Stop the owner interface, then exit. The first `app.quit()` was cancelled so
 * cleanup could finish; do not re-enter that cancelled native quit flow.
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
    app.exit(0);
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
  nativeTheme.on("updated", refreshNativeAppearance);
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
    ui = await startOwnerUi({ vaultPath, onSessionPortChanged: queueIntegrationEndpoint });
  } catch {
    failStartup();
    return;
  }

  // Quit from the page stops the server; the app follows it.
  void ui.closed.then(() => quit(undefined));

  try {
    const settings = readSettings(configDir);
    integrations = createIntegrationManager({
      configDir,
      pluginRoot: PLUGIN_ROOT,
      executablePath: process.execPath,
      endpointPort: settings.sessionPort,
    });
    queueIntegrationEndpoint(settings.sessionPort);
    await applySettings(settings);
    registerBridge();
    buildMenu();
    createTray();
    // The page decides which screen to show and calls `setScreen` for its size.
    await createMainWindow();
  } catch {
    failStartup();
  }
});
