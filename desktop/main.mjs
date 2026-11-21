import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  powerMonitor,
  safeStorage,
  screen,
  shell,
  systemPreferences,
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
// The bundled runtime's CLI. Hosts run its `agent` command, and agents its
// `run --app`, with this app's executable and ELECTRON_RUN_AS_NODE=1.
const AGENT_SCRIPT = app.isPackaged
  ? join(process.resourcesPath, "app.asar", "node_modules", "blinddrop", "dist", "cli.js")
  : fileURLToPath(new URL("node_modules/blinddrop/dist/cli.js", import.meta.url));
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
/** A host whose launch refresh failed is refreshed again this long after each failed attempt. */
const INTEGRATION_RETRY_MS = 5 * 60 * 1000;
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
let integrationOperations = Promise.resolve();
/**
 * The pending retry of failed integration refreshes; at most one at a time.
 * @type {ReturnType<typeof setTimeout> | null}
 */
let integrationRetryTimer = null;
/** An agent's unlock request arrived before the launch window existed. */
let unlockRequestedAtLaunch = false;
/** Power events currently bound to effective vault policies, by event name. */
const powerListeners = new Map();
/** @type {ReturnType<typeof setInterval> | null} */
let idleLockTimer = null;
let idleLockEnabled = false;
let idleLockCheckPending = false;

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
 * @param {boolean} [inactive] Show the window without taking keyboard focus.
 * @returns {import("electron").BrowserWindow}
 */
function createWindow(screenName, inactive = false) {
  const screen = SCREENS[screenName];
  const window = new BrowserWindow({
    show: !inactive,
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
  if (inactive) window.showInactive();
  windowScreens.set(window, screenName);
  restrictNavigation(window.webContents, ui === null ? null : new URL(ui.url).origin);
  return window;
}

/**
 * Create the single owner window, wire its lifecycle, and load the owner page.
 * The `closed` handler leaves the app and the owner server running: closing the
 * window is not quitting, so the session keeps working from the menu bar.
 *
 * @param {boolean} [inactive] Show the window without taking keyboard focus.
 * @param {boolean} [launch] The app's launch window, whose Unlock screen tries
 *   Touch ID or Without asking on its own; a window opened later waits.
 * @returns {Promise<void>}
 */
function createMainWindow(inactive = false, launch = false) {
  mainWindow = createWindow("welcome", inactive);
  mainWindow.on("close", () => {
    rememberWorkspace(mainWindow);
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
    if (settingsWindow !== null && !settingsWindow.isDestroyed()) settingsWindow.close();
  });
  mainWindowLoad = mainWindow.loadURL(launch ? `${ui.launchUrl}&launch=1` : ui.launchUrl);
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
function refreshWindows(detail) {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send("command", "refresh-state", detail);
  }
}

/**
 * An agent's call needs a locked vault. The runtime calls this once per new
 * unlock request. Show the main window and reload its state now, because the
 * page's own refresh skips hidden windows and open dialogs; the page opens the
 * unlock. BlindDrop takes keyboard focus only when none of its windows has it:
 * otherwise the owner may be typing a passphrase in another BlindDrop window,
 * which keeps its keystrokes and stays in front. Before the launch creates its
 * window, opening one here would make a second window: the launch window reads
 * the request from its initial state, and the launch brings it forward.
 */
function showUnlockRequest() {
  if (ui === null || mainWindowLoad === null) {
    unlockRequestedAtLaunch = true;
    return;
  }
  const focused = BrowserWindow.getFocusedWindow();
  if (focused === null) {
    showWindow();
  } else {
    // A minimized window is left minimized: restoring it can take focus.
    if (mainWindow === null || mainWindow.isDestroyed()) void createMainWindow(true);
    else if (!mainWindow.isMinimized()) mainWindow.showInactive();
    focused.moveTop();
  }
  refreshWindows();
  if (focused === null) app.focus({ steal: true });
}

/**
 * An agent's call needs a locked vault (its Without asking vaults were already
 * unlocked where the call asked). Before any window, the runtime shows the
 * system Touch ID prompt for each Touch ID vault the request names, one at a
 * time, or for a request that names none, the vault the Unlock screen would
 * select; it stops at Lock All or Quit. The window comes up only while a vault the
 * request needs is still locked, and the page asks for its passphrase without
 * prompting for Touch ID itself.
 *
 * @param {import("blinddrop/dist/ui.js").UnlockRequest} request
 */
async function handleUnlockRequest(request) {
  const session = ui;
  if (session === null || mainWindowLoad === null) {
    unlockRequestedAtLaunch = true;
    return;
  }
  let unlocked = false;
  try {
    unlocked = await session.quickUnlockRequest(request);
  } catch {
    // The passphrase prompt below remains the fallback.
  }
  // Lock All or Quit ended it (null): no window; a later request asks again.
  if (ui !== session || unlocked === null) return;
  if (unlocked) refreshLockRequiredMenuItems();
  if (session.unlockRequest() !== null) showUnlockRequest();
  else if (unlocked) refreshWindows();
}

/**
 * The page's Touch ID or Without asking unlock when the owner asked, or for an
 * agent request's prompt, the outcome of the app's own attempt. Failures reach
 * the page as a static code; nothing else crosses the bridge.
 *
 * @param {unknown} name
 * @param {unknown} owner
 */
async function quickUnlock(name, owner) {
  if (ui === null || typeof name !== "string") return "failed";
  try {
    return await ui.quickUnlock(name, owner === true);
  } catch {
    return "failed";
  }
}

/**
 * Settings → Vaults → Unlock.
 *
 * @param {unknown} name
 * @param {unknown} mode
 */
async function setUnlockMode(name, mode) {
  if (ui === null || typeof name !== "string" || typeof mode !== "string") return "failed";
  try {
    return await ui.setUnlockMode(name, mode);
  } catch {
    return "failed";
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
 * Cancel older unlock input immediately; reload after session synchronization.
 */
async function lockAll() {
  const session = ui;
  if (session === null) return;
  try {
    const completion = session.lockAll();
    refreshWindows({ lock: "all", intent: true });
    await completion;
    refreshLockRequiredMenuItems();
    refreshWindows();
  } catch {
    console.error(LOCK_FAILED_LOG);
  }
}

/**
 * Apply one automatic-lock event through the owner runtime's saved policies.
 * Windows hear about it only when it locked something; each page then cancels
 * unlock work and editors for exactly the vaults the resulting state shows
 * locked, never for a vault it predicts.
 */
async function lockForEvent(reason, idleSeconds = 0) {
  const session = ui;
  if (session === null) return;
  try {
    const changed = await session.lockForEvent(reason, idleSeconds);
    if (changed) {
      refreshLockRequiredMenuItems();
      refreshWindows();
    }
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
 * Forward one power event to the saved effective vault policies, or stop forwarding it. Registering
 * the same event twice is a no-op, so the page may call `applySettings` after
 * every settings write.
 *
 * @param {"suspend" | "lock-screen"} event
 * @param {"sleep" | "screen-lock"} reason
 * @param {boolean} on
 */
function forwardPowerEvent(event, reason, on) {
  const registered = powerListeners.get(event);
  if (on && registered === undefined) {
    const listener = () => {
      void lockForEvent(reason);
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
 * @param {boolean} on
 */
function applyIdleLock(on) {
  if (on === idleLockEnabled) return;
  if (idleLockTimer !== null) {
    clearInterval(idleLockTimer);
    idleLockTimer = null;
  }
  idleLockEnabled = on;
  if (!on) return;
  idleLockTimer = setInterval(() => {
    if (!hasUnlockedVaults() || idleLockCheckPending) return;
    idleLockCheckPending = true;
    void lockForEvent("idle", powerMonitor.getSystemIdleTime())
      .finally(() => { idleLockCheckPending = false; });
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
  const policies = typeof value.vaultLockPolicies === "object" &&
      value.vaultLockPolicies !== null && !Array.isArray(value.vaultLockPolicies)
    ? Object.values(value.vaultLockPolicies)
    : [];
  const policyUses = (key, predicate) => policies.some(policy =>
    typeof policy === "object" && policy !== null && predicate(policy[key]));
  forwardPowerEvent(
    "suspend",
    "sleep",
    value.lockOnSleep === true || policyUses("lockOnSleep", entry => entry === true),
  );
  forwardPowerEvent(
    "lock-screen",
    "screen-lock",
    value.lockOnScreenLock === true || policyUses("lockOnScreenLock", entry => entry === true),
  );
  applyIdleLock(
    (value.idleLockMinutes > 0 && IDLE_LOCK_MINUTES.has(value.idleLockMinutes)) ||
      policyUses("idleLockMinutes", entry => entry > 0 && IDLE_LOCK_MINUTES.has(entry)),
  );
  refreshLockRequiredMenuItems();
}

/**
 * Serialize native host CLI work. A separate settled tail keeps one failed host
 * command from poisoning later status, update or refresh operations.
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
 * Refresh the managed integrations in the background: every host at launch,
 * then, five minutes after each attempt, the hosts whose CLI was found but
 * whose refresh failed, until none remain. The integration queue keeps it from
 * overlapping Settings' Install, Update and Remove. The next attempt is armed
 * only when the previous one settles and never once shutdown has cleared `ui`,
 * so at most one timer exists.
 *
 * @param {string[]} [retry] Hosts the previous attempt returned.
 */
function refreshIntegrations(retry) {
  void serializeIntegration(() => integrations.refresh(retry)).then(failed => {
    if (ui === null || failed.length === 0) return;
    integrationRetryTimer = setTimeout(() => {
      integrationRetryTimer = null;
      refreshIntegrations(failed);
    }, INTEGRATION_RETRY_MS);
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
  ipcMain.handle("desktop:quick-unlock", (_event, name, owner) => quickUnlock(name, owner));
  ipcMain.handle("desktop:set-unlock-mode", (_event, name, mode) => setUnlockMode(name, mode));
  // Touch ID only: the Keychain is not touched until the owner chooses Touch
  // ID or Without asking, so an owner who keeps Passphrase gets no item.
  ipcMain.handle("desktop:unlock-availability", () => ({
    touchId: systemPreferences.canPromptTouchID(),
  }));
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
    applyIdleLock(false);
    if (integrationRetryTimer !== null) {
      clearTimeout(integrationRetryTimer);
      integrationRetryTimer = null;
    }
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
    ui = await startOwnerUi({
      vaultPath,
      startupVaultPath: requestedVaultPath ?? undefined,
      onUnlockRequested: handleUnlockRequest,
      // An agent's call unlocked a Without asking vault with no window.
      onUnlocked: () => {
        refreshLockRequiredMenuItems();
        refreshWindows();
      },
      quickUnlock: {
        isEncryptionAvailable: () => safeStorage.isEncryptionAvailable(),
        encryptString: plainText => safeStorage.encryptString(plainText),
        decryptString: encrypted => safeStorage.decryptString(encrypted),
        canPromptTouchID: () => systemPreferences.canPromptTouchID(),
        promptTouchID: reason => systemPreferences.promptTouchID(reason),
      },
    });
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
      agentScript: AGENT_SCRIPT,
    });
    // Host CLIs run in the background; a slow host never delays the window.
    refreshIntegrations();
    await applySettings(settings);
    registerBridge();
    buildMenu();
    createTray();
    // The page decides which screen to show and calls `setScreen` for its size.
    await createMainWindow(false, true);
    // `ui` is null if the app began quitting while the window loaded.
    const launchRequest = unlockRequestedAtLaunch && ui !== null ? ui.unlockRequest() : null;
    if (launchRequest !== null) void handleUnlockRequest(launchRequest);
  } catch {
    failStartup();
  }
});
