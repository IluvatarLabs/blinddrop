import { app, BrowserWindow, dialog } from "electron";

const WINDOW_WIDTH = 1040;
const WINDOW_HEIGHT = 760;
const APP_TITLE = "BlindDrop";
const VAULT_OPTION = "--vault";
const START_FAILED_MESSAGE =
  "BlindDrop could not start the owner interface. Quit BlindDrop and start it again.";
const SHUTDOWN_FAILED_LOG = "BlindDrop: the owner interface did not shut down cleanly.";

/** @type {import("blinddrop/dist/ui.js").OwnerUi | null} */
let ui = null;
/** @type {Promise<void> | null} */
let shutdownPromise = null;
let shutdownComplete = false;

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
 * Returns `undefined` when the option is absent, so the default archive applies,
 * and `null` when it is present without a usable value. A malformed option is
 * never treated as absent: falling back would open the owner's real archive when
 * another one was asked for.
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
 * @param {string} title
 * @returns {import("electron").BrowserWindow}
 */
function createWindow(title) {
  return new BrowserWindow({
    width: WINDOW_WIDTH,
    height: WINDOW_HEIGHT,
    title,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
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
    app.quit();
  });
}

app.on("window-all-closed", () => {
  quit(undefined);
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
  try {
    ({ startOwnerUi } = await import("blinddrop/dist/ui.js"));
    ({ defaultVaultPath } = await import("blinddrop/dist/vault.js"));
  } catch {
    failStartup();
    return;
  }

  try {
    ui = await startOwnerUi({ vaultPath: requestedVaultPath ?? defaultVaultPath() });
  } catch {
    failStartup();
    return;
  }

  // Quit from the page stops the server; the app follows it.
  void ui.closed.then(() => quit(undefined));

  try {
    const window = createWindow(APP_TITLE);
    restrictNavigation(window.webContents, new URL(ui.url).origin);
    await window.loadURL(ui.launchUrl);
  } catch {
    failStartup();
  }
});
