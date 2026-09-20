// The whole privileged surface the owner page gets. CommonJS, because a
// sandboxed preload cannot be an ES module.
const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("desktop", {
  platform: process.platform,
  /** @param {"open" | "create" | "backup"} kind */
  chooseVault: kind => ipcRenderer.invoke("desktop:choose-vault", kind),
  /** @param {File} file */
  pathForFile: file => webUtils.getPathForFile(file),
  /** @param {string} path */
  revealPath: path => ipcRenderer.invoke("desktop:reveal-path", path),
  /** @param {string} path */
  trashPath: path => ipcRenderer.invoke("desktop:trash-path", path),
  /** @param {string} name */
  setScreen: name => ipcRenderer.invoke("desktop:set-screen", name),
  /** @param {string} [tab] */
  openSettings: tab => ipcRenderer.invoke("desktop:open-settings", tab),
  /** @param {(name: string) => void} callback */
  onCommand: callback => {
    ipcRenderer.on("command", (_event, name) => callback(name));
  },
  /** @param {{ openAtLogin: boolean, lockOnSleep: boolean, lockOnScreenLock: boolean }} settings */
  applySettings: settings => ipcRenderer.invoke("desktop:apply-settings", settings),
});
