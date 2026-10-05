# BlindDrop macOS app

A thin Electron shell around the BlindDrop owner interface. The app starts the
same owner server the `blinddrop ui` command starts, in its own main process, and
shows the same page in a native window. The shell adds no separate secret store
or archive: the embedded owner server owns vault operations and holds unlocked
passphrases in memory, exactly as in the browser workflow. What the app adds is
the macOS around it — the window and its
sizes, the application menu, native file dialogs, Reveal in Finder, Move to
Trash, Open at login, and locking when the Mac sleeps or the screen locks.

For normal use, download the Mac app from the [release page](https://github.com/IluvatarLabs/blinddrop/releases/latest), move it into Applications and open it. No Node, global CLI or PATH setup is needed. Create or open a vault, save a connection from a template, and install the Claude Code/local Codex integration under Settings → Sessions. The prerequisites below apply only to building from source.

The native app targets macOS. Other platforms need their own verification.

## Prerequisites

- Node 22 and npm. The runtime requires `^22.13.0 || >=23.5.0`, but the build
  toolchain does not work on Node 26: `electron-forge` exits silently with
  status 0 while extracting the Electron archive and writes no `out/`. Build and
  run under Node 22. If Node 22 is not the default `node` on the machine, put it
  first on the path for the command:

  ```sh
  PATH=/usr/local/bin:$PATH npm run make
  ```

  Replace `/usr/local/bin` with whichever directory holds the Node 22 binary.
- macOS. The build targets the architecture of the machine it runs on.

## Build and run

Run all four commands from this directory.

```sh
npm run vendor    # pack the runtime in the repository root into vendor/
npm install       # install Electron, Electron Forge, and the packed runtime
npm start         # run the app from source
npm run make      # build a distributable .app
```

`npm run vendor` writes `vendor/blinddrop-<version>.tgz`. `npm install` then
installs that tarball as the `blinddrop` dependency, so the app always hosts a
packed copy of the runtime rather than the working tree. After changing the
runtime or owner page without changing its version, explicitly refresh the local
tarball dependency; an ordinary install can retain the previous copy:

```sh
npm run vendor
npm install --force ./vendor/blinddrop-0.6.0.tgz
```

`package-lock.json` is not committed. The only entry under `dependencies` is the
vendored tarball, and npm records an integrity hash for it; `npm run vendor`
produces a new tarball on every runtime change, so a committed lock file would
be stale immediately and `npm ci` could never resolve it, because `vendor/` is
not committed either. The three build dependencies are pinned to exact versions
in `package.json` instead.

The first `npm start` or `npm run make` downloads the Electron binary (about
115 MB) into `node_modules/electron/dist`. Electron fetches it on first use
rather than from an install script, so nothing is downloaded during
`npm install`.

`npm run package` produces the app bundle at
`out/BlindDrop-darwin-<arch>/BlindDrop.app`. `npm run make` produces that bundle
and a zip of it at
`out/make/zip/darwin/<arch>/BlindDrop-darwin-<arch>-<version>.zip`.

### Which archive the app opens

Nothing has to exist before the first launch. The app picks a vault in this
order:

1. `--vault <path>`, mirroring the runtime's global option.
2. `lastVault` from the settings file, which the owner page records whenever a
   vault is created or unlocked.
3. `~/.config/blinddrop/vault.enc`, the runtime's default path.

The page, not the app, decides what to show: the unlock screen when that file
exists, the welcome screen when it does not. From the welcome screen the owner
creates a vault anywhere, or opens an existing one, and `File › Open vault…`
(⌘O) does the same later.

From source, the argument goes after a second `--`, because the first one
belongs to npm:

```sh
npm start -- -- --vault <path>
```

The built app takes it directly:

```sh
open out/BlindDrop-darwin-<arch>/BlindDrop.app --args --vault <path>
```

`--vault` without a usable value is refused rather than ignored, so a mistyped
option cannot quietly open another archive instead.

### The settings file

Settings live at `<config dir>/settings.json` with mode 0600, where
`<config dir>` is the directory of the default vault path
(`~/.config/blinddrop`). The owner server owns that file; the app reads it once
at start for the selected archive and native settings, and never writes it directly. It also holds the
appearance, the session port and session-file switches, the recent vaults, the
last backup time, and the three macOS switches the app acts on: Open at login,
Lock when the Mac sleeps and Lock when the screen locks.

## Running the built app

Launch `BlindDrop.app` from Finder. The release notes identify the signing and notarization status of each downloadable artifact. Replacing the app preserves the separate owner data directory; quit first, replace the app, then reopen and unlock. Settings → General links to the canonical release page. There is no automatic updater.

For release builds, Forge accepts an explicit Developer ID Application identity through `BLINDDROP_SIGN_IDENTITY`, and a notarization Keychain profile through `BLINDDROP_NOTARY_KEYCHAIN_PROFILE`. The standard `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` alternative is also accepted by the build configuration. Keep credentials out of source and command logs. Without a Developer ID identity, the build is unsigned; a Development/App Store identity is not a direct-download substitute. Verify the produced artifact's signature, notarization and Gatekeeper assessment before labeling it signed/notarized.

## What the app does

On launch the app starts the owner server on a loopback port with a fresh
one-time token, then loads that page in its main window. Neither window can
navigate away from the owner server's origin, and neither can open a new one.

The window uses the macOS unified toolbar (`hiddenInset`): the real traffic
lights sit over the titlebar the page draws. The app owns the window size and
sets it from the screen the page names — welcome 760×560, unlock 460×520,
vault 1236×818 (resizable, minimum 980×640) — re-centring on each change.

`Settings…` (⌘,) opens a second 720×470 window on the same owner server. It has
no parent: ⌘W closes it and nothing else changes, and closing the main window
closes it too while the app remains available in the menu bar.

The application menu is the only App, File, Edit, View, Window and Help menu;
the page draws no menu bar of its own in the app. Workspace menu commands focus or reopen the main window. Lock All calls the owner runtime directly, including with no open window; Settings opens independently.

A startup failure shows a static error and quits rather than opening an unusable window.

The menu bar uses one monochrome template icon, with Open and Quit. Saved sleep/screen-lock choices apply from startup even while no window is open. The default remains lock-on-sleep on and lock-on-screen-lock off.

## Integrations and recovery

Settings manages only this app's Claude Code and local Codex integration through native host plugin commands. Helpers and hooks use the bundled runtime. Configured status is distinct from authenticated use; the page shows the managed version and required host reload. Update repairs the managed installation after app replacement or moving it. Unrelated host configuration is preserved.

Export Encrypted Vault copies one archive. Back Up Setup additionally includes the registry, connection definitions, groups and settings; these remain owner-only plaintext metadata alongside encrypted vaults. Restore Setup accepts only an empty app configuration and leaves all vaults locked. It never merges or overwrites existing owner data.

## Security

Unlocking a vault starts or recomputes the agent session. Locking a vault removes
the connections that need it; locking every vault or quitting ends agent access.
The passphrase is held by the owner server in the app's main process memory,
the agent session listener dies with the process, and the session file it wrote
is deleted. There is no daemon and no launch agent: the vault is reachable only
while the owner has the app running and the required vaults unlocked. Open at login, when the owner
turns it on in Settings, starts the app locked like any other launch.

Closing the main window leaves the app and unlocked session running. Use the
menu-bar icon to reopen the window or quit the app; Quit ends the session.

Both windows run with context isolation on, Node integration off, and the
renderer sandbox on. The page reaches the owner server over loopback HTTP
exactly as the browser does. The preload script adds one bridge,
`window.desktop`, and nothing else: the platform name, the file dialogs for
choosing a vault, the path of a dropped file, Reveal in Finder, Move to Trash,
the screen size and settings-window calls, the menu-command subscription,
native settings, managed integration actions, setup-folder selection and the fixed release-page link. No `ipcRenderer`, `require` or arbitrary channel
is exposed, and every path the bridge acts on must be absolute.
