# BlindDrop macOS app

A thin Electron shell around the BlindDrop owner interface. The app starts the
same owner server the `blinddrop ui` command starts, in its own main process, and
shows the same page in a native window. The shell adds no separate secret store
or archive: the embedded owner server owns vault operations and holds unlocked
passphrases in memory, exactly as in the browser workflow. The one exception is
opt-in: a vault set to Touch ID or Without asking keeps its passphrase sealed
with the app's Keychain key (see The settings file). What the app adds is
the macOS around it — the window and its
sizes, the application menu, native file dialogs, Reveal in Finder, Move to
Trash, Open at login, Touch ID, and locking when the Mac sleeps or the screen locks.

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
npm install --force ./vendor/blinddrop-0.6.2.tgz
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
   vault is created or unlocked, except a Without asking unlock for an agent's
   call.
3. `~/.config/blinddrop/vault.enc`, the runtime's default path.

The page, not the app, decides what to show: Unlock for an existing setup,
including registered files that are missing, and Welcome for first use.
Missing files offer Locate file; selecting the original or an encrypted backup
preserves the vault name and connection references and requires an unlock.
From the welcome screen the owner
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
last backup time, and native preferences: Open at login, Show Dock icon,
Lock when the Mac sleeps, Lock when the screen locks, and the idle-lock timeout.

`<config dir>/quick-unlock.json`, mode 0600, exists only while a vault is set
to Touch ID or Without asking in Settings → Vaults → Unlock. It holds each such
vault's passphrase, keyed by vault name and sealed by the app with Electron
`safeStorage`, whose key the macOS Keychain keeps. The owner server writes and
deletes it; Back Up Setup leaves it out and Restore Setup deletes it. The
unsigned app's code identity is Electron's own binary, so macOS releases that
key to any program running the same unmodified Electron release, and an update
that changes the Electron release may be asked for Keychain access again; the
whole app, its agent endpoint included, waits on that dialog.

## Running the built app

Launch `BlindDrop.app` from Finder. The release notes identify the signing and notarization status of each downloadable artifact. Replacing the app preserves the separate owner data directory; quit first, replace the app, then reopen it. It starts locked and moves installed integrations to its bundled version. There is no automatic updater.

For release builds, Forge accepts an explicit Developer ID Application identity through `BLINDDROP_SIGN_IDENTITY`, and a notarization Keychain profile through `BLINDDROP_NOTARY_KEYCHAIN_PROFILE`. The standard `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` alternative is also accepted by the build configuration. Keep credentials out of source and command logs. Without a Developer ID identity, the build is unsigned; a Development/App Store identity is not a direct-download substitute. Verify the produced artifact's signature, notarization and Gatekeeper assessment before labeling it signed/notarized.

## What the app does

On launch the app starts the owner server on a loopback port with a fresh
one-time token, then loads that page in its main window. Neither window can
navigate away from the owner server's origin, and neither can open a new one.

The window uses the macOS unified toolbar (`hiddenInset`): the real traffic
lights sit over the titlebar the page draws. The app owns the window size and
sets it from the screen the page names — welcome 760×560, unlock 460×520,
vault 1236×818 initially (resizable, minimum 980×640). The workspace's size,
position and maximized state survive lock/unlock and window close/reopen during
the app run. Routine state refresh does not resize or move the window.

`Settings…` (⌘,) opens a second 720×470 window on the same owner server. It has
no parent: requesting a specific tab switches that same window to the tab;
⌘W closes it and nothing else changes, and closing the main window
closes it too while the app remains available in the menu bar.

The application menu is the only App, File, Edit, View, Window and Help menu;
the page draws no menu bar of its own in the app. Workspace menu commands focus or reopen the main window. Lock All calls the owner runtime directly, including with no open window; Settings opens independently.

Commands that require an unlocked workspace are disabled while every vault is
locked. Settings → Security sets the default lock timeout of 1, 5, 15, 30 or 60 minutes
without keyboard/mouse activity anywhere on the Mac, including with no window
open. Off is the default, preserving existing behavior. Agent requests do not
reset the system idle clock. Settings → Vaults → Automatic locking can override the defaults for one vault. Use app defaults removes that override; Lock All and Quit always end access to every vault. Settings → Vaults → Unlock sets a vault to Passphrase, Touch ID or Without asking; nothing reaches the Keychain until one of the last two is chosen, and a vault created or opened under a name starts on Passphrase. An agent's call unlocks a Without asking vault where it asks, with no prompt or window, and that unlock does not become the last unlocked or a recent vault; for a Touch ID vault the app shows the system Touch ID prompt before any window (for a request that names no vault, never for one whose file is missing), and the page never prompts for Touch ID for an agent, except for a request that names no vault while a different Touch ID vault is selected on the Unlock screen. A connection's unlock and Unlock multiple… try Touch ID and Without asking first, and end rather than open their passphrase prompt over a dialog opened meanwhile; an attempt that Lock All cancelled opens no passphrase prompt in any window. The Unlock screen does so on its own only at app launch, and not when an agent's request is waiting; after a lock or in a reopened window it waits, offering Use Touch ID, or Unlock with no passphrase for a Without asking vault. An agent's request waits for the page's own Touch ID attempt; neither that success nor an Unlock multiple… Touch ID or Without asking success discards a passphrase typed for another vault. The Unlock screen moves to the workspace only when its own selected vault is unlocked in the background, and not while the owner is typing or a prompt is open. A cancelled or failed prompt falls back to the passphrase with the reason. Automatic locking does not apply to a Without asking vault, and an automatic lock cancels unlock work only where a vault it locked is involved, so a passphrase typed for another vault stays. Lock All and Quit lock every vault and end Touch ID and Without asking unlocks in progress or waiting; a Touch ID prompt already on screen stays, but a touch on it unlocks nothing. No attempt from before Lock All is joined afterwards or opens a window or a passphrase prompt: an agent still asking opens a Without asking vault again at its next ask, and a Touch ID or Passphrase vault is asked for again by a later request. Lock All also ends the launch window's own attempt. A Touch ID unlock restarts that vault's idle clock.

A startup failure shows a static error and quits rather than opening an unusable window.

Click the monochrome menu-bar icon to open or focus the main window; right-click for Open and Quit. Settings → General → Show Dock icon changes Dock visibility immediately and keeps the choice across launches (on by default). Hiding the Dock icon leaves the menu-bar item available. Saved sleep/screen-lock choices apply from startup even while no window is open. The default remains lock-on-sleep on and lock-on-screen-lock off.

## Integrations and recovery

Settings manages only this app's Claude Code and local Codex integration through native host plugin commands. The integration's MCP server, `blinddrop agent`, runs as the app's own executable with `ELECTRON_RUN_AS_NODE=1` and the runtime bundled in the app. Its guard hook also runs on the app's executable, so neither needs Node or PATH setup. The host's configuration holds no URL, port or token, so endpoint and token changes need no host reload. Configured status is distinct from authenticated use; the page shows the managed version and only the one-time steps for a new or updated integration: loading it in the host, approving BlindDrop's tools, and Codex's plugin and hook review. Every launch re-stages an installed integration and moves it to the bundled version, as Update does, so a moved or replaced app keeps working. Unrelated host configuration is preserved.

Export Encrypted Vault copies one archive. Back Up Setup additionally includes the registry, connection definitions, groups and settings; these remain owner-only plaintext metadata alongside encrypted vaults. It leaves out `quick-unlock.json`, so a restore or another Mac starts with every vault on Passphrase. Restore Setup accepts fresh app configuration, including a preferences-only first launch, and leaves all vaults locked. It replaces those first-launch preferences with the backup's settings but never merges or overwrites existing vault setup data. For a moved or missing registered archive, use Locate file instead.

Appearance follows the saved System, Light or Dark choice in both the page and
native window. Activity shows HTTP status for completed exchanges; a provider
401 is shown as HTTP 401 rather than success. Older records without HTTP status
are labeled Completed. Group rename/removal changes organization only.

## Security

The app's agent endpoint starts with the app, before any unlock, and runs for as
long as the app does. Unlocking a vault makes its connections usable to agents.
Locking a vault makes the connections that need it unavailable; locking every
vault revokes all agent access and replaces the session token; quitting ends
agent access. When an agent's call needs a locked vault, the app first unlocks
its Without asking vaults where the call asks and prompts for its Touch ID
vaults, then shows its main window with the unlock that call still needs,
taking keyboard focus only when none of
its windows already has it (a minimized main window stays minimized while you
work in another BlindDrop window); the passphrase is typed only in the app and never
reaches an agent. Locking also closes affected editors and clears
unsaved credential drafts in both owner windows. Stored secret values remain
hidden in the owner interface. The passphrase is held by the owner server in
the app's main process memory, and is on disk only sealed, for a vault set to
Touch ID or Without asking; the agent endpoint dies with the process, and
the session file it wrote is deleted. There is no daemon and no launch agent:
the app runs only when you open it, Open at login starts it, or an agent's call
starts it, and the vault is reachable only while the app runs and the required
vaults are unlocked. Every launch, including one started by an agent's call or
by Open at login, starts locked; a vault set to Touch ID or Without asking then opens without its passphrase when an agent's call needs it or Unlock selects it at launch, Touch ID after a touch.

Closing the main window leaves the app and its agent access running. Use the
menu-bar icon to reopen the window or quit the app; Quit ends agent access.

Both windows run with context isolation on, Node integration off, and the
renderer sandbox on. The page reaches the owner server over loopback HTTP
exactly as the browser does. The preload script adds one bridge,
`window.desktop`, and nothing else: the platform name, the file dialogs for
choosing a vault, the path of a dropped file, Reveal in Finder, Move to Trash,
the screen size and settings-window calls, the menu-command subscription,
native settings, managed integration actions, setup-folder selection, and
Touch ID and Without asking unlock and their Settings choice, which return only
a status. No `ipcRenderer`, `require` or arbitrary channel
is exposed, and every path the bridge acts on must be absolute.
