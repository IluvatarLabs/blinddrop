# BlindDrop macOS app

A thin Electron shell around the BlindDrop owner interface. The app starts the
same owner server the `blinddrop ui` command starts, in its own main process, and
shows the same page in a window. It adds no capability of its own: everything
the app can do, the command-line runtime can already do.

macOS only. Linux and Windows owners use `blinddrop ui` and their browser.

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
packed copy of the runtime rather than the working tree. After changing anything
under `src/`, run `npm run vendor` and `npm install` again; the app will not see
the change otherwise.

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

### Choosing an archive

The app administers the default archive. To point it at another one, pass
`--vault <path>`, mirroring the runtime's global option. From source, the
argument goes after a second `--`, because the first one belongs to npm:

```sh
npm start -- -- --vault <path>
```

The built app takes it directly:

```sh
open out/BlindDrop-darwin-<arch>/BlindDrop.app --args --vault <path>
```

`--vault` without a usable value is refused rather than ignored, so a mistyped
option cannot quietly open the default archive instead.

## Running the built app

Launch `BlindDrop.app` from Finder, or with `open` from a terminal. The build is
unsigned and is not notarized: it is meant to run on the machine that built it.
macOS Gatekeeper will refuse an unsigned bundle that has been downloaded or
copied from elsewhere.

## What the app does

On launch the app starts the owner server on a loopback port with a fresh
one-time token, then loads that page in a single window. The window cannot
navigate away from the owner server's origin and cannot open new windows.

If the packed runtime has no built owner server, the window opens empty with the
title `BlindDrop runtime not built`; run `npm run vendor` and `npm install` again
after building the runtime.

## Security

Quitting the app ends every agent session. The passphrase lives only in the
app's main process memory, the agent session listener dies with the process, and
the session file it wrote is deleted. There is no daemon, no login item, and no
launch agent: the vault is reachable only while the owner has the app open.

Closing the window quits the app, so closing the window also ends every session.

The window runs with context isolation on, Node integration off, and the
renderer sandbox on. It has no preload script and no privileged bridge; the page
talks to the owner server over loopback HTTP exactly as the browser does.
