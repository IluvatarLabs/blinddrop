# Changelog

## [0.6.2] - 2026-11-21

### Added

- Ten new connection templates: GitHub (OAuth app), AWS KMS, AWS SES, Tigris, Together AI, Makora, Modal, AgentMail, Vast.ai and Lambda Cloud, for 25 choices: Fly.io, Anthropic, GitHub (personal access token), GitHub (OAuth app), Stripe, AWS (SigV4), AWS KMS, AWS SES and Google APIs under Popular; OpenAI, Postmark, Twilio, Dropbox, Cloudflare R2, DigitalOcean Spaces, Telegram Bot, Backblaze B2 (S3), Tigris, Together AI, Makora, Modal, AgentMail, Vast.ai and Lambda Cloud under More; Custom last. The Modal sheet also offers a Modal web endpoint option using its Proxy Token headers. Templates are static configuration bundled with the runtime and read by the owner page through `GET /api/recipes`; there is still no runtime provider code or downloaded catalogue.
- Credential bundles shared by New Connection and New Secret. Each template field is a credential, metadata that is never sent, or a note that is never operative. New Secret offers provider bundle types next to the eight generic types, then **Create connection…**. A credential pair is one typed secret; blank inputs keep stored values, which are never read back.
- Connections may store an optional `recipe` id. `list_connections` returns usage guidance for each connection — `recipe`, `tool`, `summary`, `example`, `schematic`, `notes` and, for Modal, `target` — derived from the same template data as the owner page's details and containing no stored values, labels, notes, references or client IDs. Connections without a recognized id get generic guidance.
- Connection test: **Test** in a connection's details sends its template's example request through BlindDrop as an agent's request is sent and logged, and shows the provider's HTTP status with its short error message, or BlindDrop's own error. It also runs after the connection is saved, and after a secret it uses is saved; saving never depends on it, and connections without a concrete template example have no test.
- OAuth sign-in from the app: **Save and connect** in the connection sheet saves the client bundle, runs browser consent, stores the refresh grant in the selected field of any unlocked vault, then adds the connection. **Sign in again…** reauthorizes. Cancel, denial, timeout, a newer attempt, locking a required vault, Lock All and Quit end an attempt; closing the window does not. Owner routes `oauth/start`, `oauth/status` and `oauth/cancel`; consent settings are stored in an optional `consent` field. Manual refresh-token import and `oauth login` remain.
- OAuth `clientIdSecret`, a vault reference, as an alternative to the literal `clientId`. Exactly one is allowed; existing literal definitions remain valid.
- Modal Functions: `modal` authentication with a token ID and secret, a required `modal` target (`app`, `function`, `environment`, optional `usage`), and the third MCP tool `invoke_modal_function { connection, args?, kwargs? }` returning `{ result }`. Each request makes one invocation through the official `modal` SDK and is never replayed; results must be JSON and are checked before release; locks stop waiting immediately and request remote cancellation. The SDK is a new runtime dependency, loaded only when used.
- `UNSUPPORTED_OPERATION` error code (HTTP 400 on the session listener) when a connection does not support the called tool, including `execute_http` and the SDK endpoint with a Modal connection.
- `blinddrop agent`: a stdio MCP server, built from the official MCP SDK, that agent hosts launch themselves. It answers the MCP handshake and tool list without the app, so a host's first connection never depends on the app, and forwards each tool call to the running app, reading its session file for each call. When the app is not running before a call first reaches it, the bundled command starts it in the background, locked, and waits up to 8 seconds for its endpoint. When a call needs a locked vault, it sends the call again every second for up to 20 seconds while BlindDrop shows the unlock, and stops at once if the host cancels; if the app goes away during that wait, the call ends with its last result. A call is never sent again once the app may have acted on it, and each send ends within the app's 30-second request limit. `@modelcontextprotocol/client` becomes a runtime dependency.
- `blinddrop run --app CONNECTION [--base-url-env NAME] [--api-key-env NAME] -- COMMAND`: runs an SDK or command-line client against the running app without a passphrase prompt; run from the app's bundled runtime, it starts the app when needed. A locked connection answers HTTP 423 `VAULT_LOCKED`, and the agent runs the command again after the unlock. Its token works for every connection the agent's tools can use until every vault locks, agent access is turned off, or the 24-hour renewal. Without `--app`, `run` is unchanged.
- `VAULT_LOCKED` error (HTTP 423): a call for a locked connection, or `list_connections` while every vault is locked, brings up BlindDrop's unlock and returns at once, before any credential use or upstream request.
- Agent unlock requests: the app shows its main window with the unlock a call needs, using **Unlock multiple…** when it needs several vaults, without disturbing a prompt, unlock queue or passphrase already in progress. It takes keyboard focus only when none of its windows already has it, and a minimized main window stays minimized while another BlindDrop window has focus. `blinddrop ui` shows the request at its page's next refresh.
- `list_connections` items carry `available`; connections whose vault is locked are listed with `available: false` and `reason: "locked"`. With no vault registered yet, the list is empty; when every registered vault's file is missing and none is unlocked, agent calls get `VAULT_NOT_FOUND`.
- Touch ID and Without asking unlock in the Mac app. **Settings → Vaults → Unlock** sets each vault to **Passphrase** (the default), **Touch ID** or **Without asking**. Choosing Touch ID or Without asking needs that vault unlocked; Touch ID also needs one confirming touch and is offered only on a Mac that can show the Touch ID prompt. Nothing reaches the macOS Keychain until the owner chooses one of the two. The app then seals the vault's passphrase with Electron `safeStorage`, whose key the Keychain keeps, in `quick-unlock.json` in the configuration directory, at mode 0600. Choosing Passphrase or removing the vault deletes it; changing the passphrase in the app, or the next successful passphrase unlock, seals the passphrase again. Creating or opening a vault under a name deletes any entry left for that name, so a new archive starts on Passphrase.
- An agent's call that needs a locked Without asking vault unlocks it where the call asks, with no prompt, no window and no unlock request, so it never waits on another vault; the agent's next send completes. A call that names no vault while every vault is locked unlocks every Without asking vault the same way. For what is still locked, the app shows the system Touch ID prompt for each Touch ID vault the request names, one at a time, or for a request that names no vault, for the vault the Unlock screen would select, never one whose file is missing, when it is on Touch ID. The BlindDrop window comes up only for a vault that still needs its passphrase, and the page never starts a Touch ID prompt for an agent's request, except for a request that names no vault while a different Touch ID vault is selected on the Unlock screen. A Without asking unlock for an agent does not become the last unlocked or a recent vault.
- The Unlock screen tries its vault's Touch ID or Without asking on its own only when the app launches, and not when an agent's request is waiting. After Lock All, after automatic locking or in a reopened window it waits, offering **Use Touch ID**, or **Unlock** with no passphrase for a Without asking vault, so a lock holds until the owner or an agent asks. A connection's unlock and **Unlock multiple…** try Touch ID and Without asking vaults before their passphrase prompts; when the owner has opened another dialog meanwhile, the unlock ends instead of covering it. An attempt that Lock All cancelled never opens a passphrase prompt, in any window. The page's own Touch ID attempt counts as unlock work in progress: an agent's request waits for it, and neither its success nor an **Unlock multiple…** Touch ID or Without asking success discards a passphrase typed for another vault. When the Unlock screen's own selected vault is unlocked in the background, it moves to the workspace unless a passphrase is being typed or a prompt is open; another vault unlocking leaves it, and the agent's request it shows, in place.
- A cancelled or failed Touch ID prompt, a sealed passphrase the Keychain does not release, or one that does not open the vault falls back to the passphrase prompt with a one-line reason. A sealed passphrase that fails is kept, because a failed decryption cannot tell a changed passphrase from a damaged archive. While an agent keeps asking, the app does not try a vault whose attempt fell back again.

### Changed

- The owner page validates the archive's rules, including lowercase field IDs, before its first write, shows save failures inside the active sheet while keeping the draft, and reports partial saves exactly instead of implying rollback. Beyond the name and JSON syntax, JSON import checks only the definition's origin, the presence of an authentication type and the Modal rules, which run both ways, and shows any other schema rejection from the server inline.
- Endpoint, region, signing service, scopes and the Modal target are connection configuration with one operative source; account-specific endpoints are no longer prefilled with example values as if complete.
- The agent skill teaches agents to call `list_connections` first, follow each connection's returned tool, example and notes, fill placeholders from the task or owner, never guess Modal arguments, and never retry a consequential or ambiguous call.
- The app and `blinddrop ui` keep one agent endpoint and session file for as long as they run, locked or unlocked. Unlocking, locking and owner edits change what it authorizes, never whether it listens. The session token is replaced only when every vault becomes locked, when agent access is turned off, and at the 24-hour renewal; any other token, or an expired one, gets 403 `ACCESS_DENIED`. An unlock lets running requests finish; other changes abort them, as owner changes did before. If the app cannot work out current access, agent calls get that failure's error instead of an empty listing.
- Restore Setup works on a new installation while the app is running. BlindDrop's own session file and staged `integrations/` folder no longer block it, and restore keeps `integrations/`.
- Managed Claude Code and Codex integrations run `blinddrop agent` from the app bundle. Host configuration holds no URL, port or token, so port and token changes need no host reload. Every app launch refreshes an installed integration to the bundled version. A host whose refresh fails is refreshed again five minutes after each failed attempt while the app runs, until it succeeds; a host whose CLI is not found is skipped. The one-time owner steps are installing in Settings → Sessions, approving BlindDrop's tools in the host (Claude Code also accepts the allow rule `mcp__plugin_blinddrop_blinddrop__*`) and Codex's plugin and hook review.
- Agent guidance moves from the SessionStart hook to the MCP server's instructions. Agents are told to use `list_connections` and the listed tool, to continue other work when a vault is locked, and never to ask the owner to start a session, unlock in advance, reload plugins, reconnect, restart a host, update an integration or run a command. The skill's never-read rule covers credential values; templates such as `.env.example`, and handing a file to the program that uses it, are ordinary work.
- The guard hook denies only Read, Edit and Write calls on paths under `~/.config/blinddrop/` and shell commands that name that path, including commands that only mention it; Codex sends file edits as `apply_patch`, which it does not check. The `.env`, `.pem`, `.key`, `id_rsa` and `id_ed25519` name rules are removed, ending false denials such as the `jq` field `.licenseInfo.key`. Codex asks for a hook review after this update.
- Automatic locking (sleep, screen lock, idle) does not apply to a Without asking vault, because the next agent call would reopen it; Settings shows its Automatic locking as not applicable. An automatic lock no longer predicts which vaults a policy would lock: it closes editors and cancels unlock work only where a vault it actually locked is involved, so a passphrase typed for a vault it did not lock stays (the field is masked, and a sleep or screen lock already covers the screen), including an **Unlock multiple…** queue that contains one, which stops as a whole. A Touch ID unlock restarts that vault's idle clock on the wall clock, so a vault unlocked by a touch while the Mac is idle is not locked again at once; other unlocks follow the ordinary idle rule.
- Lock All and Quit lock every vault and end every Touch ID and Without asking unlock in progress or waiting for its prompt: none of them unlocks a vault afterwards, and a prompt still waiting is not shown. A Touch ID prompt already on screen cannot be withdrawn, but a touch on it unlocks nothing. No attempt from before Lock All is joined afterwards or opens a window or a passphrase prompt. An agent still asking after Lock All opens a Without asking vault again at its next ask; a Touch ID or Passphrase vault is asked for again by a later request. Lock All also ends the launch window's own attempt.
- Back Up Setup leaves `quick-unlock.json` out, and Restore Setup is not blocked by one and deletes it, so a restored setup, or one copied to another Mac, starts with every vault on Passphrase. A `quick-unlock.json` that cannot be read does not block the owner page, passphrase unlock, choosing Passphrase or removing a vault; the Touch ID and Without asking choices show as unavailable, and choosing Passphrase or removing a vault resets the file; creating or opening a vault leaves it as it is.
- The agent skill and the MCP server's instructions treat BlindDrop as the preferred way to use the owner's credentials, not a precondition for the task. When BlindDrop cannot be reached or has no connection for a service, agents keep working with the credentials the project's own commands, SDKs and scripts are set up with, such as environment variables, a CLI's own login or a `.env` file the program loads itself, without reading, printing or copying a value themselves.
- `oauth login`: a callback port that cannot be bound returns `PORT_UNAVAILABLE` instead of `INPUT_UNAVAILABLE`, and a token response without a refresh token returns `UNSUPPORTED_RESPONSE` instead of `UPSTREAM_ERROR`.
- Host sessions started with an earlier version's HTTP integration need one new session after the upgrade.

### Removed

- The SessionStart hook, the headers helper, and the managed endpoint rewrite and host reload guidance on port changes.

### Fixed

- Settings → Sessions and the launch refresh read Codex's BlindDrop plugin from BlindDrop's own marketplace only. Listing every marketplace made Codex re-sync its remote plugin catalog when stale, past the 30-second host-command limit, which could leave Codex on the old integration and show its status as unavailable.
- A stored credential that BlindDrop sends as a header value as stored (a bearer token, an API-key header or header binding, or an AWS access key ID or session token) and that contains a character a header cannot carry (a control character, or one outside Latin-1) now returns `SECRET_INVALID` (HTTP 502), which tells the agent the owner must re-enter it, instead of `INVALID_INPUT`, which pointed the agent at its own input.
- A key or token copied as several lines and pasted into a credential field of the owner page is no longer saved with spaces: single-line credential fields drop the line breaks. Multi-line fields, such as PEM keys, and vault passphrase fields keep their existing behavior.
- With Agent access off, connections are no longer shown as available to agents; their status says Agent access is off.

Touch ID is a prompt in front of the sealed passphrase, not a separate key: the passphrase is as safe as the app's Keychain item, which macOS releases to the app, and in the unsigned build to any program running the same unmodified Electron release; a build with a different Electron release may ask for Keychain access again after an update; the whole app, its agent endpoint included, waits on that dialog. A Without asking vault is usable by any agent's call while Agent access is on; an agent's call through the app's integration starts the app when it is not running. `blinddrop ui` and the CLI do not offer these choices.

Not verified for this release, among others: the system Touch ID prompt and a completed touch on a packaged build; most connection templates against live accounts; OAuth sign-in with GitHub.com, Google and Dropbox; Modal against a deployed Function; Codex's plugin and hook review flow; the integration's Codex plugin listing on Codex releases other than 0.165.0-alpha.1.2 and 0.167.0; `run --app` inside Codex's sandbox, which blocks loopback; the five-minute integration refresh retry; and a wall-clock 24-hour token renewal.

## [0.6.1] - 2026-10-11

- Unlock selects the requested or last-used vault, clears passphrases when changing selection, and supports Return in additional-vault prompts. Pending submissions cannot be cancelled or redirected misleadingly.
- Optional Unlock multiple prompts separately for selected vaults, keeps successful unlocks available, and supports Skip/Stop. Connections offer their required vaults and retain their detail view after unlocking.
- Per-vault automatic locking inherits app defaults or uses a complete custom sleep, screen-lock and idle preference, including with no window open. Manual Lock All uses one owner-runtime operation and overrides every preference.
- Agent guidance distinguishes unavailable connections from unconfigured ones and states supported host reconnection steps. Runtime, app and integration versions are aligned.

## [0.6.0] - 2026-10-06

- App and CLI HTTP sessions choose a random port once, save it in existing settings, and advance if occupied. Settings or CLI `--port` can change the preference; managed integrations follow the actual endpoint even with the window closed. Manual plugins use the reported URL instead of assuming 8787.
- Native Quit exits after owner/session cleanup instead of re-entering the cancelled quit flow and leaving a closed process running.
- `.env` import uses Node's built-in parser for inline comments, quoted hashes and multiline values while retaining destination review and collision checks. Cancelled or superseded parsing cannot restore a discarded draft.
- Native workspace commands reflect the actual vault lock state. Settings → Security adds an optional system-idle timeout that locks every vault with or without an open window; Off preserves the existing default.
- Connection creation makes secret reuse explicit and provider templates identify required credentials and endpoint/input details, retaining all 15 choices and Custom last.
- Settings → General adds a saved Show Dock icon option. On macOS, normal menu-bar clicks open/focus the window directly; right-click retains Open/Quit.
- Pasted credentials use the connection's default secret name when the name input is blank; unused optional slots remain absent. `.env` imports flag duplicate destination names before writing or moving the source file to Trash.
- JSON import and the connection editor reject non-origin URL components instead of silently changing the target. Settings Import/Activity and native workspace commands reopen the main window and wait for its initial state.
- Vault locking dismisses affected editors and clears unsaved credential drafts, including pending file imports and Settings passphrase fields. Delayed UI refreshes cannot restore stale unlocked state after locking.
- Settings honors requested tabs in its existing window; workspace geometry survives lock/unlock and close/reopen. Saved appearance also controls native chrome. Correct Retina tray artwork and softer Light/Dark surfaces retain the existing layout.
- Missing named vaults can be located under the same name without breaking connection references. A fresh installation can restore after changing preferences; existing setup data is never silently replaced or merged.
- Activity and Recent use show recorded HTTP status, so provider rejection is not presented as success. Older records remain readable as Completed.
- Group rename and confirmed removal preserve connections/secrets; initial connection and agent setup actions and integration progress are explicit.
- Standalone Mac workflow with a bundled runtime, shared Create/Add/Open forms and app-first setup instructions.
- Lock All is enforced by the owner runtime even with Settings focused or no window. Closing the window preserves the current session; Quit ends it and relaunch starts locked. Saved sleep/screen locking applies from launch.
- One bundled monochrome menu-bar icon with Open and Quit.
- Agent Integrations controls for Claude Code and local Codex: native plugin installation, update/removal, managed endpoint refresh and bundled helper execution. Status distinguishes configuration from authenticated use.
- Complete Back Up Setup and fresh-state Restore Setup, preserving independent encrypted archives and reference-only metadata. The one-archive operation is named Export Encrypted Vault.
- Named first vaults keep their chosen name without a missing default registration. Stripe template input, field metadata edits and empty-group persistence are corrected.
- Saved connection fields retain their human labels; request illustrations are explicitly examples. Integration actions precede guidance, status refreshes when returning, and approval guidance appears only after configuration.
- Runtime, app, plugin and skill versions aligned. App replacement preserves stored data; there is no automatic updater.

## [0.5.1] - 2026-09-20

### Added

- Multiple vaults: each is an encrypted file with its own passphrase and lock state, listed in a `~/.config/blinddrop/vaults.json` registry that stores names and paths only, never a passphrase. The `default` vault initially uses `~/.config/blinddrop/vault.enc`; its first-use location can be chosen. Every vault reuses the existing scrypt + AES-GCM envelope; no new cryptography.
- Owner vault routes `vault/create`, `vault/open`, `vault/unlock`, `vault/lock` and `vault/remove`; `state` and `list` now report every vault and its lock state.
- Least-privilege unlock and cross-vault session eligibility: unlocking one vault decrypts only that vault, and a connection is in the session only while every vault holding its referenced secrets is unlocked. Locking a vault drops just its dependent connections.
- Typed multi-field secrets: a secret has a type and named fields — a default set per type plus unlimited custom fields — each field carrying a label and masked/multiline flags. Owner routes `secret/set` (typed, multi-field), `secret/field/remove` and `secret/import-env`.
- Connection templates: a static, client-side prefill of a connection and its secret in the owner page, with Custom as the fallback. No runtime provider code and no provider catalogue; a provider needing an unsupported mechanism is flagged, not faked.

### Changed

- Connection references are vault-qualified `vault#secret#field`. `secret#field` and a bare `secret` resolve in the default vault, and a bare reference resolves to a secret's `value` field or its sole field.
- The archive payload schema version is `2`. Loading a version `1` archive migrates it in memory — single-value secrets become typed `api-key` secrets and connection references gain the default field — through a one-version-back read path, with the atomic writer preserved. Existing two-secret patterns stay valid and are not force-merged.

### Fixed

- Restored Unlock on populated startup and after locking the last vault. Operational listings, Activity, connection edits and Groups require an unlocked vault; secret changes still require their target vault.
- Restored the original Forgot-passphrase explanation and Open-a-backup action.
- Removed the unintended 64-field count cap from typed secrets; existing request/archive/value byte limits remain.
- Connections now live outside the vaults in owner-only configuration. Locking a vault with no referenced secret no longer removes a usable connection; connections with locked references remain visible with missing-reference details while another vault is unlocked.
- Legacy connections are qualified against their source vault before migration, preventing a same-named default secret from being used instead. Name collisions preserve both definitions.
- Migration collision names remain valid when truncating a long vault name at punctuation.
- Creating a field-less connection reference requires its vault unlocked so the correct field can be resolved; explicit field references remain editable while their vault is locked and another vault is unlocked.
- Activity and Last used read the same fixed log written by the owner session, including sessions with the default vault locked.
- The connection editor selects and preserves custom secret fields. Editing labels keeps stored values and stable field IDs; inline value replacement preserves sibling fields.
- First-vault creation accepts a chosen location, and the owner server honors an explicit `--vault` path.
- Backups now document the separate connection configuration required alongside encrypted vaults.

### Removed

- Kinds, the auto-bucketing of connections by authentication type, from the owner page; Search and Groups cover the need. Groups stay on connections and secrets are not grouped.
- Some of the owner page's in-app manual prose, and the connection counts in the status footer during an active session, as part of the information-architecture cleanup.

Verification: type check, the functional suite and clean-install package checks
pass on macOS arm64. Browser and native-app checks cover populated Unlock,
per-vault locking, templates, custom fields and the owner layout. Windows/Linux
0.5.x workflows and new live-provider account checks remain unverified. The
macOS build is unsigned and not notarized.

## [0.5.0] - unreleased

### Added

- Owner routes `vault/open`, `activity`, `activity/clear`, `secret/set-many`, `secret/enable`, `connection/enable`, `connection/remove`, `groups`, `settings` and `vault/backup`.
- Owner settings in `~/.config/blinddrop/settings.json` at mode 0600: appearance, session port, session file, lock on sleep, lock on screen lock, open at login, the last and recent vaults, the last backup time, and the page's own view state.
- Connection groups in a `<vault-path>.gui.json` sidecar at mode 0600 beside the archive. The archive does not store them and agents never see them.
- The owner page rebuilt: a welcome screen, an unlock screen, the vault window with its sidebar, list or table and detail pane, the secrets and activity views, and a settings window with the General, Security, Sessions, Vault and Advanced tabs.
- macOS app: a preload bridge for file dialogs, Reveal in Finder and the sleep and screen-lock handlers; the native application menu; a separate settings window; a window size per screen; and a vault chosen from `--vault`, then the last vault, then the default path.

### Changed

- The agent session is implicit: unlocking the owner page starts it over every enabled connection whose referenced secrets are present and enabled, every owner write to the archive restarts it from the new snapshot, and locking or quitting ends it.
- The session file is always written to `~/.config/blinddrop/session.json` instead of beside the archive, so a plugin finds it wherever the vault file lives.
- The owner listener accepts request bodies up to 1 MiB instead of 64 KiB, so a PEM value fits.
- `connection/import` accepts a `secrets` object, storing a new connection's values and its definition in one write.
- Version 0.5.0.

### Removed

- The `session/start` and `session/stop` routes, and the session controls in the owner page.

## [0.4.0] - unreleased

- Owner GUI: `blinddrop ui` serves an owner-only page on an authenticated loopback listener to create or unlock the vault, manage secrets and connections, change the passphrase, and start or stop agent sessions; the passphrase is held in that process's memory only.
- macOS app under `desktop/`: hosts the same server and page in an Electron window; quitting the app ends every session. Unsigned local build.
- Claude Code plugin under `plugin/`: a portable skill, a `PreToolUse` guard that refuses direct reads of `.env`, key files and the vault directory with a reason naming the BlindDrop tool, and MCP wiring that attaches automatically through an opt-in session file. The skill folder also installs into Codex and Cursor.
- `serve --http --session-file PATH` writes the session record at mode 0600 and deletes it on exit.
- Every static error code now maps through one status table shared by both listeners. Codes that previously fell through to 502 on the agent session listener return their own status: `STORAGE_ERROR` 500, `SECRET_NOT_FOUND` and `CONNECTION_NOT_FOUND` 404, `UNLOCK_FAILED` 401. A local port that cannot be bound reports the new `PORT_UNAVAILABLE` code instead of `INPUT_UNAVAILABLE`.

## [0.3.0] - 2026-09-11

Initial public release.

- Local encrypted archive with owner CLI: hidden-prompt or inherited-descriptor
  input, metadata listing, replacement, disable/remove, encrypted backup by copy
  and atomic passphrase change.
- Two MCP tools, `list_connections` and `execute_http`, over stdio or an
  authenticated loopback HTTP session started in the owner's terminal, so a
  host without a terminal can attach without receiving unlock material.
- `run`, which wraps an ordinary client command with a local base URL and an
  ephemeral session token, closes the helper on exit and stops the child on
  expiry.
- One broker and validated HTTPS sender for static header/query/JSON/form/path
  placement, Basic, OAuth client-credentials and refresh grants with PKCE
  onboarding and fixed audience/resource, RS256 JWT bearer exchange, AWS SigV4
  and mutual TLS. Pinned resolved addresses, metadata-address denial, no
  redirect following, no retries.
- Streaming SDK responses with bounded compression decoding and credential
  checks across chunk boundaries; buffered MCP responses keep complete-response
  inspection. Cookies and trailers are discarded.
- Runnable Fly.io, official Claude SDK, GitHub personal-access-token and Google
  OAuth recipes.

Verification: the functional suite and the clean-install package check pass on
macOS (arm64, Node 26) and Linux (x86_64, Node 22) against disposable local
HTTPS receivers. The mechanisms have been exercised live against Stripe's
published test-mode demo key, Postman Echo's published demo account, AWS STS
with a disposable federation token, a read-only Fly.io app listing through a
real account, and Claude Code attached over Streamable HTTP MCP. Not verified:
Windows, interactive Linux terminal prompts, desktop browser launch on any
platform, and live Anthropic, GitHub and Google accounts.

[0.3.0]: https://github.com/IluvatarLabs/blinddrop/releases/tag/v0.3.0
[0.5.1]: https://github.com/IluvatarLabs/blinddrop/releases/tag/v0.5.1
