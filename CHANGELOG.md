# Changelog

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
- The owner page rebuilt from the owner's design: a welcome screen, an unlock screen, the vault window with its sidebar, list or table and detail pane, the secrets and activity views, and a settings window with the General, Security, Sessions, Vault and Advanced tabs.
- macOS app: a preload bridge for file dialogs, Reveal in Finder and the sleep and screen-lock handlers; the native application menu; a separate settings window; a window size per screen; and a vault chosen from `--vault`, then the last vault, then the default path.

### Changed

- The agent session is implicit: unlocking the owner page starts it over every enabled connection whose referenced secrets are present and enabled, every owner write to the archive restarts it from the new snapshot, and locking or quitting ends it.
- The session file is always written to `~/.config/blinddrop/session.json` instead of beside the archive, so a plugin finds it wherever the vault file lives.
- The owner listener accepts request bodies up to 1 MiB instead of 64 KiB, so a PEM value fits.
- `connection/import` accepts a `secrets` object, storing a new connection's values and its definition in one write.
- Version 0.5.0.

### Removed

- The `session/start` and `session/stop` routes, and the session controls in the owner page.

Verification: recorded in the 0.5 verification record before release.

## [0.4.0] - unreleased

- Owner GUI: `blinddrop ui` serves an owner-only page on an authenticated loopback listener to create or unlock the vault, manage secrets and connections, change the passphrase, and start or stop agent sessions; the passphrase is held in that process's memory only.
- macOS app under `desktop/`: hosts the same server and page in an Electron window; quitting the app ends every session. Unsigned local build.
- Claude Code plugin under `plugin/`: a portable skill, a `PreToolUse` guard that refuses direct reads of `.env`, key files and the vault directory with a reason naming the BlindDrop tool, and MCP wiring that attaches automatically through an opt-in session file. The skill folder also installs into Codex and Cursor.
- `serve --http --session-file PATH` writes the session record at mode 0600 and deletes it on exit.
- Every static error code now maps through one status table shared by both listeners. Codes that previously fell through to 502 on the agent session listener return their own status: `STORAGE_ERROR` 500, `SECRET_NOT_FOUND` and `CONNECTION_NOT_FOUND` 404, `UNLOCK_FAILED` 401. A local port that cannot be bound reports the new `PORT_UNAVAILABLE` code instead of `INPUT_UNAVAILABLE`.

Verification: recorded in the 0.4 verification record before release.

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
