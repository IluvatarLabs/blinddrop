# Changelog

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
