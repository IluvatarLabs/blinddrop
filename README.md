# BlindDrop

> *“If you want to keep a secret, you must also hide it from yourself.”*
>
> — George Orwell, *Nineteen Eighty-Four*

BlindDrop lets your agents use API keys without putting those keys in their
prompts, scripts, or client configuration.

Think of a password manager's autofill, but for API requests. You store a key in
an encrypted vault on your computer and choose which connections an agent can
use. BlindDrop adds the key when it sends a request, checks the response, and
returns the result.

Providers receive their usual authentication. They do not need to change
anything to work with BlindDrop.

## Why

Giving an agent a key gives it a copy. That copy can end up in a conversation,
a generated script, or a log.

BlindDrop keeps the key in a local vault and makes requests on the agent's
behalf. You unlock the helper once for a session. The agent can use the
connections you allowed, but has no tool for reading their keys.

Each vault is a file you own, with its own passphrase and lock state. You can
copy it, back it up, and move it to another computer. Locking a vault removes
the connections that need it; locking every vault or quitting the helper ends
the session. Saved keys remain encrypted in their vaults. There is no
subscription or hosted account to maintain.

## Install

Requirements for the command-line package: Node.js 22.13+ on the 22.x line, or
23.5+, and npm. Version 0.5.1 has been verified on macOS arm64; the earlier
0.3.0 runtime was also tested on Linux. Windows is not verified.

Download `blinddrop-0.5.1.tgz` from the
[v0.5.1 GitHub release](https://github.com/IluvatarLabs/blinddrop/releases/tag/v0.5.1),
then install that file by its local path:

```sh
npm install --global --prefix "$HOME/.local" ./blinddrop-0.5.1.tgz
export PATH="$HOME/.local/bin:$PATH"
blinddrop --help
```

This installs the command under your home directory on macOS and Linux.
BlindDrop is not published to the npm registry; install the GitHub release
tarball by its path. Add
`$HOME/.local/bin` to your shell's PATH to keep the command available in new
terminals.

The release also includes `BlindDrop-darwin-arm64-0.5.1.zip`, containing the
macOS app. It is for macOS arm64 only and is unsigned and not notarized. See the
[macOS app guide](https://github.com/IluvatarLabs/blinddrop/blob/v0.5.1/desktop/README.md) for its behavior and source-build steps.

## Quick start

This example uses a GitHub personal access token to read your account. Create
a token using GitHub's normal controls, then run these commands in your own
terminal:

```sh
blinddrop init
blinddrop secret set github-pat
blinddrop connection set github \
  --origin https://api.github.com \
  --auth bearer --secret github-pat
```

Run `init` once to create the vault. Passphrases and keys are entered at hidden
prompts. `github-pat` is the name of the saved key; `github` is the connection
that uses it.

The installed package includes an HTTP client. With the user-local prefix
above, make a request with:

```sh
blinddrop run github -- node "$HOME/.local/lib/node_modules/blinddrop/examples/request.mjs" /user
```

Unlock the vault when prompted. The command prints the HTTP status and your
GitHub account details. The client receives a temporary local URL and session
token; BlindDrop supplies the real GitHub token when it contacts the API.
When the command exits, its helper stops.

For another API, use its HTTPS origin and authentication format. See the
[configuration reference](CONFIGURATION.md) and the [Fly.io walkthrough](FLY.md).

## Running it

- `blinddrop ui` opens an owner page in your browser to create, open, unlock or
  lock any of several vaults, and to manage typed multi-field secrets,
  connection groups and static connection templates through the Connections,
  Secrets and Activity views. Unlocking a vault starts or recomputes the
  implicit agent session; locking every vault or quitting ends it. The macOS
  app in `desktop/` shows the same page. Closing its main window leaves the app
  and any unlocked session running from the menu bar; Quit ends the session.
  See the
  [configuration reference](CONFIGURATION.md#owner-gui).
- The [BlindDrop plugin](plugin/README.md) for Claude Code adds a skill that
  steers the agent to the vault, a hook that refuses direct reads of `.env` and
  key files, and automatic attachment to a running session. The same skill
  folder installs into Codex and Cursor.
- `blinddrop run CONNECTION -- COMMAND ARGS…` runs a command with a local API
  endpoint and a temporary session token. Existing SDKs can use it if they let
  you configure their base URL and authentication header. Streaming is supported.
- `blinddrop serve --http --allow CONNECTION` starts a helper in your terminal
  for an independently launched MCP client. It prints the MCP URL and session
  token to put in your client's configuration. Leave the helper running.
- `blinddrop serve --allow CONNECTION` uses stdio for MCP clients that launch
  their own helper. See the [client setup](CONFIGURATION.md#agent-session).

Terminal sessions created by `serve` or `run` last one hour by default;
`--ttl SECONDS` changes that. Stopping or expiring the helper ends its session.
A new session gets a new token. The owner page and app instead recompute their
implicit session as vaults and records change. The MCP tools are
`list_connections` and `execute_http`.

The [client guide](CLIENTS.md) covers MCP configuration, the Claude SDK,
ordinary HTTP clients, and OAuth APIs. BlindDrop supports common API-key
placements, Basic authentication, OAuth grants, JWT bearer exchange, AWS
SigV4, and client TLS certificates. Native database connections, SSH,
WebSocket, gRPC, and browser login automation are outside this release.

## Your vault

BlindDrop's default configuration directory can contain the default encrypted
vault and these owner-side files:

```text
~/.config/blinddrop/
├── vault.enc               default encrypted vault of secret values
├── vaults.json             vault names and paths, never passphrases
├── connections.json        origins, authentication settings and secret references
├── groups.json             connection groups
├── settings.json           owner page and app settings
└── vault.enc.events.jsonl  request outcomes, without keys or request bodies
```

Other encrypted vault files may live anywhere you choose. Each has its own
passphrase and lock state. A typed secret can hold several named fields, and a
connection refers to the fields it needs as `vault#secret#field`.
`connections.json` contains no stored secret values.

While a session started from the owner page or the app is running with the
session-file option on, `session.json` holds that session's local URL and token
at mode 0600 and is removed when the session ends.

Back up every encrypted vault you need. The page's **Back up now…** action
copies only the selected encrypted vault, not the separate connection or app
configuration. To restore the complete app setup, retain `connections.json`,
`vaults.json` (and adjust paths after moving machines), plus any wanted
`groups.json` and `settings.json`. Each vault's passphrase is required to
restore it; there is no recovery bypass. Stop active helpers before replacing
keys or changing a passphrase. `blinddrop passwd` re-encrypts the selected
vault; older backups still need their old passphrase.

BlindDrop protects credentials through its own interfaces. Your agent harness
and operating system must restrict access to the vault's unlock input and the
helper's files and memory. An unrestricted agent on your machine can bypass
that boundary.

The API receives the real credential and must be trusted with it. BlindDrop
blocks direct credential echoes, including across streamed chunks, but cannot
prevent a malicious API from disguising a key in its response. It also cannot
prevent an agent from misusing an action its key permits. See the
[security policy](SECURITY.md) for the full boundary.

## Documentation

- [Client guide](CLIENTS.md) — connect MCP hosts, SDKs, and HTTP clients
- [Plugin](plugin/README.md) — Claude Code plugin and the portable skill for Codex and Cursor
- [macOS app](https://github.com/IluvatarLabs/blinddrop/blob/v0.5.1/desktop/README.md) — build the app that hosts the owner page
- [Configuration](CONFIGURATION.md) — authentication, connections, backup, and limits
- [Fly.io](FLY.md) — set up and use a Fly connection
- [OAuth](OAUTH.md) — browser consent and saved refresh grants
- [Contributing](https://github.com/IluvatarLabs/blinddrop/blob/v0.5.1/CONTRIBUTING.md) — development and checks
- [Security](SECURITY.md) — reporting and trust boundaries
- [Changelog](CHANGELOG.md) — release history

PolyForm Noncommercial 1.0.0 (non-commercial use only). See [LICENSE](LICENSE).
Adapted components retain their [third-party notices](THIRD-PARTY-NOTICES.md).
