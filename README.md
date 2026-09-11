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

The vault is a file you own. You can copy it, back it up, and move it to another
computer. Closing the helper ends access for that session; saved keys remain
in the vault. There is no subscription or hosted account to maintain.

## Install

Requirements: Node.js 22.13+ on the 22.x line, or 23.5+, and npm. Version 0.3.0
has been tested on macOS and Linux. Windows is not verified.

From this source checkout:

```sh
npm ci
npm pack
npm install --global --prefix "$HOME/.local" ./blinddrop-0.3.0.tgz
export PATH="$HOME/.local/bin:$PATH"
blinddrop --help
```

This installs the command under your home directory on macOS and Linux.
BlindDrop is not yet on npm; install the tarball by its path. Add
`$HOME/.local/bin` to your shell's PATH to keep the command available in new
terminals.

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

From the same checkout, make a request with the included HTTP client:

```sh
blinddrop run github -- node examples/request.mjs /user
```

Unlock the vault when prompted. The command prints the HTTP status and your
GitHub account details. The client receives a temporary local URL and session
token; BlindDrop supplies the real GitHub token when it contacts the API.
When the command exits, its helper stops.

For another API, use its HTTPS origin and authentication format. See the
[configuration reference](CONFIGURATION.md) and the [Fly.io walkthrough](FLY.md).

## Running it

- `blinddrop run CONNECTION -- COMMAND ARGS…` runs a command with a local API
  endpoint and a temporary session token. Existing SDKs can use it if they let
  you configure their base URL and authentication header. Streaming is supported.
- `blinddrop serve --http --allow CONNECTION` starts a helper in your terminal
  for an independently launched MCP client. It prints the MCP URL and session
  token to put in your client's configuration. Leave the helper running.
- `blinddrop serve --allow CONNECTION` uses stdio for MCP clients that launch
  their own helper. See the [client setup](CONFIGURATION.md#agent-session).

HTTP sessions last one hour by default; `--ttl SECONDS` changes that. Stopping
or expiring the helper ends its session. A new session gets a new token. The
MCP tools are `list_connections` and `execute_http`.

The [client guide](CLIENTS.md) covers MCP configuration, the Claude SDK,
ordinary HTTP clients, and OAuth APIs. BlindDrop supports common API-key
placements, Basic authentication, OAuth grants, JWT bearer exchange, AWS
SigV4, and client TLS certificates. Native database connections, SSH,
WebSocket, gRPC, and browser login automation are outside this release.

## Your vault

By default, BlindDrop keeps two files:

```text
~/.config/blinddrop/
├── vault.enc               encrypted keys and connection settings
└── vault.enc.events.jsonl  request outcomes, without keys or request bodies
```

Back up `vault.enc`. Its passphrase is required to restore it; there is no
recovery bypass. Stop active helpers before replacing keys or changing the
passphrase. `blinddrop passwd` re-encrypts the current vault; older backups
still need their old passphrase.

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
- [Configuration](CONFIGURATION.md) — authentication, connections, backup, and limits
- [Fly.io](FLY.md) — set up and use a Fly connection
- [OAuth](OAUTH.md) — browser consent and saved refresh grants
- [Contributing](CONTRIBUTING.md) — development and checks
- [Security](SECURITY.md) — reporting and trust boundaries
- [Changelog](CHANGELOG.md) — release history

PolyForm Noncommercial 1.0.0 (non-commercial use only). See [LICENSE](LICENSE).
Adapted components retain their [third-party notices](THIRD-PARTY-NOTICES.md).
