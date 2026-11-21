# Use BlindDrop with existing clients

Keep credentials in an encrypted local archive and let an ordinary client use a
local endpoint. The provider's real key stays inside BlindDrop. The
client receives a random session token that works only with that running
helper and its allowed connections. No provider changes, cloud account with
BlindDrop, installed daemon, or interception certificate are required.

```mermaid
flowchart LR
    O[Owner app or terminal] -->|Unlock archive| F[BlindDrop session]
    V[Encrypted local archive] --> F
    A[SDK or MCP client] -->|Local URL + session token| F
    F -->|Existing authentication over HTTPS| P[Provider]
    P -->|Response| F
    F -->|Checked bytes or MCP result| A
```

The harness/OS protects the owner context and helper. The provider receives
its usual credential and must be trusted. These are the same assumptions as
the [security policy](SECURITY.md).

## Mac app: set up once

Install **BlindDrop.app** from the [release page](https://github.com/IluvatarLabs/blinddrop/releases/latest), then create or open a vault. Choose a connection template, enter its credential in the owner window, and save. In **Settings → Sessions**, install the integration for Claude Code or local Codex once. Host sessions started afterwards have BlindDrop's tools. The first time, approve those tools when the host asks: in Claude Code, its permission prompt or the user-level allow rule `mcp__plugin_blinddrop_blinddrop__*`; in Codex, its tool approval setting for the plugin. Codex also asks you to review the plugin and its hook, and asks again whenever the plugin changes, as after an update or after moving the app. Then ask the agent to use the named connection. Normal Mac use needs no global CLI, Node installation, PATH changes or copied session token.

From then on, routine agent use needs nothing from you except an unlock when a vault is locked. You never start a session or unlock in advance. Agents may still ask you for what only you can give: task inputs, a credential or connection you have not added, an OAuth sign-in in the app, or a decision after an outcome that may be unknown. When an agent's call needs a vault that is locked, BlindDrop brings up its unlock; once you unlock it, the waiting call continues. If you do not unlock within 20 seconds, the agent gets `VAULT_LOCKED`, carries on with other work and tries again later. If the app is not running, the agent's call starts it, locked. Closing the window keeps the app and its agent access running; the Dock or menu-bar icon reopens it. **Lock All** revokes access, and **Quit** ends the process. A new launch starts locked; a vault set to Touch ID or Without asking then opens without its passphrase when an agent's call needs it or Unlock selects it at launch, Touch ID after a touch.

The app manages its integration's Install, Update and Remove controls, and refreshes an installed integration at every launch, so a moved or replaced app keeps working. The host's configuration holds no URL, port or session token: the integration reads the app's current endpoint for each call, so port changes, lock and unlock, edits and token renewal need no host reload or reconnect. Hooks provide guidance; they do not replace the host's permission boundary. See the [integration guide](plugin/README.md) for host behavior and the optional manual setup.

## Optional CLI: put a key in the archive

Install the release as described in [README](README.md#install). In your own
terminal, initialize once, store a key at the hidden prompt, then name its
destination:

```sh
blinddrop init
blinddrop secret set work-key
blinddrop connection set work-api \
  --origin https://api.example.com --auth bearer --secret work-key
blinddrop list
```

Substitute the real HTTPS origin and authentication format. Do not reinitialize
an existing vault. The value persists in `~/.config/blinddrop/vault.enc` until
you replace/remove it; stopping the helper does not erase it. The provider
can expire/revoke a key independently. Owner commands ask for the archive
passphrase; the helper asks once for its lifetime.

Since 0.5.1 a secret can hold more than one named field, and a connection
reference can name a vault and a field as `vault#secret#field`. These
single-value recipes still work unchanged: `secret set NAME` stores one value,
and a bare `--secret NAME` resolves to it. When a credential has several parts
— an AWS access-key id and secret, a client id and secret, a certificate and
its key — build a typed multi-field secret in the owner page's field editor, or
pick a connection template that shapes both the connection and its secret for
you. Keep unrelated secrets in separate vaults and unlock only the one a task
needs; a connection is usable only while every vault holding its referenced
fields is unlocked.

## Run an HTTP client

From this checkout, this is a complete read through an existing connection:

```sh
blinddrop run work-api -- node examples/request.mjs /v1/items
```

The example uses Node's normal `fetch`; it has no access to the stored key.
`run` sets `BLINDDROP_BASE_URL` and `BLINDDROP_TOKEN` for the child, inherits its
normal terminal I/O and returns its exit code. The helper closes when the
command exits. Ctrl-C or session expiry closes the helper and terminates the
child. `--ttl 3600` is the default; allowed values are 1–86400 seconds.

The example files are also included under `examples/` in the installed
package. Copy them into your own project if using a tarball without this
checkout. With the README's user prefix, the installed directory is
`~/.local/lib/node_modules/blinddrop/examples/` on macOS/Linux.

### Fly.io: use the existing saved connection

For the owner setup and complete `FlyV1 ` Authorization value, see [Fly](FLY.md).
If the `fly` connection already exists, no new token is needed:

```sh
blinddrop run fly -- node examples/request.mjs '/v1/apps?org_slug=personal'
```

Replace `personal` for another organization. A successful request returns
HTTP 200, app names and `total_apps`. This command reads; it does not deploy
or restart anything. The provider's token scope controls allowed operations.

### Claude: use the official SDK, including streaming

In your application directory, install the official SDK and copy the supplied
`examples/anthropic.mjs` into it. The example has no BlindDrop imports and uses
the SDK's normal environment configuration. The version used by the controlled
functional verification is pinned here for reproduction:

```sh
npm install @anthropic-ai/sdk@0.125.0
blinddrop secret set anthropic-key
blinddrop connection set anthropic \
  --origin https://api.anthropic.com \
  --auth header --field x-api-key --secret anthropic-key
blinddrop run anthropic \
  --base-url-env ANTHROPIC_BASE_URL --api-key-env ANTHROPIC_API_KEY \
  -- node anthropic.mjs YOUR_AVAILABLE_MODEL 'Say hello in one sentence.'
```

Choose a model available to your account. Enter the provider key only in the
owner secret prompt. `ANTHROPIC_API_KEY` in the child contains the **session
token**, which BlindDrop consumes before inserting the actual provider key.
`ANTHROPIC_BASE_URL` points to the local connection endpoint. Text deltas
print as they arrive. The example disables SDK automatic retries so a failed
response does not cause an implicit replay. Existing applications can use
the same two environment options or their SDK's `baseURL` and key settings.
[Official SDK](https://github.com/anthropics/anthropic-sdk-typescript).

Controlled HTTPS receivers and a real provider account are different proof
layers. Consult [CHANGELOG.md](CHANGELOG.md) for what has actually been exercised;
a recipe alone is not live-account verification.

### GitHub: an ordinary personal access token

Create a token using GitHub's existing controls, then store it:

```sh
blinddrop secret set github-pat
blinddrop connection set github \
  --origin https://api.github.com --auth bearer --secret github-pat
blinddrop run github -- node examples/request.mjs /user
```

The example sends the User-Agent GitHub requires. `/user` returns the
authenticated identity; a fine-grained token needs no additional permission
for that endpoint. For repository operations, give the token the appropriate
repository access. This is REST API use; native Git/SSH and automatic GitHub
App token minting are separate mechanisms and are not supplied.
[GitHub endpoint requirements](https://docs.github.com/en/rest/users/users#get-the-authenticated-user).

### Google and other OAuth APIs

Follow [OAuth onboarding](OAUTH.md) to save a refresh grant. The same resulting
connection works through MCP or the HTTP endpoint:

```sh
blinddrop run google-drive -- node examples/request.mjs \
  '/drive/v3/files?pageSize=10&fields=files(id,name)'
```

The helper handles token acquisition/refresh and saves rotated refresh tokens
using the existing encrypted writer. There is no SDK-specific Google adapter.
The Google example remains a configuration recipe unless
[CHANGELOG.md](CHANGELOG.md) records a live-account result.

## Attach an independently launched MCP host

Start a finite helper in your owner terminal:

```sh
blinddrop serve --http --allow work-api --ttl 3600
```

After hidden unlock, it prints one JSON object with `mcpUrl`, `connections`,
`token` and `expiresAt`. Leave that process running. Configure a host that
supports Streamable HTTP with the reported URL and Bearer header. For hosts
using Claude Code's MCP JSON shape:

```json
{
  "mcpServers": {
    "blinddrop": {
      "type": "http",
      "url": "http://127.0.0.1:REPORTED_PORT/mcp",
      "headers": { "Authorization": "Bearer REPORTED_SESSION_TOKEN" }
    }
  }
}
```

That configuration contains session-use authority, not the vault passphrase
or provider key. It stops working when the process stops or expires. A new
helper issues a new token; update the client configuration. The port is chosen
randomly once and saved in Settings. `--port PORT` saves a custom preference;
if busy, the next available port is saved. Always use the reported URL.
`--port 0` requests a temporary port without changing the saved preference. Repeat
`--allow` to include another exact connection. The host sees only
`list_connections`, `execute_http` and `invoke_modal_function`. Existing stdio setup remains available
in [CONFIGURATION.md](CONFIGURATION.md#agent-session).

This CLI mode keeps owner unlock in the terminal. The Mac app provides its
own owner window; neither path implies that every GUI host has been tested.
Browser JavaScript requests carrying `Origin` are rejected;
this endpoint is for local clients, not a webpage API.

## Agent integrations

Use the app's Agent Integrations controls for Claude Code and local Codex. They manage a local plugin through the host's native plugin commands, preserving unrelated configuration. The plugin's MCP server is `blinddrop agent`, a stdio server the host launches from the app bundle:

- It answers the host's MCP handshake and tool list itself, so the host's first connection never depends on the app.
- For each tool call it reads the app's current session file and forwards the call to the app's local endpoint. For these calls the session token stays between `blinddrop agent` and the app, and the provider key never reaches the agent.
- If the app is not running when a call starts, it starts it in the background, locked, and waits up to 8 seconds for its endpoint.
- If the call needs a locked vault, BlindDrop shows its unlock and `blinddrop agent` sends the call again every second for up to 20 seconds, stopping at once if the host cancels. If the app goes away during that wait, for example because you quit it, the call ends with its last result and the app is not started again. Nothing is sent upstream while the vault is locked, so this never runs a request twice. A call whose outcome may be unknown is never sent again.

Leave **Agent access** enabled in Settings; with it off, the agent's calls report that agent access is turned off and the app is not started, and turning it off ends running `run --app` commands' access (below). The app chooses and saves a random port on first use, and the integration follows it without a host reload. Manual plugin/skill installation remains available in the [plugin guide](plugin/README.md); a manual MCP setup runs `blinddrop agent` from the CLI on PATH. Hook support differs by host; the [security policy](SECURITY.md) defines the boundary.

The plugin's one hook steers agents away from BlindDrop's own files: it refuses Read, Edit and Write calls on paths under `~/.config/blinddrop/`, and shell commands that name that path, including commands that only mention it, such as a search over source code for that string. It does not restrict other files. Codex sends file edits to hooks as `apply_patch`, which the hook does not check, so in Codex it refuses only the shell commands.

### Commands that agents run

An agent that needs an SDK or command-line client runs it through the app:

```sh
blinddrop run --app CONNECTION -- COMMAND ARGS...
```

`--base-url-env NAME` and `--api-key-env NAME` work as for `run` above. It reads the app's session file and never prompts. Run from the app's bundled runtime, it starts the app when it is not running. The command receives `BLINDDROP_BASE_URL` (the connection's base URL on the app's endpoint) and `BLINDDROP_TOKEN` (the app's session token), never the provider key. In an app-only installation, BlindDrop's MCP instructions and skill give agents the exact command for the runtime bundled in the app, so no CLI on PATH is needed.

- A locked connection answers the command's first request with HTTP 423 `VAULT_LOCKED`, and BlindDrop shows its unlock. The agent runs the command again after the unlock.
- The token works for every connection the agent can already use through its tools, not only `CONNECTION`. It keeps working across unlocks and edits, and stops when every vault becomes locked, when **Agent access** is turned off, or at the 24-hour renewal. It gives the command no access the agent's tools lack.
- Changing the session port in Settings ends running commands' access, because their base URL names the old port.
- A host that sandboxes shell commands can block `run --app`. In Claude Code's sandboxed Bash, a command cannot reach a local server outside the sandbox by default, and the suggested `Read(~/.config/blinddrop/**)` deny rule also stops it from reading the session file. Run such commands outside the sandbox through the host's own settings; permissions and isolation belong to the host.

Without `--app`, `run` is the owner-terminal workflow above.

## What fits, and what does not

A client must let you configure its base URL and send a header containing
the session token: `Authorization: Bearer TOKEN` **or** `x-api-key: TOKEN`.
Send one, not both. Preserve the `/api/CONNECTION/` prefix when building URLs.
The helper removes these local authentication headers, supplies the configured
upstream authentication and preserves ordinary path/query/body bytes.
Clients with fixed endpoints or unsupported authentication headers need an
existing customization hook; BlindDrop does not intercept their TLS traffic.

The SDK path supports ordinary HTTP and SSE with identity/gzip/deflate/Brotli
decoding. Requests are buffered up to 16 MiB; responses stream up to 64 MiB
on both encoded and decoded bytes; the total request bound is ten minutes.
Headers are limited to 16 KiB and the session permits four concurrent operations.
MCP remains buffered with its original 1 MiB request/4 MiB response/30-second
limits. There are no user-facing tuning flags.

Streaming checks known credential patterns across chunk boundaries before
releasing bytes. If a later chunk fails, the connection is truncated;
already delivered safe bytes remain visible. MCP checks its complete response
before releasing it. Neither promises to detect a malicious provider's
arbitrary transformation of its credential. Cookies/trailers are discarded;
SDK redirects fail instead of sending a client to another destination.
BlindDrop never retries an ambiguous operation. WebSocket, gRPC, browser-login
automation, native databases and SSH are outside this release, except the
bounded [Modal Function](CONFIGURATION.md#modal-functions) invocation through
Modal's official SDK.

## Maintain your vault

A running CLI helper (`serve` or `run` without `--app`) keeps the archive it opened. Stop it before owner changes from the CLI, then start a new one:

```sh
blinddrop secret set work-key
blinddrop passwd
```

`passwd` asks for the old passphrase and the new passphrase twice, then
atomically re-encrypts the archive. Secrets and connection references stay
the same. Existing encrypted backups still need their old passphrase.
In the app, **Back Up Setup** saves all registered encrypted vaults and their
connection definitions, groups and settings. **Restore Setup** accepts that
folder only into a fresh installation, preserving each vault's passphrase.
Changing Appearance before restore is allowed; existing vaults and connection
configuration are never overwritten or merged. If an archive was moved,
**Locate file** reconnects it under its existing vault name and references,
then asks for its passphrase.
**Export Encrypted Vault** copies one archive only. There is no recovery bypass
if its passphrase is lost. A complete app setup also needs `connections.json`
and `vaults.json`, plus any wanted groups and settings. A standalone CLI archive
needs its `.connections.json` sidecar. See the backup instructions in
[CONFIGURATION.md](CONFIGURATION.md#replace-disable-and-back-up).
Disable/remove commands and trusted inherited-input
descriptors are documented in [CONFIGURATION.md](CONFIGURATION.md#replace-disable-and-back-up).
