# Use BlindDrop with existing clients

Use an encrypted local archive, unlock once, and let an ordinary client use a
temporary local endpoint. The provider's real key stays inside BlindDrop. The
client receives a random session token that works only with that running
helper and its allowed connections. No provider changes, cloud account with
BlindDrop, installed daemon, or interception certificate are required.

```mermaid
flowchart LR
    O[Owner terminal] -->|Unlock archive| F[BlindDrop session]
    V[Encrypted local archive] --> F
    A[SDK or MCP client] -->|Local URL + session token| F
    F -->|Existing authentication over HTTPS| P[Provider]
    P -->|Response| F
    F -->|Checked bytes or MCP result| A
```

The harness/OS protects the owner context and helper. The provider receives
its usual credential and must be trusted. These are the same assumptions as
the [security policy](SECURITY.md).

## First: put a key in the archive

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
helper issues a new token; update the client configuration. `--port 8787`
can keep the URL stable but does not make the token permanent. Repeat
`--allow` to include another exact connection. The host sees only
`list_connections` and `execute_http`. Existing stdio setup remains available
in [CONFIGURATION.md](CONFIGURATION.md#agent-session).

HTTP mode solves terminal-less clients' unlock problem by keeping owner
unlock in the terminal. It does not provide a GUI or claim every GUI host
has been tested. Browser JavaScript requests carrying `Origin` are rejected;
this endpoint is for local clients, not a webpage API.

## Claude Code plugin

Install the plugin from the `plugin/` directory: `claude --plugin-dir /path/to/plugin` for a local checkout, or add the repository as a marketplace as the [plugin README](plugin/README.md) describes. It registers the BlindDrop MCP server at `http://127.0.0.1:8787/mcp` with a headers helper that reads `~/.config/blinddrop/session.json`, ships a skill that tells the agent to use `list_connections` and `execute_http` instead of reading keys, and adds a hook that refuses direct reads of `.env`, key files and the vault directory with a reason pointing at the tool. Start a session with the session file on, from the owner page, the app, or `blinddrop serve --http --allow CONNECTION --port 8787 --session-file ~/.config/blinddrop/session.json`, and Claude Code connects on its next request. The same skill folder installs into Codex and Cursor by copying; the README lists the paths. Hooks and permission rules steer the model; they are not a security boundary, as [SECURITY.md](SECURITY.md) explains.

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
automation, native databases and SSH are outside this release.

## Maintain your vault

Stop active helpers before owner changes, then start a new session:

```sh
blinddrop secret set work-key
blinddrop passwd
```

`passwd` asks for the old passphrase and the new passphrase twice, then
atomically re-encrypts the archive. Secrets and connection references stay
the same. Existing encrypted backups still need their old passphrase.
Copy the encrypted archive for backup; there is no recovery bypass if its
passphrase is lost. Disable/remove commands and trusted inherited-input
descriptors are documented in [CONFIGURATION.md](CONFIGURATION.md#replace-disable-and-back-up).
