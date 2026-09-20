---
name: blinddrop
description: Use an API key, token or other credential without ever seeing it. BlindDrop keeps the owner's credentials in a local encrypted vault and makes the authenticated HTTPS request for you. Use this skill when a task needs an API key, token, password or authenticated request; when a request comes back 401 Unauthorized or 403 Forbidden; when you are about to read, search or copy a .env file, a .pem or .key file, an id_rsa file or any other credential store; or when the owner asks for a call to an API you hold no key for. It covers the two session tools, list_connections and execute_http, the `blinddrop run` wrapper for SDKs and CLIs, what to do when the connection you need does not exist, and what never to do with a credential.
license: PolyForm-Noncommercial-1.0.0
compatibility: Requires the blinddrop executable installed locally and a session the owner has started; the agent host must support MCP over HTTP, or the work must run under `blinddrop run`.
metadata:
  component: agent-credential-use
  version: "0.5.1"
---

# BlindDrop: use credentials you are not allowed to read

## How it works, and what you never see

The owner keeps secrets in one or more local encrypted vaults, unlocks the ones a
task needs in their own terminal or in the BlindDrop app, and authorizes an exact
list of **connections** for the session. A connection binds one HTTPS origin to
the stored secret fields it uses and one authentication format.

You send an ordinary HTTPS request naming a connection. BlindDrop adds the
configured authentication inside its own process, sends it to that origin, checks
the complete response for the credential, and returns the response to you.

You never receive, and must never try to obtain: the archive passphrase, any
stored secret value, the authenticated URL, or upstream cookies. A request to a
connection this session did not authorize, or to any other origin, is refused.
BlindDrop holds the key; you hold the ability to use it for this session only.

## The two tools

The tools are named `list_connections` and `execute_http`. Your host may list
them under a longer namespaced name; use whatever name your tool list shows for
these two tools.

`list_connections` takes no arguments and returns the connections this session
authorizes, with the origin and authentication type of each. Call it first: it
tells you what is actually available before you plan a request.

`execute_http` performs one request through one connection:

```json
{
  "connection": "work-api",
  "method": "GET",
  "path": "/v1/items",
  "query": { "limit": "10" },
  "headers": { "Accept": "application/json" }
}
```

- `connection` and `path` are required; `method` defaults to GET.
- Choose exactly one request representation: `body` for UTF-8 text,
  `bodyBase64` for bytes, or `multipart` with `fields` and
  `files: [{ "name", "filename", "contentType", "dataBase64" }]`.
- The result carries `status`, `headers` and a UTF-8 `body`. Set
  `responseEncoding: "base64"` for binary bytes.
- Errors carry a static `error.code` and `error.message`. `RESPONSE_BLOCKED`
  means the response contained the credential and was withheld; that is the
  system working, not a bug to route around.
- Do not add an `Authorization`, `x-api-key` or similar header yourself.
  BlindDrop supplies the authentication; a header you invent will be wrong.

## SDKs and command-line tools: `blinddrop run`

For work that belongs to a real SDK or CLI rather than a single request, the
owner runs the command inside a session:

```sh
blinddrop run work-api -- node ./script.mjs /v1/items
```

`run` sets `BLINDDROP_BASE_URL` and `BLINDDROP_TOKEN` for the child process and
closes the session when the command exits. For an SDK that reads its own
variables, name them:

```sh
blinddrop run anthropic \
  --base-url-env ANTHROPIC_BASE_URL --api-key-env ANTHROPIC_API_KEY \
  -- node ./app.mjs
```

The child receives the local base URL and the **session token**, never the
provider key. `blinddrop run` asks for the passphrase on the owner's controlling
terminal, so you cannot start it from a tool call: give the owner the exact
command to run.

## Never

- Never read, search, copy, print or write a `.env` or `.env.*` file, a `.pem`
  or `.key` file, `id_rsa`, `id_ed25519`, or anything under `~/.config/blinddrop/`,
  and never work around a rule that stops you.
- Never print, log, echo, commit or write a credential value anywhere, including
  into a scratch file, a test fixture, or a message to the owner.
- Never ask the owner to paste a key, token or passphrase into the conversation.
  Credentials are entered at the owner's hidden prompt, nowhere else.
- Never store a credential you were given by accident: report it and stop.

## When the connection you need does not exist

`list_connections` is the authority. If the connection you need is not there,
do not look for the key elsewhere. Tell the owner exactly what to run in their
own terminal, or the same steps in the BlindDrop app, substituting the real
origin and authentication format:

```sh
blinddrop secret set work-key
blinddrop connection set work-api \
  --origin https://api.example.com \
  --auth bearer --secret work-key
```

Other formats are `--auth header --secret KEY_REF --field X-Api-Key`,
`--auth query --secret KEY_REF --field api_key`, and
`--auth basic --username-secret USER_REF --password-secret PASS_REF`. Add
`--allow-private` for a private or localhost HTTPS API. The value is typed at
the hidden prompt `secret set` opens; it is never a command argument.

For a credential with several parts (an AWS key pair, a client id and secret) or
to keep it in a separate vault, tell the owner to build a typed multi-field
secret or pick a connection template in the BlindDrop app instead; a reference can
name a vault and field as `vault#secret#field`. A single-value key still works
exactly as shown above.

Changing the archive requires a new session. In the BlindDrop app that happens
by itself: an owner change restarts the session. With a terminal session, the
owner stops it, makes the change, and starts a new one.

## When no BlindDrop session is attached

If your tool list has no BlindDrop tools, no session is reachable. Ask the owner
to unlock the BlindDrop app: while a vault is unlocked a session runs, and it
writes the session file this plugin reads automatically. Locking every vault or
quitting the app ends that session.

The owner can instead start one in their own terminal:

```sh
blinddrop serve --http --allow work-api --ttl 3600
```

It prints one JSON line with `mcpUrl`, `connections`, `token` and `expiresAt`,
and keeps running. The host is then attached by hand with the printed values,
for example:

```sh
claude mcp add --transport http blinddrop MCP_URL --header "Authorization: Bearer SESSION_TOKEN"
```

That token is session-use capability, not the vault passphrase or the provider
key, and it stops working when the session stops or expires. Let the owner
configure it; do not ask for it to be pasted into the conversation.
