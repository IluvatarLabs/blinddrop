---
name: blinddrop
description: Use an API key, token or other credential without ever seeing it. BlindDrop keeps the owner's credentials in a local encrypted vault and makes the authenticated HTTPS request for you. Use this skill when a task needs an API key, token, password or authenticated request; when a request comes back 401 Unauthorized or 403 Forbidden; when you are about to read, search or copy a .env file, a .pem or .key file, an id_rsa file or any other credential store; or when the owner asks for a call to an API you hold no key for. It covers the two session tools, list_connections and execute_http, the optional `blinddrop run` CLI workflow, what to do when the connection you need does not exist, and what never to do with a credential.
license: PolyForm-Noncommercial-1.0.0
compatibility: Requires a running BlindDrop app session and an agent host with local HTTP MCP support; an owner who explicitly uses the installed CLI may instead use `blinddrop run`.
metadata:
  component: agent-credential-use
  version: "0.6.0"
---

# BlindDrop: use credentials you are not allowed to read

## How it works, and what you never see

The owner keeps secrets in one or more local encrypted vaults, unlocks the ones a
task needs in the BlindDrop app, and authorizes an exact list of **connections**
for the session. A connection binds one HTTPS origin to the stored secret fields
it uses and one authentication format.

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

## Optional installed-CLI workflows: `blinddrop run`

If the owner explicitly chooses the installed CLI for work that belongs to an
SDK or command-line tool rather than a single request, they run the command
inside a session:

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
  Credentials belong in BlindDrop's protected owner fields or, for an explicit
  installed-CLI workflow, the CLI's hidden prompt.
- Never store a credential you were given by accident: report it and stop.

## When the connection you need does not exist

`list_connections` is the authority. If the connection you need is not there,
do not look for the key elsewhere. Ask the owner to open BlindDrop, unlock the
target vault, choose **New Connection**, select the matching template (or
**Custom**), enter the credential in the protected fields, and save. For a
credential with several parts or a separate vault, the owner uses one typed
multi-field secret; references can name a vault and field as
`vault#secret#field`.

If the owner explicitly prefers the installed CLI, the equivalent optional
workflow is:

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

Changing the archive requires a new session. In the BlindDrop app that happens
by itself: an owner change restarts the session. With a terminal session, the
owner stops it, makes the change, and starts a new one.

## When no BlindDrop session is attached

If your tool list has no BlindDrop tools, ask the owner to unlock the BlindDrop
app. While a vault is unlocked, the app runs a session and the managed plugin's
header helper reads its rotating session file. Locking every vault or quitting
the app ends access.

If the tools are still absent, ask the owner to use **Settings → Sessions**
and choose **Install** or **Update** for this host. Claude Code
then needs a restart or `/reload-plugins`; Codex needs a new session and may ask
the owner to review the plugin. Configuration is not proof of connection, so
call `list_connections` again after that supported reload step.

Only when the owner explicitly chose an installed-CLI workflow should you refer
them to the CLI's `serve` documentation. Never ask them to copy a session token
into chat or expose it to you.
