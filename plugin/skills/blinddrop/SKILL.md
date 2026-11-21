---
name: blinddrop
description: Use an API key, token or other credential without ever seeing it. BlindDrop keeps the owner's credentials in a local encrypted vault and uses them for you. Use this skill when a task needs an API key, token, password, authenticated request or Modal Function call; when a request comes back 401 Unauthorized or 403 Forbidden; when you are about to read, search or copy a credential from a .env file, a .pem or .key file, an id_rsa file or any other credential store; or when the owner asks for a call to an API you hold no key for. It covers the three tools, list_connections, execute_http and invoke_modal_function, how to follow each connection's returned usage guidance, the `run --app` command for SDKs and command-line tools, what to do when a connection is locked or missing, and what never to do with a credential.
license: PolyForm-Noncommercial-1.0.0
compatibility: Requires BlindDrop's MCP server, `blinddrop agent`, which BlindDrop's agent integration installs, and an agent host that runs local stdio MCP servers.
metadata:
  component: agent-credential-use
  version: "0.6.2"
---

# BlindDrop: use credentials you are not allowed to read

## How it works, and what you never see

The owner keeps secrets in one or more local encrypted vaults in the BlindDrop
app and sets up **connections** for agents. A connection binds one service to
the stored secret fields it uses and the way that service expects them.

You name a connection and supply an ordinary request: an HTTPS request, or JSON
arguments for the one Modal Function the owner chose. BlindDrop adds the
credentials inside its own process, makes the call, checks the complete result
for the credential, and returns the result to you. When a vault the connection
needs is locked, your call asks BlindDrop to show the owner its unlock prompt.

You never receive, and must never try to obtain: the archive passphrase, any
stored secret value, client or token IDs, the authenticated URL, or upstream
cookies. A request to a connection the owner has not set up, or to any other
origin, is refused. BlindDrop holds the key; you hold the ability to use it.

## The three tools

The tools are named `list_connections`, `execute_http` and
`invoke_modal_function`. Your host may list them under a longer namespaced
name; use whatever name your tool list shows for these tools.

### Start with `list_connections`

`list_connections` takes no arguments. Call it first, before you plan a
request: it returns the connections you can use, and how to use each one. Each
item has:

- `name`, `origin` and `authType`: the connection and the service it reaches.
- `available`: `true` when you can use the connection now. `false`, with
  `reason: "locked"`, when a vault it needs is locked; calling it asks the
  owner to unlock (see "When a connection is locked or missing").
- `tool`: the tool to call for this connection, `execute_http` or
  `invoke_modal_function`.
- `summary`: what the connection is for.
- `example`: a complete input for that tool, already naming the connection.
  Start from it rather than writing a request from memory.
- `schematic`: when `true`, the example contains placeholders such as
  `<bucket>` or `<key-id>`, or is not a documented provider operation. Fill
  each placeholder from the task, or ask the owner. Never invent a resource
  name, ID or path, and check the provider's API documentation before relying
  on a schematic example.
- `notes`: required headers, permissions, inputs and other usage details.
  Follow them.
- `recipe`: the template the connection came from, or `null` when only generic
  guidance is available.
- `target` (Modal connections only): the app, Function and environment the
  owner fixed, with an optional `usage` description of the arguments.

This guidance never contains a credential. Do not look for one elsewhere.

### `execute_http`

`execute_http` performs one HTTPS request through one connection. Copy the
connection's `example` and adjust it for the task; the shape is:

```json
{
  "connection": "<name from list_connections>",
  "method": "GET",
  "path": "<path from the connection's example>",
  "query": { "<name>": "<value>" },
  "headers": { "Accept": "application/json" }
}
```

- `connection` and `path` are required; `method` defaults to GET.
- Choose exactly one request representation: `body` for UTF-8 text,
  `bodyBase64` for bytes, or `multipart` with `fields` and
  `files: [{ "name", "filename", "contentType", "dataBase64" }]`.
- The result carries `status`, `headers` and a UTF-8 `body`. Set
  `responseEncoding: "base64"` for binary bytes.
- Do not add an `Authorization`, `x-api-key` or similar header yourself.
  BlindDrop supplies the authentication; a header you invent will be wrong.

### `invoke_modal_function`

`invoke_modal_function` calls the Modal Function in the connection's `target`.
You supply only JSON arguments:

```json
{
  "connection": "<name from list_connections>",
  "args": [],
  "kwargs": { "<argument>": "<value>" }
}
```

`args` holds positional and `kwargs` keyword arguments, both optional. The
result is `{ "result": ... }`, the Function's JSON return value; a non-JSON
return fails with `UNSUPPORTED_RESPONSE`. You cannot choose another app,
Function, environment or credential.

Arguments must match the Function's signature. Take them from the target's
`usage`, the task, or the application's own code. If none of those establishes
them, ask the owner. Never guess Modal arguments.

### Errors and retries

Errors carry a static `error.code` and `error.message`.

- `VAULT_LOCKED` means a vault the request needs is locked, and the request
  was not sent. BlindDrop has already shown the owner its unlock prompt and
  waited up to 20 seconds. See "When a connection is locked or missing".
- `SECRET_INVALID` means the connection's stored credential cannot be sent as
  stored, usually a stray character pasted with it; nothing was sent. Tell the
  owner which connection needs its credential re-entered, and do not retry.
- `RESPONSE_BLOCKED` means the response contained the credential and was
  withheld; that is the system working, not a bug to route around.
- `UNSUPPORTED_OPERATION` means you called a tool this connection does not
  support. Call `list_connections` and use the connection's listed `tool`.
- `TIMEOUT` and `UPSTREAM_ERROR` mean the outcome is unknown: the request may
  have reached the service, and a Modal Function may have run. BlindDrop never
  retries for you. Do not retry a consequential call (one that creates, sends,
  charges, changes or deletes something) or any call with an unknown outcome.
  Report what happened to the owner and let them decide.

### OAuth connections

An OAuth connection the owner sets up with **Save and connect** in the
BlindDrop app appears only after they finish signing in. If an OAuth
connection fails because its authorization was rejected or expired, ask the
owner to sign in to it again in the BlindDrop app, then call
`list_connections` again. Never ask for an authorization code, token or
client secret.

## SDKs and command-line tools

For work that belongs to an SDK or a command-line tool rather than single
requests, run the command through BlindDrop. This works for HTTP connections,
not Modal Function connections:

```sh
blinddrop run --app CONNECTION -- COMMAND
```

`run --app` uses the BlindDrop app and never asks for a passphrase. It sets `BLINDDROP_BASE_URL`, the connection's base URL on
BlindDrop's local endpoint, and `BLINDDROP_TOKEN` for the command. For an SDK
that reads its own variables, add `--base-url-env NAME` and
`--api-key-env NAME` before `--`, for example
`--base-url-env ANTHROPIC_BASE_URL --api-key-env ANTHROPIC_API_KEY`. The command
receives the local base URL and a session token, never the provider key.

If the command's request comes back with HTTP 423 and `VAULT_LOCKED`,
BlindDrop has asked the owner to unlock the vault, and the request was not
sent. Continue other work, and run the command again once `list_connections`
shows the connection with `available: true`.

## When a connection is locked or missing

A connection with `available: false` is locked. When the task needs it, call
it anyway: BlindDrop shows the owner its unlock prompt, and the same call
completes if they unlock it within 20 seconds. If every vault is locked,
`list_connections` itself brings up the unlock and waits the same way.

A `VAULT_LOCKED` result means BlindDrop already showed the owner its unlock and
waited. Continue the parts of the task that need no credential, and call again
later. Never ask the owner to unlock, and never ask for a passphrase.

A connection that is not listed has not been added, or is turned off or
missing a secret. If the project already authenticates another way, keep
working that way (see the next section). Otherwise ask the owner to add it in
BlindDrop: **New Connection**, the matching template (or **Custom**), the
credential in the protected fields, then save. OAuth templates finish with
**Save and connect**, which opens the provider's sign-in in the owner's
browser. Then call `list_connections` again.

## When BlindDrop cannot be reached or has no connection

A BlindDrop tool call can return one of these errors:

- "Agent access is turned off in BlindDrop."
- "BlindDrop's agent endpoint did not start within 8 seconds."
- "BlindDrop is not running."

BlindDrop is the preferred way to use the owner's credentials, not a
precondition for the task. If a call returns one of these errors, your tool
list has no BlindDrop tools, or BlindDrop has no connection for the service,
mention it to the owner once and keep working as you would without BlindDrop:
commands, SDKs and scripts may use the credentials they are already set up
with, such as environment variables, a CLI's own login, or a `.env` file the
program loads itself. Do not stop the task over it, and do not report it again
on every call. The rules under "Never" still apply: do not read, print or copy
a credential value yourself.

## What you may ask the owner

Ask the owner only for what only they can give:

- task inputs, such as placeholder values and Modal arguments;
- a credential or connection that has not been added;
- an OAuth sign-in or re-sign-in in the BlindDrop app;
- a decision after an unknown outcome.

You may also tell them:

- that BlindDrop is waiting for an unlock it already raised;
- that BlindDrop does not hand credentials to other programs, so handing one
  over, for example to an installer that reads a key from a prompt or a file,
  is an owner step.

Never ask the owner to start a session, unlock in advance, reload plugins,
reconnect, restart a host, update an integration or run a command.

## Never

- Never read, print, search for or copy a credential from a `.env` file, a
  `.pem` or `.key` file, `id_rsa`, `id_ed25519` or another credential store.
  Templates such as `.env.example`, and handing such a file to the program that
  uses it, are ordinary work.
- Never read or change anything under `~/.config/blinddrop/`; BlindDrop owns
  those files. Never work around a rule that stops you.
- Never print, log, echo, commit or write a credential value anywhere, including
  into a scratch file, a test fixture, or a message to the owner.
- Never ask the owner to paste a key, token or passphrase into the
  conversation. Credentials belong in BlindDrop's protected fields.
- Never store a credential you were given by accident: report it and stop.
- Never guess a placeholder value or a Modal Function's arguments, and never
  retry a consequential or ambiguous call.
