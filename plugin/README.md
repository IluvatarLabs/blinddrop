# BlindDrop agent plugin

Agents reach for the key file because nothing better is in front of them. This
plugin puts something better in front of them: the skill that explains how to
use a credential without seeing it, a `PreToolUse` hook that answers an attempt
to open a credential file with the tool to use instead, and the MCP wiring that
finds the BlindDrop session the owner already started.

It contains no credential and no policy of its own. Everything it can do comes
from a session the owner started and scoped.

| Component | Path | What it does |
|---|---|---|
| Skill | `skills/blinddrop/SKILL.md` | How to use `list_connections` and `execute_http`, `blinddrop run` for SDKs and CLIs, and what to tell the owner when a connection is missing |
| Guard hook | `hooks/hooks.json`, `scripts/guard.mjs` | `PreToolUse` on `Read`, `Edit`, `Write` and `Bash`: denies a credential file and names the BlindDrop tool to use instead |
| Session context | `scripts/session-context.mjs` | `SessionStart`: tells the session which connections are live |
| MCP server | `.mcp.json`, `scripts/session-headers.mjs` | Connects to the running session and supplies its Bearer header |

The scripts are dependency-free Node ES modules. Node `^22.13.0 || >=23.5.0`,
the same range the runtime requires.

## Install

For one session, from a local checkout:

```sh
claude --plugin-dir /path/to/plugin
```

From the repository:

```sh
git clone https://github.com/IluvatarLabs/blinddrop
claude --plugin-dir ./blinddrop/plugin
```

Once the repository publishes a plugin marketplace catalog, the marketplace form
installs it permanently instead:

```
/plugin marketplace add IluvatarLabs/blinddrop
/plugin install blinddrop@blinddrop
```

## Point it at a session

The plugin reads the session file BlindDrop writes, defaulting to
`~/.config/blinddrop/session.json`. Set `BLINDDROP_SESSION_FILE` to read another
path. The owner unlocks the BlindDrop app, which runs a session for as long as
a vault stays unlocked, or starts one in their own terminal:

```sh
blinddrop serve --http --allow work-api --ttl 3600 --session-file ~/.config/blinddrop/session.json
```

The MCP URL defaults to `http://127.0.0.1:8787/mcp`. Set `BLINDDROP_MCP_URL` when
the session runs on another port. With no live session file the server connects
without a credential, the helper writes one line to stderr saying so, and the
`SessionStart` note tells the agent that no stored credential is reachable.

The session token is capability to use the owner's allowed connections until the
session ends. It is never the archive passphrase and never a provider key.

## Add the deny rules

The hook covers tool calls. Permission rules cover the same paths one layer
lower, including `@`-references in a prompt, which no `PreToolUse` hook sees.
Paste this into `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.config/blinddrop/**)",
      "Read(//**/.env)",
      "Read(//**/.env.*)",
      "Read(//**/*.pem)",
      "Read(//**/*.key)"
    ]
  }
}
```

The block lives here rather than in the plugin because a plugin's own
`settings.json` supports only the `agent` and `subagentStatusLine` keys; a
plugin cannot ship permission rules.

## Codex, Cursor, and other hosts

The skill uses only the six portable Agent Skills frontmatter fields, so the
same folder installs anywhere that reads the standard. Copy the directory
unchanged:

```sh
cp -R plugin/skills/blinddrop ~/.agents/skills/blinddrop     # Codex
cp -R plugin/skills/blinddrop .cursor/skills/blinddrop       # Cursor, per project
```

Codex also reads `.agents/skills/` in the project directory. The hook and the
MCP wiring are Claude Code formats; in another host, attach the session the way
that host configures an HTTP MCP server, with the URL and Bearer token
`blinddrop serve --http` prints.

## What this does not do

Hooks and deny rules steer the model. They are not a security boundary. A
`PreToolUse` hook sees the tool calls Claude Code makes; it does not see, and
cannot stop, a process that reads the file by another route, and an agent
running without the host's permission checks is outside the assumed
restrictions.

The boundary BlindDrop does hold is the one in `SECURITY.md`: encrypted storage,
restrictive file permissions, owner operations separated from agent tools,
authorized credential use, and credentials kept out of the request, response,
error and logging paths, assuming the agent harness and operating system enforce
the configured host permissions and the destination service is trusted with the
credential it receives. This plugin adds guidance and friction on top of that
boundary; it does not widen it.

## Verified

September 16, 2026, on macOS with Claude Code 2.1.273, codex-cli 0.147.0 and
Node 26.7.0. A disposable HTTPS fixture, a scratch archive with a generated
passphrase and a generated fixture credential, and a scratch `.env` holding a
generated fake value. Every temporary vault, session file, `.env` and receiver
was removed afterwards.

The session ran as `serve --http --allow fixture`, and its readiness JSON, which
carries the same fields as the session file, was written to a scratch session
file with mode `0600`. Claude Code ran in print mode from a scratch working
directory:

```sh
claude -p --plugin-dir <plugin> --setting-sources '' --permission-mode default \
  --allowedTools Read Bash Skill \
    mcp__plugin_blinddrop_blinddrop__list_connections \
    mcp__plugin_blinddrop_blinddrop__execute_http \
  --no-session-persistence --output-format stream-json --verbose "<prompt>"
```

- **Loaded.** The `init` event reported the server as `plugin:blinddrop:blinddrop`
  with status `connected`, the tools as
  `mcp__plugin_blinddrop_blinddrop__list_connections` and
  `mcp__plugin_blinddrop_blinddrop__execute_http`, and the skill as
  `blinddrop:blinddrop`. The headers helper supplied the session token: a server
  whose credential is rejected reports a failed connection instead.
- **`--strict-mcp-config` had to be dropped.** With that flag the `init` event
  reported no MCP servers at all: it restricts the session to servers passed
  with `--mcp-config`, which excludes a plugin's own server.
- **The hook denied the credential file**, in `default` and in
  `bypassPermissions` permission mode, for `Read` on `.env` and for Bash
  `cat .env`. The reason reached the model verbatim:

  ```text
  BlindDrop holds this credential. Use the blinddrop MCP tool execute_http with a connection from list_connections, or run the command under `blinddrop run CONNECTION -- ...`. Never read the key itself.
  ```

- **The request went through BlindDrop.** The fixture recorded one authenticated
  `GET /identity` and the model reported the account id from its response.
- **Nothing leaked.** The scratch `.env` value never appeared in the model's
  output; the fixture credential, the archive passphrase and the session token
  appeared nowhere in captured stdout or stderr.
- **Without being told to read the file**, asked only to print `.env` and then
  call the fixture, the model declined the read on its own and cited the
  `SessionStart` note, then made the BlindDrop request. The transcripts that show
  the hook denial come from a prompt that instructed the tool call directly.
- **Deterministic script checks**, driving each script the way its host does,
  with the hook event on stdin and the session file named by the environment:

  ```sh
  echo '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}' | node scripts/guard.mjs
  echo '{"tool_name":"Read","tool_input":{"file_path":"/h/.config/blinddrop/vault.enc"}}' | node scripts/guard.mjs
  echo '{"tool_name":"Bash","tool_input":{"command":"npm test -- --run"}}' | node scripts/guard.mjs
  BLINDDROP_SESSION_FILE=<live>    node scripts/session-headers.mjs
  BLINDDROP_SESSION_FILE=<expired> node scripts/session-headers.mjs
  BLINDDROP_SESSION_FILE=<live>    node scripts/session-context.mjs
  ```

  `guard.mjs` denied `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`
  and paths under `.config/blinddrop/` for `Read`, `Edit`, `Write` and `Bash`,
  including quoted, `--file=`, redirected, command-substituted and Windows
  spellings, printing the deny object above and exiting 0; it printed nothing and
  exited 0 for benign commands, unrelated tools, absent `tool_input`, malformed
  JSON and empty input. `session-headers.mjs` printed
  `{"Authorization":"Bearer <token>"}` for a live session file, and `{}` plus the
  one-line stderr note for an expired and for a missing one.
  `session-context.mjs` listed the live connection names, printed `none` for an
  empty connections map, and reported no running session when the file was
  absent or expired.
- **Codex.** With the skill directory copied unchanged to `.agents/skills/blinddrop`
  in a scratch project, `codex debug prompt-input` listed it as
  `- blinddrop: <description> (file: .../.agents/skills/blinddrop/SKILL.md)`. The
  Cursor path is documented from the standard, not exercised here.

One deviation: port `8787` was already in use on the test machine by an
unrelated process, so the session bound a free port and the run set
`BLINDDROP_MCP_URL` to its URL. That exercises the documented override in
`.mcp.json` rather than its default.
