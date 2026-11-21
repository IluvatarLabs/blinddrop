# BlindDrop agent plugin

Agents reach for the key file because nothing better is in front of them. This
plugin puts something better in front of them: the skill that explains how to
use a credential without seeing it, BlindDrop's MCP server, `blinddrop agent`,
which carries each tool call to the BlindDrop app, and a `PreToolUse` hook that
steers tool calls away from BlindDrop's own files.

It contains no credential and no policy of its own. Everything it can do comes
from the connections the owner set up in BlindDrop.

| Component | Path | What it does |
|---|---|---|
| Skill | `skills/blinddrop/SKILL.md` | How to use `list_connections` and its per-connection guidance, `execute_http` and `invoke_modal_function`, `run --app` for SDKs and CLIs, and what to do when a connection is locked or missing |
| MCP server | `.mcp.json` | Runs `blinddrop agent`, a local stdio MCP server that forwards each tool call to the BlindDrop app |
| Guard hook | `hooks/hooks.json`, `scripts/guard.mjs` | `PreToolUse` on `Read`, `Edit`, `Write` and `Bash`: denies a call that targets BlindDrop's own files and names the tool to use instead |

The app-managed integration runs `blinddrop agent` and the guard with the app's
bundled runtime, so normal Mac use needs no external Node or shell PATH setup.
Manual installation requires the `blinddrop` CLI on PATH and Node
`^22.13.0 || >=23.5.0`.

## Install

In BlindDrop.app, open **Settings → Sessions**. Use
**Install**, **Update** or **Remove** for Claude Code or local Codex. The app
uses each host's native plugin commands and changes only its own local plugin.
Unrelated plugins, skills, MCP servers and settings are preserved. The host
must already be installed. **Configured** means installed configuration, not a
verified authenticated request. Remove disables this integration without
deleting vaults or connections.

Each launch of the app refreshes an installed integration through the host's
own update command, so a moved, replaced or upgraded app keeps working.

After an install or update, once:

- start a new Claude Code session or run `/reload-plugins`, and start a new
  Codex session;
- approve BlindDrop's tools in each host (below);
- in Codex, review the plugin and its hook when Codex asks. Codex asks again
  whenever the plugin changes, as after an update or after moving the app.

Nothing else is needed for daily use. Host sessions started with BlindDrop's
earlier HTTP configuration need one new session after the upgrade.

### Approve BlindDrop's tools once

Claude Code asks permission the first time each BlindDrop tool runs. To allow
them in every session, add this rule to `~/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["mcp__plugin_blinddrop_blinddrop__*"]
  }
}
```

Codex applies its tool approval setting to the plugin's MCP tools. To approve
them for the app-managed plugin, add this to `~/.codex/config.toml`:

```toml
[plugins."blinddrop@blinddrop-desktop".mcp_servers.blinddrop]
default_tools_approval_mode = "approve"
```

BlindDrop never writes these settings itself: permissions belong to the host.

## How agents reach BlindDrop

The host starts `blinddrop agent` as a local stdio MCP server. It answers the
host's handshake and tool list itself, so a session that starts while BlindDrop
is locked or not running still has BlindDrop's tools. For each tool call, it
reads the session file BlindDrop keeps and forwards the call to the app's local
endpoint. The host configuration holds no URL, port or token, so locking,
unlocking, owner edits, token renewal and port changes need no reload.

- **Locked vault.** A call that needs a locked vault brings up BlindDrop's
  unlock prompt. `blinddrop agent` waits up to 20 seconds for the owner to
  unlock, then completes the call or returns `VAULT_LOCKED`. Nothing is sent
  to the service while the vault is locked.
- **App not running.** The app-managed command starts BlindDrop in the
  background and waits up to 8 seconds for its endpoint. A manual install
  reports that BlindDrop is not running.
- **Agent access off.** With **Agent access** turned off in Settings →
  Sessions, calls report that agent access is turned off. Turning it off
  also replaces the session token, which ends the access of commands
  already running under `run --app`.

The endpoint uses a randomly chosen port saved in BlindDrop's settings. If it
is busy, the app uses the next free port and saves it. Settings → Sessions
changes it.

The session token is capability to use the owner's connections through
BlindDrop. It is never the archive passphrase and never a provider key. It
changes when every vault locks, when Agent access is turned off, and at
its 24-hour renewal.

### SDKs and command-line tools

`blinddrop run --app CONNECTION -- COMMAND` runs a command with
`BLINDDROP_BASE_URL`, the connection's base URL on BlindDrop's endpoint, and
`BLINDDROP_TOKEN`, the session token. `--base-url-env NAME` and
`--api-key-env NAME` add the names an SDK reads. It never asks for a
passphrase. A locked connection answers the command's request with HTTP 423
and `VAULT_LOCKED` and brings up the unlock prompt; the agent runs the command
again after the unlock. The app-managed skill gives agents the command for the
app's bundled runtime, so the CLI need not be on PATH.

Hosts that sandbox shell commands can block `run --app`. In Claude Code's
sandboxed Bash, a command cannot reach a loopback server outside the sandbox
by default, and the suggested `Read(~/.config/blinddrop/**)` deny rule below
also stops it from reading the session file. Such commands run outside the
sandbox through the host's own settings.

### Manual installation

With the `blinddrop` CLI on PATH, load the plugin for one Claude Code session
from a local checkout:

```sh
claude --plugin-dir /path/to/plugin
```

From the repository:

```sh
git clone https://github.com/IluvatarLabs/blinddrop
claude --plugin-dir ./blinddrop/plugin
```

The manual `.mcp.json` runs `blinddrop agent` from PATH and uses the session of
a running BlindDrop app.

## Add the deny rules

The hook covers tool calls. Permission rules cover the same paths one layer
lower, including `@`-references in a prompt, which no `PreToolUse` hook sees.
Paste this into `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.config/blinddrop/**)",
      "Edit(~/.config/blinddrop/**)"
    ]
  }
}
```

The block lives here rather than in the plugin because a plugin's own
`settings.json` supports only the `agent` and `subagentStatusLine` keys; a
plugin cannot ship permission rules.

The guard denies `Read`, `Edit` and `Write` of a path under
`~/.config/blinddrop/`, and a `Bash` command that names such a path, even when
the command only mentions it as text, such as `grep -rn .config/blinddrop src`.
It denies nothing else: `.env` templates, certificates and other project files
are ordinary work, and the skill tells agents never to read a credential.

## Codex, Cursor, and other hosts

The Mac app installs a native local Codex plugin containing the portable skill,
the guard hook and the same stdio MCP server definition. Codex starts
`blinddrop agent` as it does any plugin MCP server. The guard checks Claude
Code's Read/Edit/Write/Bash tools. Codex passes shell commands to it as Bash
but file edits as `apply_patch`, which it does not check; do not assume that
other hosts have identical tool hooks or guard coverage.

The skill uses only the six portable Agent Skills frontmatter fields, so the
same folder installs anywhere that reads the standard. Copy the directory
unchanged:

```sh
cp -R plugin/skills/blinddrop ~/.agents/skills/blinddrop     # Codex
cp -R plugin/skills/blinddrop .cursor/skills/blinddrop       # Cursor, per project
```

Codex also reads `.agents/skills/` in the project directory. Copying the skill
alone provides instructions, not an MCP connection. Another host that runs
local stdio MCP servers can add `blinddrop agent`: command `blinddrop`, argument
`agent`.

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
