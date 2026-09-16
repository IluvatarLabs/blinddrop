#!/usr/bin/env node
// SessionStart hook. Tells the session which BlindDrop connections are live, so
// a task that needs a credential goes to the vault instead of a key file.
// Prints connection names only: never the session token, never a secret value.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const path =
  process.env.BLINDDROP_SESSION_FILE ??
  join(homedir(), ".config", "blinddrop", "session.json");

let connections;
try {
  const session = JSON.parse(readFileSync(path, "utf8"));
  if (
    typeof session.expiresAt === "number" &&
    session.expiresAt > Date.now() &&
    session.connections !== null &&
    typeof session.connections === "object"
  ) {
    connections = Object.keys(session.connections);
  }
} catch {
  // No readable session file: report that no session is running.
}

const additionalContext =
  connections === undefined
    ? "BlindDrop is installed but no session is running, so no stored credential is reachable right now; if a task needs an API key or token, ask the owner to start a BlindDrop session instead of looking for the key on disk."
    : `BlindDrop has a running session. Authorized connections: ${connections.length === 0 ? "none" : connections.join(", ")}. Use the blinddrop tools list_connections and execute_http for any request to these APIs, or \`blinddrop run CONNECTION -- ...\` for an SDK or CLI. Never read a .env, .pem, .key or id_rsa file for a credential.`;

process.stdout.write(
  `${JSON.stringify({
    hookSpecificOutput: { hookEventName: "SessionStart", additionalContext }
  })}\n`
);
