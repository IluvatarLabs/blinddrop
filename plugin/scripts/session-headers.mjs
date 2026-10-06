#!/usr/bin/env node
// MCP headersHelper. Prints the running BlindDrop session's Bearer header as a
// JSON object, or an empty object when no live session file is readable. The
// session token is capability to use the owner's allowed connections for the
// session's lifetime; it is never the passphrase or a provider credential.
// Stdout carries the JSON object and nothing else.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const path =
  process.env.BLINDDROP_SESSION_FILE ??
  join(homedir(), ".config", "blinddrop", "session.json");

let headers = {};
try {
  const session = JSON.parse(readFileSync(path, "utf8"));
  if (
    typeof session.token === "string" &&
    typeof session.expiresAt === "number" &&
    session.expiresAt > Date.now()
  ) {
    headers = { Authorization: `Bearer ${session.token}` };
  }
} catch {
  // No readable session file: connect without a credential and say so below.
}

process.stdout.write(`${JSON.stringify(headers)}\n`);
if (headers.Authorization === undefined) {
  process.stderr.write(
    "No active BlindDrop connection. Open BlindDrop and unlock the vault needed by this connection. For optional CLI use, run " +
      "`blinddrop serve --http --allow CONNECTION --session-file ~/.config/blinddrop/session.json` and set the manual host URL to the reported mcpUrl.\n"
  );
}
