#!/usr/bin/env node
// PreToolUse guard. Reads the hook event from stdin and denies a tool call that
// targets a credential file, naming the BlindDrop tool to use instead. Any other
// event, and any input this cannot parse, exits 0 with no output: a guard must
// never block unrelated work by crashing.

const REASON =
  "BlindDrop holds this credential. Use the blinddrop MCP tool execute_http with a " +
  "connection from list_connections, or run the command under " +
  "`blinddrop run CONNECTION -- ...`. Never read the key itself.";

// Whitespace, shell operators, quotes and assignment separate a command into
// candidate paths. This is deliberately not a shell parser.
const SEPARATORS = /[\s|&;<>()"'`=]+/;

function credentialFile(target) {
  const path = target.replaceAll("\\", "/");
  if (/(^|\/)\.config\/blinddrop(\/|$)/.test(path)) {
    return true;
  }
  const name = path.slice(path.lastIndexOf("/") + 1);
  return (
    name === ".env" ||
    name.startsWith(".env.") ||
    name.endsWith(".pem") ||
    name.endsWith(".key") ||
    name === "id_rsa" ||
    name === "id_ed25519"
  );
}

function candidates(event) {
  const input = event.tool_input;
  if (input === null || typeof input !== "object") {
    return [];
  }
  if (event.tool_name === "Bash") {
    return typeof input.command === "string" ? input.command.split(SEPARATORS) : [];
  }
  return typeof input.file_path === "string" ? [input.file_path] : [];
}

async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

try {
  const event = JSON.parse(await readAll(process.stdin));
  if (candidates(event).some(credentialFile)) {
    process.stdout.write(
      `${JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: REASON
        }
      })}\n`
    );
  }
} catch {
  // Unparsable input is not a reason to interrupt the session.
}
