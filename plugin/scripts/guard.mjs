#!/usr/bin/env node
// PreToolUse guard. Reads the hook event from stdin and denies a Read, Edit or
// Write of a path under .config/blinddrop/, or a Bash command naming such a
// path, because BlindDrop owns those files. It steers the agent to BlindDrop's
// tools; it is guidance, not a security boundary. Any other event, and any
// input this cannot parse, exits 0 with no output: a guard must never block
// unrelated work by crashing.

const REASON =
  "BlindDrop owns this file; do not read or change it. To use a stored " +
  "credential, call BlindDrop's list_connections tool and the tool it names " +
  "for the connection.";

// Whitespace, shell operators, quotes and assignment separate a command into
// candidate paths. This is deliberately not a shell parser.
const SEPARATORS = /[\s|&;<>()"'`=]+/;

function ownFile(target) {
  return /(^|\/)\.config\/blinddrop(\/|$)/.test(target.replaceAll("\\", "/"));
}

function candidates(event) {
  const input = event.tool_input;
  if (input === null || typeof input !== "object") {
    return [];
  }
  if (event.tool_name === "Bash") {
    return typeof input.command === "string" ? input.command.split(SEPARATORS) : [];
  }
  if (["Read", "Edit", "Write"].includes(event.tool_name)) {
    return typeof input.file_path === "string" ? [input.file_path] : [];
  }
  return [];
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
  if (candidates(event).some(ownFile)) {
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
