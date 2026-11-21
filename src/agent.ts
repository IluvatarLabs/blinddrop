// `blinddrop agent`: the stdio MCP server an agent host launches, as
// 1Password's and 1Claw's integrations do. It answers the handshake and the
// tool list itself, from the runtime's own tool definitions, so a host's first
// connection never depends on the app. Each tool call goes to the running
// app's agent endpoint through the official MCP client, one client per call,
// and the app's result comes back unchanged. stdout carries only MCP; nothing
// it writes elsewhere carries a token or credential.

import { spawn } from "node:child_process";
import { connect } from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";

import {
  Client,
  SdkError,
  SdkErrorCode,
  SdkHttpError,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { DEFAULT_LIMITS } from "./broker.js";
import { BlindDropError, isErrorCode } from "./errors.js";
import { createToolServer, errorResult, MAX_MCP_MESSAGE_BYTES, type ToolName } from "./mcp.js";
import { readStoredSettings } from "./owner-files.js";
import { readSessionFile, type SessionFileContents } from "./session-file.js";
import { defaultVaultPath } from "./vault.js";

/** The unlock wait: the same call every second, up to 20 seconds after the first VAULT_LOCKED. */
const UNLOCK_WAIT_MS = 20_000;
const RETRY_MS = 1_000;
/** How long an app started by a call has to publish a session file whose listener accepts. */
const LAUNCH_WAIT_MS = 8_000;
const LAUNCH_POLL_MS = 100;
/**
 * Each request to the app settles within the app's own MCP request limit. A
 * tool call is answered as a stream without event ids, so a stream the app
 * ends early (its limit, a lock, Quit) would otherwise wait for the client's
 * 60-second default.
 */
const SEND_TIMEOUT_MS = DEFAULT_LIMITS.timeoutMs;
/** The bundled runtime's place inside an app bundle. */
const BUNDLED_CLI = join("Contents", "Resources", "app.asar", "node_modules", "blinddrop", "dist", "cli.js");

const ACCESS_OFF = "Agent access is turned off in BlindDrop.";
const NOT_STARTED = "BlindDrop's agent endpoint did not start within 8 seconds.";
const NOT_RUNNING = "BlindDrop is not running.";

/** Self-contained within its first 512 characters, which Codex treats as such. */
const CORE_INSTRUCTIONS = "BlindDrop uses the owner's credentials for you; you never see them. " +
  "Call list_connections first, then the tool each connection names, following its example. " +
  "Calling a locked connection (available: false) shows the owner BlindDrop's unlock and waits briefly; " +
  "on VAULT_LOCKED, do other work and retry later. " +
  "If BlindDrop cannot be reached or lacks a connection, use the project's own credential setup without reading values. " +
  "Never ask the owner to unlock, start a session, reload, reconnect or run a command.";

const OWNER_INSTRUCTIONS = "Ask the owner only for what only the owner can give: task inputs such as placeholder " +
  "values or Modal arguments, a credential or connection that has not been added, an OAuth sign-in in BlindDrop, " +
  "or a decision after an unknown outcome. You may tell the owner that BlindDrop is waiting for an unlock it " +
  "already raised, and that BlindDrop does not hand credentials to other programs, so handing one over is an " +
  "owner step.";

const RUN_INSTRUCTIONS = "For an SDK or CLI program, run it with the command below. COMMAND receives " +
  "BLINDDROP_BASE_URL, the connection's base URL on BlindDrop's local endpoint, and BLINDDROP_TOKEN, a BlindDrop " +
  "session token that is never a provider credential; add --base-url-env NAME or --api-key-env NAME to also set " +
  "the variables the program reads. If the program gets HTTP 423 VAULT_LOCKED, BlindDrop has asked the owner to " +
  "unlock: continue other work and run it again once list_connections shows the connection with available: true.";

function sessionPath(): string {
  return join(dirname(defaultVaultPath()), "session.json");
}

/**
 * The app bundle this command runs from: the runtime file is the bundle's
 * bundled cli.js, and the executable sits in the bundle's Contents/MacOS.
 */
export function appBundle(): string | undefined {
  const script = process.argv[1];
  if (script === undefined) return undefined;
  const runtime = resolve(script);
  if (!runtime.endsWith(`${sep}${BUNDLED_CLI}`)) return undefined;
  const bundle = runtime.slice(0, -BUNDLED_CLI.length - 1);
  return dirname(resolve(process.execPath)) === join(bundle, "Contents", "MacOS") ? bundle : undefined;
}

/** The exact `run --app` command for this runtime: the bundled one when it runs from an app. */
export function runAppCommand(): string {
  // The same POSIX quoting the app's staged SKILL.md line uses.
  const quote = (value: string): string => `'${value.replaceAll("'", `'"'"'`)}'`;
  return appBundle() === undefined
    ? "blinddrop run --app CONNECTION -- COMMAND"
    : `ELECTRON_RUN_AS_NODE=1 ${quote(process.execPath)} ${quote(resolve(process.argv[1]))} run --app CONNECTION -- COMMAND`;
}

/** The core rules first; the whole text stays far below Claude Code's 4,096-character limit. */
export function agentInstructions(): string {
  return [CORE_INSTRUCTIONS, "", OWNER_INSTRUCTIONS, "", RUN_INSTRUCTIONS, runAppCommand()].join("\n");
}

/** Only `sessionFile: false` turns agent access off; an unreadable file does not. */
function agentAccessOff(): boolean {
  try {
    return readStoredSettings(dirname(defaultVaultPath()))?.sessionFile === false;
  } catch {
    return false;
  }
}

/** The running app's session when its listener accepts; undefined otherwise. */
async function runningApp(): Promise<SessionFileContents | undefined> {
  const session = readSessionFile(sessionPath());
  return session !== undefined && await accepts(session.mcpUrl) ? session : undefined;
}

/** Whether the session's loopback listener accepts a connection. */
function accepts(mcpUrl: string): Promise<boolean> {
  const url = new URL(mcpUrl);
  return new Promise(resolveAccepts => {
    const socket = connect(Number(url.port), url.hostname);
    socket.once("connect", () => {
      socket.destroy();
      resolveAccepts(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolveAccepts(false);
    });
  });
}

/** LaunchServices starts one instance per bundle path, however many agents ask at once. */
function launch(bundle: string): void {
  const child = spawn("/usr/bin/open", ["-g", bundle], {
    // Only PATH and HOME: ELECTRON_RUN_AS_NODE and host variables never reach the app.
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? homedir() },
    stdio: "ignore",
  });
  child.once("error", () => undefined);
  child.unref();
}

export interface Reach {
  /** Set once the app was started; it then has until this time to accept. */
  deadline?: number;
}

/**
 * The session of a running app whose listener accepts. When BlindDrop is
 * unreachable (no session file, or its listener refuses), `settings.json`
 * decides: agent access is off, or the app starts once, from its own bundle
 * only, and gets eight seconds. Returns the error text when it cannot.
 */
export async function reachApp(reach: Reach, signal: AbortSignal): Promise<SessionFileContents | string> {
  for (;;) {
    signal.throwIfAborted();
    const session = await runningApp();
    if (session !== undefined) return session;
    if (reach.deadline === undefined) {
      if (agentAccessOff()) return ACCESS_OFF;
      const bundle = appBundle();
      if (bundle === undefined) return NOT_RUNNING;
      launch(bundle);
      reach.deadline = Date.now() + LAUNCH_WAIT_MS;
    } else if (Date.now() >= reach.deadline) {
      return NOT_STARTED;
    }
    await sleep(LAUNCH_POLL_MS, undefined, { signal });
  }
}

type Sent =
  | { kind: "result"; result: CallToolResult }
  /** The connection was refused: nothing was written. */
  | { kind: "refused" }
  /** 403 before anything else: the endpoint acted on nothing. */
  | { kind: "denied"; result: CallToolResult };

function textError(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function vaultLocked(result: CallToolResult): boolean {
  const content = result.structuredContent as { error?: { code?: unknown } } | undefined;
  return result.isError === true && content?.error?.code === "VAULT_LOCKED";
}

function refused(error: unknown): boolean {
  const cause = typeof error === "object" && error !== null ? (error as { cause?: unknown }).cause : undefined;
  return typeof cause === "object" && cause !== null && (cause as { code?: unknown }).code === "ECONNREFUSED";
}

/** The app's static JSON error reply as the app's MCP error result. */
function replyResult(error: SdkHttpError): CallToolResult {
  let code: unknown;
  try {
    const text = (error.data as { text?: unknown } | undefined)?.text;
    code = (JSON.parse(String(text)) as { error?: { code?: unknown } }).error?.code;
  } catch {
    code = undefined;
  }
  return errorResult(new BlindDropError(isErrorCode(code) ? code : "UPSTREAM_ERROR"));
}

/** One call on one official client, closed when the host cancels and when the call ends. */
async function send(
  session: SessionFileContents,
  name: ToolName,
  input: unknown,
  signal: AbortSignal,
): Promise<Sent> {
  const client = new Client({ name: "blinddrop-agent", version: "0.6.2" });
  const transport = new StreamableHTTPClientTransport(new URL(session.mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${session.token}` } },
  });
  // Closing aborts the in-flight request, which the endpoint treats as a disconnect.
  const close = (): void => { void client.close().catch(() => undefined); };
  signal.addEventListener("abort", close, { once: true });
  try {
    signal.throwIfAborted();
    await client.connect(transport, { timeout: SEND_TIMEOUT_MS });
    const result = await client.callTool(
      { name, arguments: input as Record<string, unknown> },
      { timeout: SEND_TIMEOUT_MS },
    );
    return { kind: "result", result: result as CallToolResult };
  } catch (error) {
    if (refused(error)) return { kind: "refused" };
    if (error instanceof SdkHttpError) {
      const result = replyResult(error);
      return error.status === 403 ? { kind: "denied", result } : { kind: "result", result };
    }
    if (error instanceof SdkError && error.code === SdkErrorCode.RequestTimeout) {
      // Closing the client below aborts the request; it is never sent again.
      return { kind: "result", result: errorResult(new BlindDropError("TIMEOUT")) };
    }
    // Written, then reset or cancelled: the outcome may be unknown.
    return { kind: "result", result: errorResult(new BlindDropError("UPSTREAM_ERROR")) };
  } finally {
    signal.removeEventListener("abort", close);
    await client.close().catch(() => undefined);
  }
}

/**
 * Forwards one tool call. A call is sent again only when the endpoint cannot
 * have acted on it: the connection failed before anything was written, a 403
 * came while the session file now holds another token, or VAULT_LOCKED came
 * within the unlock wait. Every other reply is the call's result. The app is
 * started only before the call first reaches it; once the app has answered,
 * a later connection failure returns that answer.
 */
async function forward(name: ToolName, input: unknown, signal: AbortSignal): Promise<CallToolResult> {
  const reach: Reach = {};
  let lockedSince: number | undefined;
  let last: CallToolResult | undefined;
  try {
    for (;;) {
      let session: SessionFileContents;
      if (last === undefined) {
        const reached = await reachApp(reach, signal);
        if (typeof reached === "string") return textError(reached);
        session = reached;
      } else {
        const running = await runningApp();
        if (running === undefined) return last;
        session = running;
      }
      const sent = await send(session, name, input, signal);
      if (signal.aborted) return errorResult(new BlindDropError("SESSION_CLOSED"));
      if (sent.kind === "refused") {
        if (last !== undefined) return last;
        await sleep(LAUNCH_POLL_MS, undefined, { signal });
        continue;
      }
      last = sent.result;
      if (sent.kind === "denied") {
        if (readSessionFile(sessionPath())?.token !== session.token) continue;
        return sent.result;
      }
      if (!vaultLocked(sent.result)) return sent.result;
      lockedSince ??= Date.now();
      const remaining = lockedSince + UNLOCK_WAIT_MS - Date.now();
      if (remaining <= 0) return sent.result;
      await sleep(Math.min(RETRY_MS, remaining), undefined, { signal });
    }
  } catch (error) {
    // The host's cancellation ends a wait at once.
    return errorResult(signal.aborted ? new BlindDropError("SESSION_CLOSED") : error);
  }
}

/** Serves until stdin ends; every failure is a tool result, never an exit. */
export async function serveAgent(): Promise<void> {
  const stopping = new AbortController();
  const server = createToolServer(
    (name, input, signal) => forward(name, input, AbortSignal.any([signal, stopping.signal])),
    agentInstructions(),
  );
  const transport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: MAX_MCP_MESSAGE_BYTES,
  });
  let finish!: () => void;
  const finished = new Promise<void>(resolveFinished => { finish = resolveFinished; });
  let shuttingDown = false;
  const shutdown = async (): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdin.off("end", onInputEnd);
    process.stdin.off("close", onInputEnd);
    stopping.abort();
    await server.close().catch(() => undefined);
    process.stdin.destroy();
    finish();
  };
  const onInputEnd = (): void => { void shutdown(); };
  process.stdin.once("end", onInputEnd);
  process.stdin.once("close", onInputEnd);
  server.server.onclose = () => { void shutdown(); };
  server.server.onerror = () => { process.stderr.write("MCP transport error.\n"); };
  await server.connect(transport);
  await finished;
}
