import { isUtf8 } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";

import { Broker, DEFAULT_LIMITS, STREAM_LIMITS } from "./broker.js";
import { BlindDropError, publicError, type ErrorCode } from "./errors.js";
import {
  brokerTools,
  createToolServer,
  errorResult,
  MAX_MCP_MESSAGE_BYTES,
  toolResult,
  type ToolHandler
} from "./mcp.js";
import type { ConnectionMetadata } from "./types.js";

const DYNAMIC_PORT_MIN = 49_152;
const MAX_PORT = 65_535;

/** The one status mapping for every static error code both listeners return. */
const ERROR_STATUS: Record<ErrorCode, number> = {
  INVALID_INPUT: 400,
  VAULT_EXISTS: 409,
  VAULT_NOT_FOUND: 404,
  VAULT_INVALID: 502,
  UNLOCK_FAILED: 401,
  SECRET_NOT_FOUND: 404,
  SECRET_INVALID: 502,
  CONNECTION_NOT_FOUND: 404,
  ACCESS_DENIED: 403,
  UNSUPPORTED_OPERATION: 400,
  SESSION_EXPIRED: 410,
  SESSION_CLOSED: 410,
  VAULT_LOCKED: 423,
  DESTINATION_DENIED: 403,
  RESPONSE_BLOCKED: 502,
  RESPONSE_TOO_LARGE: 502,
  REQUEST_TOO_LARGE: 413,
  UNSUPPORTED_RESPONSE: 502,
  TIMEOUT: 504,
  UPSTREAM_ERROR: 502,
  BUSY: 429,
  PORT_UNAVAILABLE: 409,
  STORAGE_ERROR: 500,
  INPUT_UNAVAILABLE: 500,
  INTERNAL_ERROR: 502
};

export function errorStatus(code: ErrorCode): number {
  return ERROR_STATUS[code];
}

export interface HttpSession {
  token: string;
  mcpUrl: string;
  connections: Record<string, string>;
  expiresAt: number;
  closed: Promise<void>;
  close(): Promise<void>;
}

/**
 * What one agent request may use. A request keeps the access it arrived with
 * until it ends, whatever the listener authorizes afterwards.
 */
export interface AgentAccess {
  /** Serves the usable connections; absent while none is usable or nothing is served. */
  broker?: Broker;
  /** The connections the broker serves, which the SDK base-URL route accepts. */
  names: readonly string[];
  /** Each locked connection and the locked vaults it needs. */
  locked: ReadonlyMap<string, readonly string[]>;
  /** Credential-free listing items for the locked connections. */
  lockedItems: readonly ConnectionMetadata[];
  /** Every registered vault is locked: `list_connections` asks for the primary unlock. */
  primary: boolean;
  /**
   * Nothing is served: every tool call and SDK route answers this static error
   * and asks for nothing. `BUSY` while setup backup reads owner files; the
   * failure's code when access could not be computed.
   */
  unavailable?: ErrorCode;
  /** The token's and broker's expiry, which also bounds each request's timer. */
  expiresAt: number;
}

/** Records that an agent request asked for these locked vaults ([] for the primary unlock). */
export type UnlockAsk = (connection: string | null, vaults: readonly string[]) => void;

interface Admission {
  access: AgentAccess;
  /** The session token the request presented; it is also a reflection pattern. */
  token: string;
}

function values(request: IncomingMessage, name: string): string[] {
  const result: string[] = [];
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i].toLowerCase() === name) result.push(request.rawHeaders[i + 1]);
  }
  return result;
}

function authorize(request: IncomingMessage, authority: string, token: Buffer): void {
  const hosts = values(request, "host");
  const bearer = values(request, "authorization");
  const apiKey = values(request, "x-api-key");
  if (hosts.length !== 1 || hosts[0] !== authority || values(request, "origin").length !== 0 ||
      bearer.length + apiKey.length !== 1) {
    throw new BlindDropError("ACCESS_DENIED");
  }
  const supplied = bearer.length ? /^Bearer ([A-Za-z0-9_-]+)$/i.exec(bearer[0])?.[1] : apiKey[0];
  const bytes = Buffer.from(supplied ?? "", "utf8");
  if (bytes.length !== token.length || !timingSafeEqual(bytes, token)) {
    throw new BlindDropError("ACCESS_DENIED");
  }
  // These are local session credentials, never provider credentials.
  delete request.headers.authorization;
  delete request.headers["x-api-key"];
}

function readBody(request: IncomingMessage, limit: number, signal: AbortSignal): Promise<Buffer> {
  // Throwing from a Readable async iterator destroys the request/socket. Keep
  // the response alive long enough to return a static 413/504 instead.
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (error?: unknown) => {
      request.pause();
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onError);
      signal.removeEventListener("abort", onAbort);
      if (error !== undefined) reject(error);
      else resolve(Buffer.concat(chunks, size));
    };
    const onData = (value: Buffer) => {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      size += chunk.length;
      if (size > limit) finish(new BlindDropError("REQUEST_TOO_LARGE"));
      else chunks.push(chunk);
    };
    const onEnd = () => finish();
    const onError = () => finish(new BlindDropError("UPSTREAM_ERROR"));
    const onAbort = () => finish(signal.reason);
    if (signal.aborted) { onAbort(); return; }
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function sendError(response: ServerResponse, error: unknown): void {
  if (response.destroyed) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const safe = publicError(error);
  response.writeHead(errorStatus(safe.code), {
    "content-type": "application/json",
    "cache-control": "no-store",
    "connection": "close"
  });
  response.end(JSON.stringify({ error: safe }));
}

function writeChunk(response: ServerResponse, chunk: Buffer, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const onAbort = () => finish(new BlindDropError("SESSION_CLOSED"));
    const finish = (error?: Error | null) => {
      signal.removeEventListener("abort", onAbort);
      error ? reject(error) : resolve();
    };
    if (signal.aborted || response.destroyed) {
      finish(new BlindDropError("SESSION_CLOSED"));
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    response.write(chunk, finish);
  });
}

function systemErrorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

function nextPort(port: number, initial: number): number | undefined {
  if (initial < DYNAMIC_PORT_MIN) {
    return port < MAX_PORT ? port + 1 : undefined;
  }
  const next = port === MAX_PORT ? DYNAMIC_PORT_MIN : port + 1;
  return next === initial ? undefined : next;
}

function checkedPort(port: number): number {
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return port;
}

/** Each connection's SDK base URL on a listener origin. */
export function connectionUrls(origin: string, names: readonly string[]): Record<string, string> {
  return Object.fromEntries(names.map(name => [name, `${origin}/api/${encodeURIComponent(name)}/`]));
}

/** Tool calls under one request's access: locked connections ask, the broker serves the rest. */
function accessTools(access: AgentAccess, token: string, ask: UnlockAsk): ToolHandler {
  const served = access.broker === undefined ? undefined : brokerTools(access.broker, [token]);
  return async (name, input, signal) => {
    if (access.unavailable !== undefined) return errorResult(new BlindDropError(access.unavailable));
    if (name === "list_connections") {
      if (access.primary) {
        ask(null, []);
        return errorResult(new BlindDropError("VAULT_LOCKED"));
      }
      try {
        const usable = access.broker?.listConnections() ?? [];
        return toolResult({ connections: [...usable, ...access.lockedItems] });
      } catch (error) {
        return errorResult(error);
      }
    }
    const connection = (input as { connection: string }).connection;
    const vaults = access.locked.get(connection);
    if (vaults !== undefined) {
      ask(connection, vaults);
      return errorResult(new BlindDropError("VAULT_LOCKED"));
    }
    if (served === undefined) return errorResult(new BlindDropError("ACCESS_DENIED"));
    return served(name, input, signal);
  };
}

/**
 * The one agent request handler both listeners use. `admit` checks the caller
 * before anything else and returns the access the request keeps; `active`
 * holds every admitted request until it ends.
 */
function agentHandler(
  admit: (request: IncomingMessage) => Admission,
  active: Map<AbortController, AgentAccess>,
  ask: UnlockAsk,
  ended: (access: AgentAccess) => void
): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  return async (request, response) => {
    const { access, token } = admit(request);
    const target = request.url ?? "";
    if (!target.startsWith("/") || target.startsWith("//") || target.includes("#")) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const isMcp = target === "/mcp";
    const match = /^\/api\/([^/?#]+)([/?][^#]*)?$/.exec(target);
    let connection: string | undefined;
    let broker: Broker | undefined;
    let path = "/";
    if (!isMcp) {
      try { connection = match ? decodeURIComponent(match[1]) : undefined; }
      catch { throw new BlindDropError("INVALID_INPUT"); }
      if (connection === undefined) throw new BlindDropError("ACCESS_DENIED");
      if (access.unavailable !== undefined) throw new BlindDropError(access.unavailable);
      const vaults = access.locked.get(connection);
      if (vaults !== undefined) {
        // Nothing is dispatched: the request only asks for the unlock.
        ask(connection, vaults);
        throw new BlindDropError("VAULT_LOCKED");
      }
      broker = access.names.includes(connection) ? access.broker : undefined;
      if (broker === undefined) throw new BlindDropError("ACCESS_DENIED");
      path = match?.[2] ?? "/";
      if (path.startsWith("?")) path = `/${path}`;
    }
    if (active.size >= STREAM_LIMITS.concurrency) throw new BlindDropError("BUSY");
    const controller = new AbortController();
    active.set(controller, access);
    const duration = isMcp ? DEFAULT_LIMITS.timeoutMs : STREAM_LIMITS.timeoutMs;
    const timer = setTimeout(() => controller.abort(new BlindDropError("TIMEOUT")),
      Math.max(0, Math.min(Date.now() + duration, access.expiresAt) - Date.now()));
    const abortDelivery = () => {
      if (response.headersSent) { response.destroy(); request.destroy(); }
      else { request.pause(); sendError(response, controller.signal.reason); }
    };
    const onClose = () => controller.abort(new BlindDropError("SESSION_CLOSED"));
    controller.signal.addEventListener("abort", abortDelivery, { once: true });
    response.once("close", onClose);
    response.on("error", () => undefined);
    request.on("error", () => undefined);
    try {
      const body = await readBody(request, isMcp ? MAX_MCP_MESSAGE_BYTES : STREAM_LIMITS.requestBytes, controller.signal);
      if (controller.signal.aborted) throw controller.signal.reason;
      if (isMcp) {
        let parsed: unknown;
        if (request.method === "POST") {
          if (!isUtf8(body)) throw new BlindDropError("INVALID_INPUT");
          try { parsed = JSON.parse(body.toString("utf8")); }
          catch { throw new BlindDropError("INVALID_INPUT"); }
        }
        // A fresh stateless MCP server for this request, bound to its access.
        const mcp = createMcpHandler(() => createToolServer(accessTools(access, token, ask)));
        try {
          await toNodeHandler(mcp)(request, response, parsed);
        } finally {
          await mcp.close().catch(() => undefined);
        }
      } else {
        await broker!.executeStreaming({
          connection: connection!, method: request.method, path, headers: forwardedHeaders(request),
          ...(body.length ? { bodyBase64: body.toString("base64") } : {})
        }, {
          head(status, safeHeaders) {
            if (controller.signal.aborted) throw controller.signal.reason;
            response.writeHead(status, { ...safeHeaders, "cache-control": "no-store" });
          },
          write: chunk => writeChunk(response, chunk, controller.signal)
        }, { signal: controller.signal, extraPatterns: [token] });
        response.end();
      }
    } finally {
      clearTimeout(timer);
      active.delete(controller);
      controller.signal.removeEventListener("abort", abortDelivery);
      response.off("close", onClose);
      ended(access);
    }
  };
}

function forwardedHeaders(request: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(request.headers)) {
    if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

function agentServer(handle: (request: IncomingMessage, response: ServerResponse) => Promise<void>): Server {
  const server = createServer({
    maxHeaderSize: STREAM_LIMITS.headerBytes,
    requestTimeout: STREAM_LIMITS.timeoutMs,
    headersTimeout: DEFAULT_LIMITS.timeoutMs
  }, (request, response) => {
    void handle(request, response).catch(error => sendError(response, error));
  });
  // The ordinary Node parser rejects malformed framing. Never echo its diagnostics.
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("connect", (_request, socket) => socket.destroy());
  server.on("upgrade", (_request, socket) => socket.destroy());
  return server;
}

/** Binds 127.0.0.1 with the saved-port collision fallback; returns the bound port. */
async function listen(server: Server, port: number): Promise<number> {
  let candidate = port;
  while (true) {
    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(candidate, "127.0.0.1");
      });
      break;
    } catch (error) {
      const next = candidate === 0 || systemErrorCode(error) !== "EADDRINUSE"
        ? undefined
        : nextPort(candidate, port);
      if (next === undefined) throw new BlindDropError("PORT_UNAVAILABLE");
      candidate = next;
    }
  }
  const address = server.address();
  if (!address || typeof address === "string") throw new BlindDropError("INTERNAL_ERROR");
  return address.port;
}

function closeServer(server: Server): Promise<void> {
  const socketClosed = new Promise<void>(resolve => server.close(() => resolve()));
  server.closeAllConnections();
  return socketClosed;
}

/** One owner-unlocked, finite loopback session. No process-global lifecycle. */
export async function startHttpSession(
  broker: Broker,
  expiresAt: number,
  options: { port?: number } = {}
): Promise<HttpSession> {
  const port = checkedPort(options.port ?? 0);
  const names = broker.listConnections().map(connection => connection.name);
  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token, "utf8");
  const access: AgentAccess = {
    broker, names, locked: new Map(), lockedItems: [], primary: false, expiresAt
  };
  const active = new Map<AbortController, AgentAccess>();
  let authority = "";
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });
  let expiryTimer: NodeJS.Timeout | undefined;

  const server = agentServer(agentHandler(request => {
    if (stopped || Date.now() >= expiresAt) throw new BlindDropError("SESSION_EXPIRED");
    authorize(request, authority, tokenBytes);
    return { access, token };
  }, active, () => undefined, () => undefined));

  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    clearTimeout(expiryTimer);
    broker.close();
    tokenBytes.fill(0);
    for (const controller of active.keys()) controller.abort(new BlindDropError("SESSION_CLOSED"));
    closePromise = (async () => {
      await closeServer(server);
      finish();
    })();
    return closePromise;
  }

  let bound: number;
  try {
    bound = await listen(server, port);
  } catch (error) {
    await close();
    throw error;
  }
  server.on("error", () => { void close(); });
  authority = `127.0.0.1:${bound}`;
  const origin = `http://${authority}`;
  expiryTimer = setTimeout(() => { void close(); }, Math.max(0, expiresAt - Date.now()));
  return { token, mcpUrl: `${origin}/mcp`, connections: connectionUrls(origin, names), expiresAt, closed, close };
}

/** The owner runtime's agent listener: one for the runtime's lifetime. */
export interface AgentEndpoint {
  readonly port: number;
  readonly mcpUrl: string;
  readonly closed: Promise<void>;
  /** The connections' SDK base URLs on this listener. */
  urls(names: readonly string[]): Record<string, string>;
  /**
   * Replaces what the listener authorizes without closing it. With `drain`
   * (an unlock), requests running on the previous broker finish and it closes
   * after them; otherwise every broker closes at once, draining ones included.
   * Any token other than `token`, and `token` from `access.expiresAt` on, is
   * refused from now on.
   */
  update(token: string, access: AgentAccess, drain: boolean): void;
  close(): Promise<void>;
}

export async function startAgentEndpoint(
  port: number,
  token: string,
  access: AgentAccess,
  ask: UnlockAsk
): Promise<AgentEndpoint> {
  let current = access;
  let currentToken = token;
  let tokenBytes = Buffer.from(token, "utf8");
  const draining = new Set<AgentAccess>();
  const active = new Map<AbortController, AgentAccess>();
  let authority = "";
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });

  const holds = (held: AgentAccess): boolean => [...active.values()].includes(held);

  /** A draining broker closes once no request that holds it is running. */
  function ended(held: AgentAccess): void {
    if (draining.has(held) && !holds(held)) {
      draining.delete(held);
      held.broker?.close();
    }
  }

  /** Closes these brokers now and aborts the requests that hold them. */
  function closeBrokers(accesses: Iterable<AgentAccess>): void {
    const closing = new Set([...accesses].filter(held => held.broker !== undefined));
    for (const held of closing) {
      draining.delete(held);
      held.broker!.close();
    }
    for (const [controller, held] of active) {
      if (closing.has(held)) controller.abort(new BlindDropError("SESSION_CLOSED"));
    }
  }

  const server = agentServer(agentHandler(request => {
    if (stopped) throw new BlindDropError("SESSION_CLOSED");
    // A stale or expired token is refused here, before it can reach a tool or
    // an SDK route, even if renewal is late.
    if (Date.now() >= current.expiresAt) throw new BlindDropError("ACCESS_DENIED");
    authorize(request, authority, tokenBytes);
    return { access: current, token: currentToken };
  }, active, ask, ended));

  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    closeBrokers([current, ...draining]);
    tokenBytes.fill(0);
    for (const controller of active.keys()) controller.abort(new BlindDropError("SESSION_CLOSED"));
    closePromise = (async () => {
      await closeServer(server);
      finish();
    })();
    return closePromise;
  }

  let bound: number;
  try {
    bound = await listen(server, checkedPort(port));
  } catch (error) {
    await close();
    throw error;
  }
  server.on("error", () => { void close(); });
  authority = `127.0.0.1:${bound}`;
  const origin = `http://${authority}`;

  return {
    port: bound,
    mcpUrl: `${origin}/mcp`,
    closed,
    urls: names => connectionUrls(origin, names),
    update(nextToken, next, drain) {
      if (stopped) {
        next.broker?.close();
        return;
      }
      const previous = current;
      current = next;
      if (nextToken !== currentToken) {
        tokenBytes.fill(0);
        currentToken = nextToken;
        tokenBytes = Buffer.from(nextToken, "utf8");
      }
      if (previous === next) return;
      if (!drain) {
        closeBrokers([previous, ...draining]);
      } else if (previous.broker !== undefined) {
        draining.add(previous);
        ended(previous);
      }
    },
    close
  };
}
