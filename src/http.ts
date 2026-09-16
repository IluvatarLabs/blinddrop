import { isUtf8 } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";

import { Broker, DEFAULT_LIMITS, STREAM_LIMITS } from "./broker.js";
import { BlindDropError, publicError, type ErrorCode } from "./errors.js";
import { createMcpServer, MAX_MCP_MESSAGE_BYTES } from "./mcp.js";

/** The one status mapping for every static error code both listeners return. */
const ERROR_STATUS: Record<ErrorCode, number> = {
  INVALID_INPUT: 400,
  VAULT_EXISTS: 409,
  VAULT_NOT_FOUND: 404,
  VAULT_INVALID: 502,
  UNLOCK_FAILED: 401,
  SECRET_NOT_FOUND: 404,
  CONNECTION_NOT_FOUND: 404,
  ACCESS_DENIED: 403,
  SESSION_EXPIRED: 410,
  SESSION_CLOSED: 410,
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

/** One owner-unlocked, finite loopback session. No process-global lifecycle. */
export async function startHttpSession(
  broker: Broker,
  expiresAt: number,
  options: { port?: number } = {}
): Promise<HttpSession> {
  const port = options.port ?? 0;
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const names = broker.listConnections().map(connection => connection.name);
  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token, "utf8");
  const mcp = createMcpHandler(() => createMcpServer(broker, [token]));
  const handleMcp = toNodeHandler(mcp);
  const active = new Set<AbortController>();
  let authority = "";
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });
  let expiryTimer: NodeJS.Timeout | undefined;

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

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (stopped || Date.now() >= expiresAt) throw new BlindDropError("SESSION_EXPIRED");
    authorize(request, authority, tokenBytes);
    const target = request.url ?? "";
    if (!target.startsWith("/") || target.startsWith("//") || target.includes("#")) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const isMcp = target === "/mcp";
    const match = /^\/api\/([^/?#]+)([/?][^#]*)?$/.exec(target);
    let connection: string | undefined;
    let path = "/";
    if (!isMcp) {
      try { connection = match ? decodeURIComponent(match[1]) : undefined; }
      catch { throw new BlindDropError("INVALID_INPUT"); }
      if (connection === undefined || !names.includes(connection)) throw new BlindDropError("ACCESS_DENIED");
      path = match?.[2] ?? "/";
      if (path.startsWith("?")) path = `/${path}`;
    }
    if (active.size >= STREAM_LIMITS.concurrency) throw new BlindDropError("BUSY");
    const controller = new AbortController();
    active.add(controller);
    const duration = isMcp ? DEFAULT_LIMITS.timeoutMs : STREAM_LIMITS.timeoutMs;
    const timer = setTimeout(() => controller.abort(new BlindDropError("TIMEOUT")),
      Math.max(0, Math.min(Date.now() + duration, expiresAt) - Date.now()));
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
        await handleMcp(request, response, parsed);
      } else {
        const headers: Record<string, string> = Object.create(null);
        for (const [name, value] of Object.entries(request.headers)) {
          if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(", ") : value;
        }
        await broker.executeStreaming({
          connection: connection!, method: request.method, path, headers,
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
    }
  }

  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    clearTimeout(expiryTimer);
    broker.close();
    tokenBytes.fill(0);
    for (const controller of active) controller.abort(new BlindDropError("SESSION_CLOSED"));
    closePromise = (async () => {
      const socketClosed = new Promise<void>(resolve => server.close(() => resolve()));
      server.closeAllConnections();
      await Promise.all([socketClosed, mcp.close().catch(() => undefined)]);
      finish();
    })();
    return closePromise;
  }

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = () => reject(new BlindDropError("PORT_UNAVAILABLE"));
      server.once("error", onError);
      server.listen(port, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    });
  } catch (error) {
    await close();
    throw error;
  }
  server.on("error", () => { void close(); });
  const address = server.address();
  if (!address || typeof address === "string") {
    await close();
    throw new BlindDropError("INTERNAL_ERROR");
  }
  authority = `127.0.0.1:${address.port}`;
  const origin = `http://${authority}`;
  const connections = Object.fromEntries(names.map(name => [name, `${origin}/api/${encodeURIComponent(name)}/`]));
  expiryTimer = setTimeout(() => { void close(); }, Math.max(0, expiresAt - Date.now()));
  return { token, mcpUrl: `${origin}/mcp`, connections, expiresAt, closed, close };
}
