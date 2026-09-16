// The owner's own loopback server: one page and a small JSON API for the
// operations the owner performs by hand. It is a separate listener with a
// separate token from the agent session in http.ts, and the two never
// authorize each other. Terminal input and browser launching stay in the CLI
// so a desktop host can import this module directly.

import { isUtf8 } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, join } from "node:path";

import { z } from "zod";

import { BlindDropError, publicError } from "./errors.js";
import { errorStatus, startHttpSession, type HttpSession } from "./http.js";
import { deleteSessionFile, writeSessionFile } from "./session-file.js";
import { createBrokerSession } from "./session.js";
import {
  changePassphrase,
  disableConnection,
  disableSecret,
  importConnection,
  listMetadata,
  removeSecret,
  setConnection,
  setSecret
} from "./vault-admin.js";
import { createVault, loadVault } from "./vault.js";

const MAX_REQUEST_BYTES = 65_536;
const DEFAULT_SESSION_PORT = 8787;
const CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'unsafe-inline'; " +
  "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; form-action 'none'; " +
  "base-uri 'none'; frame-ancestors 'none'";
const BEARER = /^Bearer ([A-Za-z0-9_-]+)$/i;
const PAGE = readFileSync(new URL("../ui/index.html", import.meta.url));

const PassphraseBody = z.object({ passphrase: z.string() }).strict();
const EmptyBody = z.object({}).strict();
const NameBody = z.object({ name: z.string() }).strict();
const SecretSetBody = z.object({ name: z.string(), value: z.string() }).strict();
const ConnectionSetBody = z
  .object({
    name: z.string(),
    origin: z.string(),
    auth: z.string(),
    secret: z.string().optional(),
    usernameSecret: z.string().optional(),
    passwordSecret: z.string().optional(),
    field: z.string().optional(),
    allowPrivate: z.boolean().optional()
  })
  .strict();
const ConnectionImportBody = z.object({ name: z.string(), definition: z.unknown() }).strict();
const PasswdBody = z
  .object({ currentPassphrase: z.string(), newPassphrase: z.string() })
  .strict();
const SessionStartBody = z
  .object({
    allow: z.array(z.string()).min(1),
    ttl: z.number().int().min(1).max(86_400),
    port: z.number().int().min(0).max(65_535).optional(),
    sessionFile: z.boolean().optional()
  })
  .strict();

export interface OwnerUiOptions {
  vaultPath: string;
  port?: number;
  sessionPort?: number;
  sessionFile?: string;
}

export interface OwnerUi {
  url: string;
  token: string;
  launchUrl: string;
  closed: Promise<void>;
  close(): Promise<void>;
}

interface ActiveSession {
  http: HttpSession;
  filePath?: string;
}

function values(request: IncomingMessage, name: string): string[] {
  const result: string[] = [];
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i].toLowerCase() === name) result.push(request.rawHeaders[i + 1]);
  }
  return result;
}

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return parsed.data;
}

function boundedPort(port: number | undefined, fallback: number): number {
  const value = port ?? fallback;
  if (!Number.isSafeInteger(value) || value < 0 || value > 65_535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return value;
}

/**
 * Throwing from a Readable async iterator destroys the request/socket. Keep the
 * response alive long enough to return a static 400/413 instead.
 */
function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (error?: unknown) => {
      request.pause();
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onError);
      if (error !== undefined) reject(error);
      else resolve(Buffer.concat(chunks, size));
    };
    const onData = (value: Buffer) => {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) finish(new BlindDropError("REQUEST_TOO_LARGE"));
      else chunks.push(chunk);
    };
    const onEnd = () => finish();
    const onError = () => finish(new BlindDropError("INVALID_INPUT"));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onError);
  });
}

function send(response: ServerResponse, status: number, value: unknown): void {
  if (response.destroyed || response.headersSent) return;
  const body = Buffer.from(JSON.stringify(value), "utf8");
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": String(body.length)
  });
  response.end(body);
}

function sendError(response: ServerResponse, error: unknown): void {
  if (response.destroyed) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const safe = publicError(error);
  send(response, errorStatus(safe.code), { error: safe });
}

/** One owner-facing loopback server. No process-global lifecycle. */
export async function startOwnerUi(options: OwnerUiOptions): Promise<OwnerUi> {
  const vaultPath = options.vaultPath;
  if (typeof vaultPath !== "string" || vaultPath.length === 0 || vaultPath.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const port = boundedPort(options.port, 0);
  const sessionPort = boundedPort(options.sessionPort, DEFAULT_SESSION_PORT);
  const sessionFilePath = options.sessionFile ?? join(dirname(vaultPath), "session.json");

  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token, "utf8");
  let passphrase: Buffer | undefined;
  let active: ActiveSession | undefined;
  let startingSession = false;
  let authority = "";
  let pageOrigin = "";
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });

  function hold(value: string): void {
    passphrase?.fill(0);
    passphrase = Buffer.from(value, "utf8");
  }

  function release(): void {
    passphrase?.fill(0);
    passphrase = undefined;
  }

  function unlocked(): string {
    if (passphrase === undefined) throw new BlindDropError("ACCESS_DENIED");
    return passphrase.toString("utf8");
  }

  function forget(entry: ActiveSession): void {
    if (active === entry) active = undefined;
    if (entry.filePath !== undefined) {
      const path = entry.filePath;
      entry.filePath = undefined;
      try {
        deleteSessionFile(path);
      } catch {
        // Best effort: a stale file carries a dead token that readers reject on expiry.
      }
    }
  }

  async function stopSession(): Promise<void> {
    const entry = active;
    if (entry === undefined) return;
    await entry.http.close();
    forget(entry);
  }

  function verify(supplied: string): void {
    const bytes = Buffer.from(supplied, "utf8");
    if (bytes.length !== tokenBytes.length || !timingSafeEqual(bytes, tokenBytes)) {
      throw new BlindDropError("ACCESS_DENIED");
    }
  }

  async function startSession(body: unknown): Promise<unknown> {
    const input = parse(SessionStartBody, body);
    const held = unlocked();
    if (active !== undefined || startingSession) throw new BlindDropError("BUSY");
    startingSession = true;
    try {
      const session = createBrokerSession(vaultPath, held, input.allow, input.ttl);
      let http: HttpSession;
      try {
        http = await startHttpSession(session.broker, session.expiresAt, {
          port: boundedPort(input.port, sessionPort)
        });
      } catch (error) {
        session.broker.close();
        throw error;
      }
      const entry: ActiveSession = { http };
      active = entry;
      void http.closed.then(() => forget(entry));
      if (input.sessionFile !== false) {
        try {
          writeSessionFile(sessionFilePath, {
            mcpUrl: http.mcpUrl,
            token: http.token,
            expiresAt: http.expiresAt,
            connections: http.connections
          });
        } catch (error) {
          await http.close();
          forget(entry);
          throw error;
        }
        entry.filePath = sessionFilePath;
      }
      return {
        mcpUrl: http.mcpUrl,
        connections: http.connections,
        token: http.token,
        expiresAt: http.expiresAt,
        sessionFile: entry.filePath ?? null
      };
    } finally {
      startingSession = false;
    }
  }

  const routes = new Map<string, {
    method: "GET" | "POST";
    handle: (body: unknown) => unknown | Promise<unknown>;
  }>([
    ["/api/state", {
      method: "GET",
      handle: () => ({
        vaultPath,
        vaultExists: existsSync(vaultPath),
        unlocked: passphrase !== undefined,
        sessionPort,
        session: active === undefined ? null : {
          mcpUrl: active.http.mcpUrl,
          connections: active.http.connections,
          expiresAt: active.http.expiresAt,
          sessionFile: active.filePath ?? null
        }
      })
    }],
    ["/api/init", {
      method: "POST",
      handle: body => {
        const input = parse(PassphraseBody, body);
        createVault(vaultPath, input.passphrase);
        hold(input.passphrase);
        return { ok: true };
      }
    }],
    ["/api/unlock", {
      method: "POST",
      handle: body => {
        const input = parse(PassphraseBody, body);
        loadVault(vaultPath, input.passphrase);
        hold(input.passphrase);
        return { ok: true };
      }
    }],
    ["/api/lock", {
      method: "POST",
      handle: async body => {
        parse(EmptyBody, body);
        await stopSession();
        release();
        return { ok: true };
      }
    }],
    ["/api/list", {
      method: "GET",
      handle: () => listMetadata(loadVault(vaultPath, unlocked()))
    }],
    ["/api/secret/set", {
      method: "POST",
      handle: body => {
        const input = parse(SecretSetBody, body);
        setSecret(vaultPath, unlocked(), input.name, input.value);
        return { ok: true };
      }
    }],
    ["/api/secret/disable", {
      method: "POST",
      handle: body => {
        const input = parse(NameBody, body);
        disableSecret(vaultPath, unlocked(), input.name);
        return { ok: true };
      }
    }],
    ["/api/secret/remove", {
      method: "POST",
      handle: body => {
        const input = parse(NameBody, body);
        removeSecret(vaultPath, unlocked(), input.name);
        return { ok: true };
      }
    }],
    ["/api/connection/set", {
      method: "POST",
      handle: body => {
        const { name, ...connection } = parse(ConnectionSetBody, body);
        setConnection(vaultPath, unlocked(), name, connection);
        return { ok: true };
      }
    }],
    ["/api/connection/import", {
      method: "POST",
      handle: body => {
        const input = parse(ConnectionImportBody, body);
        importConnection(vaultPath, unlocked(), input.name, input.definition);
        return { ok: true };
      }
    }],
    ["/api/connection/disable", {
      method: "POST",
      handle: body => {
        const input = parse(NameBody, body);
        disableConnection(vaultPath, unlocked(), input.name);
        return { ok: true };
      }
    }],
    ["/api/passwd", {
      method: "POST",
      handle: body => {
        const input = parse(PasswdBody, body);
        if (passphrase === undefined) throw new BlindDropError("ACCESS_DENIED");
        const supplied = Buffer.from(input.currentPassphrase, "utf8");
        try {
          if (supplied.length !== passphrase.length || !timingSafeEqual(supplied, passphrase)) {
            throw new BlindDropError("UNLOCK_FAILED");
          }
        } finally {
          supplied.fill(0);
        }
        changePassphrase(vaultPath, input.currentPassphrase, input.newPassphrase);
        hold(input.newPassphrase);
        return { ok: true };
      }
    }],
    ["/api/session/start", { method: "POST", handle: startSession }],
    ["/api/session/stop", {
      method: "POST",
      handle: async body => {
        parse(EmptyBody, body);
        await stopSession();
        return { ok: true };
      }
    }],
    ["/api/shutdown", {
      method: "POST",
      handle: body => {
        parse(EmptyBody, body);
        return { ok: true };
      }
    }]
  ]);

  const server = createServer((request, response) => {
    void handle(request, response).catch(error => sendError(response, error));
  });
  // The ordinary Node parser rejects malformed framing. Never echo its diagnostics.
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("connect", (_request, socket) => socket.destroy());
  server.on("upgrade", (_request, socket) => socket.destroy());

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (stopped) throw new BlindDropError("SESSION_CLOSED");
    response.on("error", () => undefined);
    request.on("error", () => undefined);

    const hosts = values(request, "host");
    if (hosts.length !== 1 || hosts[0] !== authority) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    const origins = values(request, "origin");
    if (origins.length > 1 || (origins.length === 1 && origins[0] !== pageOrigin)) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    const fetchSites = values(request, "sec-fetch-site");
    if (fetchSites.length > 1 ||
        (fetchSites.length === 1 && fetchSites[0] !== "same-origin" && fetchSites[0] !== "none")) {
      throw new BlindDropError("ACCESS_DENIED");
    }

    const target = request.url ?? "";
    if (!target.startsWith("/") || target.startsWith("//") || target.includes("#")) {
      throw new BlindDropError("INVALID_INPUT");
    }
    let url: URL;
    try {
      url = new URL(target, pageOrigin);
    } catch {
      throw new BlindDropError("INVALID_INPUT");
    }
    const path = url.pathname;

    const bearer = values(request, "authorization");
    const query = url.searchParams.getAll("t");
    if (path === "/") {
      if (bearer.length !== 0 || query.length !== 1) throw new BlindDropError("ACCESS_DENIED");
      verify(query[0]);
    } else {
      if (query.length !== 0 || bearer.length !== 1) throw new BlindDropError("ACCESS_DENIED");
      verify(BEARER.exec(bearer[0])?.[1] ?? "");
    }

    const route = path === "/" ? undefined : routes.get(path);
    const method = path === "/" ? "GET" : route?.method;
    if (method === undefined || method !== request.method) {
      throw new BlindDropError("INVALID_INPUT");
    }

    const raw = await readBody(request);
    let body: unknown;
    if (request.method === "POST") {
      const contentType = values(request, "content-type");
      if (contentType.length !== 1 || !contentType[0].startsWith("application/json")) {
        throw new BlindDropError("INVALID_INPUT");
      }
      if (!isUtf8(raw)) throw new BlindDropError("INVALID_INPUT");
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new BlindDropError("INVALID_INPUT");
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        throw new BlindDropError("INVALID_INPUT");
      }
    }

    if (route === undefined) {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy": CONTENT_SECURITY_POLICY,
        "content-length": String(PAGE.length)
      });
      response.end(PAGE);
      return;
    }

    if (path === "/api/shutdown") {
      response.once("close", () => { void close(); });
    }
    send(response, 200, await route.handle(body));
  }

  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    closePromise = (async () => {
      await stopSession();
      release();
      tokenBytes.fill(0);
      const socketClosed = new Promise<void>(resolve => server.close(() => resolve()));
      server.closeAllConnections();
      await socketClosed;
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
  pageOrigin = `http://${authority}`;
  return { url: `${pageOrigin}/`, token, launchUrl: `${pageOrigin}/?t=${token}`, closed, close };
}
