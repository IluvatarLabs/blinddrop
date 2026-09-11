import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  openSync,
  writeSync,
} from "node:fs";
import { validateHeaderName, validateHeaderValue } from "node:http";
import { TextDecoder } from "node:util";

import { AuthSession } from "./auth.js";
import { BlindDropError, type ErrorCode } from "./errors.js";
import { connectionSecretNames } from "./references.js";
import { awaitAbortable, streamFilteredResponse } from "./stream.js";
import { sendHttps, sendHttpsStreaming } from "./transport.js";
import type {
  ClientTls,
  Connection,
  ConnectionMetadata,
  ExecuteOptions,
  Grant,
  HttpResult,
  Limits,
  PersistSecret,
  PreparedRequest,
  RequestInput,
  Secret,
  StreamingOptions,
  StreamingSink,
  TransportResponse,
  VaultData,
} from "./types.js";
import { validateConnection } from "./vault.js";

export const DEFAULT_LIMITS: Limits = Object.freeze({
  requestBytes: 1024 * 1024,
  responseBytes: 4 * 1024 * 1024,
  headerBytes: 16 * 1024,
  timeoutMs: 30_000,
  concurrency: 4,
});

export const STREAM_LIMITS: Limits = Object.freeze({
  requestBytes: 16 * 1024 * 1024,
  responseBytes: 64 * 1024 * 1024,
  headerBytes: 16 * 1024,
  timeoutMs: 600_000,
  concurrency: 4,
});

const ALLOWED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

// Adapted from Agent Vault's canonical hop-by-hop filtering and injected-field
// precedence in internal/brokercore/brokercore.go at
// bd1a325d79129644487f3e5b4f18c51adbc64638.
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const FORBIDDEN_REQUEST_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  "host",
  "content-length",
  "expect",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  "set-cookie",
  "content-encoding",
  "content-length",
  "alt-svc",
  "strict-transport-security",
  "public-key-pins",
  "public-key-pins-report-only",
]);

const MAX_MULTIPART_NAME_BYTES = 256;
const MAX_MULTIPART_FILENAME_BYTES = 1024;
const MAX_MULTIPART_CONTENT_TYPE_BYTES = 256;

interface ActiveRequest {
  controller: AbortController;
}

interface UseEvent {
  timestamp: string;
  grantId: string;
  connection: string | null;
  outcome: "success" | "denied" | "blocked" | "failed";
  code: ErrorCode | null;
}

interface EncodedBody {
  body?: Buffer;
  contentType?: string;
}

interface PreparedOperation {
  request: PreparedRequest;
  tls?: ClientTls;
  patterns: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function cloneVault(vault: VaultData): VaultData {
  let cloned: VaultData;
  try {
    cloned = structuredClone(vault);
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  if (
    !cloned ||
    cloned.version !== 1 ||
    typeof cloned.createdAt !== "string" ||
    typeof cloned.updatedAt !== "string" ||
    !isRecord(cloned.secrets) ||
    !isRecord(cloned.connections)
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }

  const secrets = Object.create(null) as Record<string, Secret>;
  for (const [name, secret] of Object.entries(cloned.secrets)) {
    if (
      !isRecord(secret) ||
      Object.keys(secret).length !== 2 ||
      typeof secret.value !== "string" ||
      secret.value.length === 0 ||
      typeof secret.enabled !== "boolean"
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
    secrets[name] = { value: secret.value, enabled: secret.enabled };
  }

  const connections = Object.create(null) as Record<string, Connection>;
  for (const [name, connection] of Object.entries(cloned.connections)) {
    connections[name] = validateConnection(connection);
  }
  return {
    version: 1,
    createdAt: cloned.createdAt,
    updatedAt: cloned.updatedAt,
    secrets,
    connections,
  };
}

function mergeLimits(
  defaults: Limits,
  overrides: Partial<Limits> | undefined,
): Limits {
  const limits = { ...defaults, ...overrides };
  for (const value of Object.values(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new BlindDropError("INVALID_INPUT");
    }
  }
  return limits;
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function hasControls(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return Boolean(
    isRecord(value) &&
    Object.entries(value).every(
      ([key, entry]) => key.length > 0 && typeof entry === "string",
    ),
  );
}

function responseContains(
  patterns: readonly string[],
  values: readonly string[],
): boolean {
  return patterns.some(
    (pattern) => pattern.length > 0 && values.some((value) => value.includes(pattern)),
  );
}

function bufferContains(patterns: readonly string[], value: Buffer): boolean {
  return patterns.some((pattern) =>
    pattern.length > 0 && value.includes(Buffer.from(pattern, "utf8")),
  );
}

function errorOutcome(code: ErrorCode): UseEvent["outcome"] {
  if (code === "RESPONSE_BLOCKED") {
    return "blocked";
  }
  if (
    code === "ACCESS_DENIED" ||
    code === "SESSION_EXPIRED" ||
    code === "SESSION_CLOSED" ||
    code === "CONNECTION_NOT_FOUND" ||
    code === "SECRET_NOT_FOUND" ||
    code === "DESTINATION_DENIED" ||
    code === "INVALID_INPUT" ||
    code === "BUSY"
  ) {
    return "denied";
  }
  return "failed";
}

function strictBase64(value: string): Buffer {
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    decoded.fill(0);
    throw new BlindDropError("INVALID_INPUT");
  }
  return decoded;
}

function assertMultipartMetadata(value: string, maximumBytes: number): void {
  if (
    value.length === 0 ||
    byteLength(value) > maximumBytes ||
    hasControls(value)
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function withoutSetCookie(rawFields: readonly string[]): string[] {
  const result: string[] = [];
  for (let index = 0; index < rawFields.length; index += 2) {
    const name = rawFields[index];
    const value = rawFields[index + 1];
    if (
      name === undefined ||
      value === undefined ||
      name.toLowerCase() === "set-cookie"
    ) {
      continue;
    }
    result.push(name, value);
  }
  return result;
}

export class Broker {
  private vault: VaultData | null;
  private grant: Grant | null;
  private readonly limits: Limits;
  private readonly streamLimits: Limits;
  private readonly active = new Set<ActiveRequest>();
  private readonly grantId: string;
  private readonly auth: AuthSession;
  private logFd: number | null;
  private closed = false;

  constructor(
    vault: VaultData,
    grant: Grant,
    options: {
      logPath: string;
      limits?: Partial<Limits>;
      streamLimits?: Partial<Limits>;
      persistSecret?: PersistSecret;
    },
  ) {
    let descriptor: number | undefined;
    try {
      const snapshot = cloneVault(vault);
      this.vault = snapshot;
      this.grant = {
        id: grant.id,
        connections: [...grant.connections],
        expiresAt: grant.expiresAt,
      };
      this.grantId = grant.id;
      this.limits = mergeLimits(DEFAULT_LIMITS, options.limits);
      this.streamLimits = mergeLimits(STREAM_LIMITS, options.streamLimits);
      this.auth = new AuthSession(snapshot, {
        persistSecret: options.persistSecret,
      });
      if (!options.logPath || hasControls(options.logPath)) {
        throw new BlindDropError("INVALID_INPUT");
      }
      descriptor = openSync(
        options.logPath,
        fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY,
        0o600,
      );
      fchmodSync(descriptor, 0o600);
      this.logFd = descriptor;
    } catch (error) {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          // Preserve the fixed startup error below.
        }
      }
      if (error instanceof BlindDropError) {
        throw error;
      }
      throw new BlindDropError("STORAGE_ERROR");
    }
  }

  listConnections(): ConnectionMetadata[] {
    this.assertSession();
    const vault = this.requireVault();
    const grant = this.requireGrant();
    return grant.connections.flatMap((name) => {
      const connection = Object.hasOwn(vault.connections, name)
        ? vault.connections[name]
        : undefined;
      if (
        !connection?.enabled ||
        !this.connectionSecretsEnabled(connection, vault.secrets)
      ) {
        return [];
      }
      return [{ name, origin: connection.origin, authType: connection.auth.type }];
    });
  }

  async execute(
    input: RequestInput,
    options: ExecuteOptions = {},
  ): Promise<HttpResult> {
    const extraPatterns = this.normalizeExtraPatterns(options.extraPatterns);
    return this.executeOperation(
      input,
      this.limits,
      options.signal,
      (connection, active) => this.executeActive(
        input,
        connection,
        active,
        this.limits,
        extraPatterns,
      ),
    );
  }

  async executeStreaming(
    input: RequestInput,
    sink: StreamingSink,
    options: StreamingOptions = {},
  ): Promise<void> {
    const extraPatterns = this.normalizeExtraPatterns(options.extraPatterns);
    return this.executeOperation(
      input,
      this.streamLimits,
      options.signal,
      (connection, active) => this.executeStreamingActive(
        input,
        connection,
        active,
        sink,
        extraPatterns,
      ),
    );
  }

  private async executeOperation<T>(
    input: RequestInput,
    limits: Limits,
    externalSignal: AbortSignal | undefined,
    operation: (
      connection: Connection,
      active: ActiveRequest,
    ) => Promise<T>,
  ): Promise<T> {
    const knownConnection = this.knownConnectionName(input?.connection);
    try {
      this.assertSession();
      this.validateInputShape(input);
      const connection = this.authorizedConnection(input.connection);
      if (this.active.size >= limits.concurrency) {
        throw new BlindDropError("BUSY");
      }

      const active: ActiveRequest = { controller: new AbortController() };
      this.active.add(active);
      const onExternalAbort = (): void => {
        active.controller.abort(
          externalSignal?.reason instanceof BlindDropError
            ? externalSignal.reason
            : new BlindDropError("SESSION_CLOSED"),
        );
      };
      if (externalSignal?.aborted) {
        onExternalAbort();
      } else {
        externalSignal?.addEventListener("abort", onExternalAbort, { once: true });
      }
      const grantExpiry = this.requireGrant().expiresAt;
      const timeoutAt = Date.now() + limits.timeoutMs;
      const deadline = Math.min(grantExpiry, timeoutAt);
      const timer = setTimeout(() => {
        const code = deadline === grantExpiry ? "SESSION_EXPIRED" : "TIMEOUT";
        active.controller.abort(new BlindDropError(code));
      }, Math.max(0, deadline - Date.now()));
      timer.unref();

      try {
        const result = await operation(connection, active);
        this.writeUseEvent(knownConnection, "success", null);
        return result;
      } finally {
        clearTimeout(timer);
        externalSignal?.removeEventListener("abort", onExternalAbort);
        this.active.delete(active);
      }
    } catch (error) {
      const safe = error instanceof BlindDropError
        ? error
        : new BlindDropError("INTERNAL_ERROR");
      this.writeUseEvent(knownConnection, errorOutcome(safe.code), safe.code);
      throw safe;
    }
  }

  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const active of this.active) {
      active.controller.abort(new BlindDropError("SESSION_CLOSED"));
    }
    this.active.clear();
    this.auth.close();

    if (this.vault) {
      for (const secret of Object.values(this.vault.secrets)) {
        secret.value = "";
        secret.enabled = false;
      }
    }
    this.vault = null;
    this.grant = null;

    if (this.logFd !== null) {
      try {
        closeSync(this.logFd);
      } catch {
        // close() is best-effort cleanup and must not expose a raw filesystem error.
      }
      this.logFd = null;
    }
  }

  private async executeActive(
    input: RequestInput,
    connection: Connection,
    active: ActiveRequest,
    limits: Limits,
    extraPatterns: readonly string[],
  ): Promise<HttpResult> {
    const prepared = await this.prepareActive(
      input,
      connection,
      active,
      limits,
      extraPatterns,
    );

    const response = await sendHttps({
      ...prepared.request,
      allowPrivate: connection.allowPrivate,
      tls: prepared.tls,
      signal: active.controller.signal,
      limits,
    });
    try {
      this.assertActive(active);
      this.assertSession();
      this.authorizedConnection(input.connection);
      this.assertSafeResponse(response, prepared.patterns);
      return this.releaseResponse(response, input.responseEncoding ?? "utf8");
    } finally {
      response.body.fill(0);
    }
  }

  private async executeStreamingActive(
    input: RequestInput,
    connection: Connection,
    active: ActiveRequest,
    sink: StreamingSink,
    extraPatterns: readonly string[],
  ): Promise<void> {
    const prepared = await this.prepareActive(
      input,
      connection,
      active,
      this.streamLimits,
      extraPatterns,
    );
    await sendHttpsStreaming(
      {
        ...prepared.request,
        allowPrivate: connection.allowPrivate,
        tls: prepared.tls,
        signal: active.controller.signal,
        limits: this.streamLimits,
      },
      async (response) => {
        this.assertActive(active);
        this.assertSession();
        this.authorizedConnection(input.connection);
        if (response.status >= 300 && response.status < 400) {
          throw new BlindDropError("DESTINATION_DENIED");
        }
        this.assertSafeResponseHead(
          response.statusText,
          response.rawHeaders,
          prepared.patterns,
        );
        await awaitAbortable(
          () => sink.head(
            response.status,
            this.safeResponseHeaders(response.rawHeaders),
          ),
          active.controller.signal,
        );
        await streamFilteredResponse(
          response.body,
          sink,
          prepared.patterns,
          active.controller.signal,
        );
      },
    );
    this.assertActive(active);
    this.assertSession();
    this.authorizedConnection(input.connection);
  }

  private async prepareActive(
    input: RequestInput,
    connection: Connection,
    active: ActiveRequest,
    limits: Limits,
    extraPatterns: readonly string[],
  ): Promise<PreparedOperation> {
    const origin = this.parseOrigin(connection.origin);
    const target = this.buildTarget(origin, input);
    const encoded = await this.encodeBody(input);
    const headers = this.buildHeaders(input.headers ?? {});
    if (encoded.contentType !== undefined) {
      headers["content-type"] = encoded.contentType;
    }
    const initial: PreparedRequest = {
      url: target,
      method: (input.method ?? "GET").toUpperCase(),
      headers,
      body: encoded.body,
    };

    this.assertNoExtraPatterns(initial, extraPatterns);

    this.assertActive(active);
    this.assertSession();
    this.authorizedConnection(input.connection);
    const prepared = await this.auth.prepare(
      input.connection,
      connection,
      initial,
      sendHttps,
      active.controller.signal,
      limits,
    );

    this.assertActive(active);
    this.assertSession();
    this.authorizedConnection(input.connection);
    if (
      prepared.request.url.origin !== origin.origin ||
      prepared.request.url.protocol !== "https:"
    ) {
      throw new BlindDropError("DESTINATION_DENIED");
    }
    this.ensureFinalContentLength(prepared.request);

    return {
      request: prepared.request,
      tls: prepared.tls,
      patterns: [...new Set([...prepared.patterns, ...extraPatterns])],
    };
  }

  private async encodeBody(input: RequestInput): Promise<EncodedBody> {
    if (input.body !== undefined) {
      return { body: Buffer.from(input.body, "utf8") };
    }
    if (input.bodyBase64 !== undefined) {
      return { body: strictBase64(input.bodyBase64) };
    }
    if (input.multipart === undefined) {
      return {};
    }

    const form = new FormData();
    for (const [name, value] of Object.entries(input.multipart.fields ?? {})) {
      assertMultipartMetadata(name, MAX_MULTIPART_NAME_BYTES);
      form.append(name, value);
    }
    for (const file of input.multipart.files) {
      assertMultipartMetadata(file.name, MAX_MULTIPART_NAME_BYTES);
      assertMultipartMetadata(file.filename, MAX_MULTIPART_FILENAME_BYTES);
      if (file.contentType !== undefined) {
        assertMultipartMetadata(
          file.contentType,
          MAX_MULTIPART_CONTENT_TYPE_BYTES,
        );
      }
      const data = strictBase64(file.dataBase64);
      try {
        form.append(
          file.name,
          new Blob(
            [new Uint8Array(data)],
            file.contentType === undefined ? undefined : { type: file.contentType },
          ),
          file.filename,
        );
      } finally {
        data.fill(0);
      }
    }

    const encoded = new Request("https://multipart.invalid/", {
      method: "POST",
      body: form,
    });
    const contentType = encoded.headers.get("content-type");
    if (contentType === null) {
      throw new BlindDropError("INTERNAL_ERROR");
    }
    return {
      body: Buffer.from(await encoded.arrayBuffer()),
      contentType,
    };
  }

  private assertSafeResponse(
    response: TransportResponse,
    patterns: readonly string[],
  ): void {
    const fields = [
      response.statusText,
      ...withoutSetCookie(response.rawHeaders),
      ...withoutSetCookie(response.rawTrailers),
    ];
    if (
      responseContains(patterns, fields) ||
      bufferContains(patterns, response.body)
    ) {
      throw new BlindDropError("RESPONSE_BLOCKED");
    }
  }

  private assertSafeResponseHead(
    statusText: string,
    rawHeaders: readonly string[],
    patterns: readonly string[],
  ): void {
    if (responseContains(
      patterns,
      [statusText, ...withoutSetCookie(rawHeaders)],
    )) {
      throw new BlindDropError("RESPONSE_BLOCKED");
    }
  }

  private normalizeExtraPatterns(
    patterns: readonly string[] | undefined,
  ): string[] {
    if (patterns === undefined) {
      return [];
    }
    if (!Array.isArray(patterns) || patterns.some(
      (pattern) => typeof pattern !== "string",
    )) {
      throw new BlindDropError("INVALID_INPUT");
    }
    return [...new Set(patterns.filter((pattern) => pattern.length > 0))];
  }

  private assertNoExtraPatterns(
    request: PreparedRequest,
    patterns: readonly string[],
  ): void {
    if (patterns.length === 0) {
      return;
    }
    let decodedPath = request.url.pathname;
    try {
      decodedPath = decodeURIComponent(decodedPath);
    } catch {
      // buildTarget already accepted the URL; the encoded path is still checked.
    }
    const fields = [
      request.url.href,
      request.url.pathname,
      decodedPath,
      ...Array.from(request.url.searchParams.entries()).flatMap(
        ([name, value]) => [name, value],
      ),
      ...Object.entries(request.headers).flatMap(([name, value]) => [name, value]),
    ];
    if (
      responseContains(patterns, fields) ||
      (request.body !== undefined && bufferContains(patterns, request.body))
    ) {
      request.body?.fill(0);
      throw new BlindDropError("ACCESS_DENIED");
    }
  }

  private releaseResponse(
    response: TransportResponse,
    encoding: "utf8" | "base64",
  ): HttpResult {
    if (encoding === "base64") {
      return {
        status: response.status,
        headers: this.safeResponseHeaders(response.rawHeaders),
        body: response.body.toString("base64"),
        bodyEncoding: "base64",
      };
    }
    let body: string;
    try {
      body = new TextDecoder("utf-8", { fatal: true }).decode(response.body);
    } catch {
      throw new BlindDropError("UNSUPPORTED_RESPONSE");
    }
    return {
      status: response.status,
      headers: this.safeResponseHeaders(response.rawHeaders),
      body,
    };
  }

  private assertActive(active: ActiveRequest): void {
    if (!active.controller.signal.aborted) {
      return;
    }
    throw active.controller.signal.reason instanceof BlindDropError
      ? active.controller.signal.reason
      : new BlindDropError("SESSION_CLOSED");
  }

  private assertSession(): void {
    if (this.closed || !this.grant || !this.vault) {
      throw new BlindDropError("SESSION_CLOSED");
    }
    if (
      typeof this.grant.id !== "string" ||
      this.grant.id.length === 0 ||
      !Array.isArray(this.grant.connections) ||
      !this.grant.connections.every((name) => typeof name === "string") ||
      !Number.isSafeInteger(this.grant.expiresAt)
    ) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    if (Date.now() >= this.grant.expiresAt) {
      throw new BlindDropError("SESSION_EXPIRED");
    }
  }

  private validateInputShape(input: RequestInput): void {
    const allowedKeys = new Set([
      "connection",
      "method",
      "path",
      "query",
      "headers",
      "body",
      "bodyBase64",
      "multipart",
      "responseEncoding",
    ]);
    if (
      !isRecord(input) ||
      Object.keys(input).some((key) => !allowedKeys.has(key)) ||
      typeof input.connection !== "string" ||
      typeof input.path !== "string" ||
      (input.method !== undefined && typeof input.method !== "string") ||
      (input.body !== undefined && typeof input.body !== "string") ||
      (input.bodyBase64 !== undefined && typeof input.bodyBase64 !== "string") ||
      (input.headers !== undefined && !isStringRecord(input.headers)) ||
      (input.query !== undefined && !isStringRecord(input.query)) ||
      (input.responseEncoding !== undefined &&
        input.responseEncoding !== "utf8" &&
        input.responseEncoding !== "base64")
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
    if (
      [input.body, input.bodyBase64, input.multipart]
        .filter((value) => value !== undefined).length > 1
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
    if (input.multipart !== undefined) {
      this.validateMultipart(input.multipart);
    }
    const method = (input.method ?? "GET").toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      throw new BlindDropError("INVALID_INPUT");
    }
    if (
      !input.path.startsWith("/") ||
      input.path.startsWith("//") ||
      input.path.includes("\\") ||
      input.path.includes("#") ||
      hasControls(input.path)
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
  }

  private validateMultipart(value: RequestInput["multipart"]): void {
    if (
      !isRecord(value) ||
      Object.keys(value).some((key) => key !== "fields" && key !== "files") ||
      (value.fields !== undefined && !isStringRecord(value.fields)) ||
      !Array.isArray(value.files)
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const allowedFileKeys = new Set([
      "name",
      "filename",
      "contentType",
      "dataBase64",
    ]);
    for (const file of value.files) {
      if (
        !isRecord(file) ||
        Object.keys(file).some((key) => !allowedFileKeys.has(key)) ||
        typeof file.name !== "string" ||
        typeof file.filename !== "string" ||
        (file.contentType !== undefined && typeof file.contentType !== "string") ||
        typeof file.dataBase64 !== "string"
      ) {
        throw new BlindDropError("INVALID_INPUT");
      }
    }
  }

  private authorizedConnection(name: string): Connection {
    const grant = this.requireGrant();
    const vault = this.requireVault();
    if (!grant.connections.includes(name)) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    const connection = Object.hasOwn(vault.connections, name)
      ? vault.connections[name]
      : undefined;
    if (!connection?.enabled) {
      throw new BlindDropError("CONNECTION_NOT_FOUND");
    }
    return connection;
  }

  private parseOrigin(value: string): URL {
    try {
      const origin = new URL(value);
      if (
        origin.protocol !== "https:" ||
        origin.username ||
        origin.password ||
        origin.pathname !== "/" ||
        origin.search ||
        origin.hash
      ) {
        throw new BlindDropError("DESTINATION_DENIED");
      }
      return origin;
    } catch (error) {
      if (error instanceof BlindDropError) {
        throw error;
      }
      throw new BlindDropError("DESTINATION_DENIED");
    }
  }

  private buildTarget(origin: URL, input: RequestInput): URL {
    let target: URL;
    try {
      target = new URL(input.path, origin);
      for (const [name, value] of Object.entries(input.query ?? {})) {
        target.searchParams.set(name, value);
      }
    } catch {
      throw new BlindDropError("INVALID_INPUT");
    }
    if (target.origin !== origin.origin || target.protocol !== "https:") {
      throw new BlindDropError("DESTINATION_DENIED");
    }
    return target;
  }

  private buildHeaders(clientHeaders: Record<string, string>): Record<string, string> {
    const connectionNominated = new Set<string>();
    for (const [name, value] of Object.entries(clientHeaders)) {
      try {
        validateHeaderName(name);
        validateHeaderValue(name, value);
      } catch {
        throw new BlindDropError("INVALID_INPUT");
      }
      if (name.toLowerCase() === "connection") {
        for (const token of value.split(",")) {
          const normalized = token.trim().toLowerCase();
          if (normalized) {
            connectionNominated.add(normalized);
          }
        }
      }
    }

    const result = Object.create(null) as Record<string, string>;
    for (const [name, value] of Object.entries(clientHeaders)) {
      const normalized = name.toLowerCase();
      if (
        FORBIDDEN_REQUEST_HEADERS.has(normalized) ||
        connectionNominated.has(normalized)
      ) {
        continue;
      }
      result[normalized] = value;
    }
    return result;
  }

  private ensureFinalContentLength(request: PreparedRequest): void {
    if (request.body === undefined) {
      return;
    }
    const entries = Object.entries(request.headers).filter(
      ([name]) => name.toLowerCase() === "content-length",
    );
    const expected = String(request.body.length);
    if (entries.length === 0) {
      request.headers["content-length"] = expected;
      return;
    }
    if (entries.length !== 1 || entries[0]?.[1] !== expected) {
      throw new BlindDropError("INVALID_INPUT");
    }
  }

  private safeResponseHeaders(rawHeaders: readonly string[]): Record<string, string> {
    const safe = Object.create(null) as Record<string, string>;
    for (let index = 0; index < rawHeaders.length; index += 2) {
      const name = rawHeaders[index]?.toLowerCase();
      const value = rawHeaders[index + 1];
      if (!name || value === undefined || STRIPPED_RESPONSE_HEADERS.has(name)) {
        continue;
      }
      safe[name] = Object.hasOwn(safe, name) ? `${safe[name]}, ${value}` : value;
    }
    return safe;
  }

  private connectionSecretsEnabled(
    connection: Connection,
    secrets: Record<string, Secret>,
  ): boolean {
    return connectionSecretNames(connection).every(
      (name) => Object.hasOwn(secrets, name) && Boolean(secrets[name]?.enabled),
    );
  }

  private knownConnectionName(inputName: unknown): string | null {
    if (typeof inputName !== "string" || !this.vault) {
      return null;
    }
    return Object.hasOwn(this.vault.connections, inputName) ? inputName : null;
  }

  private requireVault(): VaultData {
    if (!this.vault) {
      throw new BlindDropError("SESSION_CLOSED");
    }
    return this.vault;
  }

  private requireGrant(): Grant {
    if (!this.grant) {
      throw new BlindDropError("SESSION_CLOSED");
    }
    return this.grant;
  }

  private writeUseEvent(
    connection: string | null,
    outcome: UseEvent["outcome"],
    code: ErrorCode | null,
  ): void {
    if (this.logFd === null) {
      return;
    }
    const event: UseEvent = {
      timestamp: new Date().toISOString(),
      grantId: this.grantId,
      connection,
      outcome,
      code,
    };
    try {
      writeSync(this.logFd, `${JSON.stringify(event)}\n`, undefined, "utf8");
    } catch {
      try {
        process.stderr.write("BlindDrop warning: use-event log write failed.\n");
      } catch {
        // No further safe reporting channel is available.
      }
    }
  }
}
