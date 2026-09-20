import { importConnection } from "./vault-admin.js";
import {
  closeSync,
  fstatSync,
  openSync,
  readSync,
} from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import process from "node:process";
import { TextDecoder } from "node:util";

import * as oauth from "oauth4webapi";
import open from "open";

import { createOAuthTokenRequestOptions } from "./auth.js";
import { DEFAULT_LIMITS } from "./broker.js";
import { BlindDropError } from "./errors.js";
import {
  DEFAULT_FIELD_ID,
  DEFAULT_VAULT_NAME,
  parseSecretRef,
  resolveValue,
} from "./references.js";
import { sendHttps } from "./transport.js";
import type {
  ClientTls,
  Connection,
  Field,
  VaultData,
} from "./types.js";
import {
  loadVault,
  saveVault,
  validateConnection,
} from "./vault.js";

const MAX_DEFINITION_BYTES = 64 * 1024;
const MAX_ENDPOINT_BYTES = 2_048;
const MAX_AUTHORIZATION_PARAMETERS = 32;
const MAX_PARAMETER_NAME_BYTES = 128;
const MAX_PARAMETER_VALUE_BYTES = 4_096;
const MAX_AUTHORIZATION_URL_BYTES = 16 * 1024;
const MAX_CALLBACK_URL_BYTES = 8 * 1024;
const CALLBACK_PATH = "/oauth/callback";
const LOGIN_TIMEOUT_MS = 5 * 60 * 1_000;
const PARAMETER_NAME = /^[A-Za-z0-9._~-]+$/u;
const PROTECTED_AUTHORIZATION_PARAMETERS = new Set([
  "audience",
  "client_id",
  "code_challenge",
  "code_challenge_method",
  "redirect_uri",
  "resource",
  "request",
  "request_uri",
  "response_mode",
  "response_type",
  "scope",
  "state",
]);

export interface OAuthLoginDefinition {
  issuer: string;
  authorizationEndpoint: string;
  redirectPort: number;
  authorizationParameters: Record<string, string>;
  connection: Connection & {
    auth: Extract<Connection["auth"], { type: "oauth2" }> & {
      grant: "refresh_token";
      refreshSecret: string;
    };
  };
}

export interface OAuthLoginOptions {
  vaultPath: string;
  passphrase: string;
  name: string;
  definition: OAuthLoginDefinition;
  signal?: AbortSignal;
  visitAuthorizationUrl(url: string, signal: AbortSignal): Promise<void>;
}

interface CallbackListener {
  redirectUri: string;
  response: Promise<URL>;
  close(): Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasControls(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value);
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function fixedHttpsUrl(value: unknown, allowQuery: boolean): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    byteLength(value) > MAX_ENDPOINT_BYTES ||
    hasControls(value)
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    (!allowQuery && parsed.search !== "") ||
    parsed.origin === "null"
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
  // OAuth issuer identifiers use exact string comparison (RFC 9207).
  // In particular, adding a trailing slash can change the issuer identity.
  return value;
}

function authorizationParameters(value: unknown): Record<string, string> {
  if (value === undefined) {
    return Object.create(null) as Record<string, string>;
  }
  if (!isRecord(value)) {
    throw new BlindDropError("INVALID_INPUT");
  }

  const entries = Object.entries(value);
  if (entries.length > MAX_AUTHORIZATION_PARAMETERS) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const result = Object.create(null) as Record<string, string>;
  for (const [name, entry] of entries) {
    if (
      byteLength(name) === 0 ||
      byteLength(name) > MAX_PARAMETER_NAME_BYTES ||
      !PARAMETER_NAME.test(name) ||
      PROTECTED_AUTHORIZATION_PARAMETERS.has(name.toLowerCase()) ||
      typeof entry !== "string" ||
      byteLength(entry) > MAX_PARAMETER_VALUE_BYTES ||
      hasControls(entry)
    ) {
      throw new BlindDropError("INVALID_INPUT");
    }
    result[name] = entry;
  }
  return result;
}

function redirectPort(value: unknown): number {
  if (value === undefined || value === 0) {
    return 0;
  }
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65_535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return value as number;
}

function readDefinitionFile(path: string): unknown {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }

  let descriptor: number | undefined;
  let contents: Buffer;
  try {
    descriptor = openSync(path, "r");
    const size = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_DEFINITION_BYTES) {
      throw new BlindDropError("INVALID_INPUT");
    }
    contents = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const read = readSync(descriptor, contents, offset, size - offset, null);
      if (read === 0) {
        throw new BlindDropError("STORAGE_ERROR");
      }
      offset += read;
    }
    if (readSync(descriptor, Buffer.allocUnsafe(1), 0, 1, null) !== 0) {
      throw new BlindDropError("STORAGE_ERROR");
    }
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the fixed read or validation result.
      }
    }
  }

  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents));
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
}

export function readOAuthLoginDefinition(path: string): OAuthLoginDefinition {
  const input = readDefinitionFile(path);
  if (!isRecord(input)) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const allowed = new Set([
    "issuer",
    "authorizationEndpoint",
    "redirectPort",
    "authorizationParameters",
    "connection",
  ]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    throw new BlindDropError("INVALID_INPUT");
  }

  const issuer = fixedHttpsUrl(input.issuer, false);
  const endpoint = fixedHttpsUrl(input.authorizationEndpoint, false);
  const connection = validateConnection(input.connection);
  if (
    connection.auth.type !== "oauth2" ||
    connection.auth.grant !== "refresh_token" ||
    connection.auth.refreshSecret === undefined
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const overwrittenReferences = [
    connection.auth.clientSecret,
    connection.tls?.certificateSecret,
    connection.tls?.privateKeySecret,
    connection.tls?.passphraseSecret,
  ].filter((name): name is string => name !== undefined);
  if (overwrittenReferences.includes(connection.auth.refreshSecret)) {
    throw new BlindDropError("INVALID_INPUT");
  }

  return {
    issuer,
    authorizationEndpoint: endpoint,
    redirectPort: redirectPort(input.redirectPort),
    authorizationParameters: authorizationParameters(input.authorizationParameters),
    connection: connection as OAuthLoginDefinition["connection"],
  };
}

// OAuth login manages the default vault it unlocked; a reference must resolve
// to an enabled, nonempty field there.
function requireSecret(vault: VaultData, reference: string): string {
  const value = resolveValue(
    new Map([[DEFAULT_VAULT_NAME, vault]]),
    parseSecretRef(reference, DEFAULT_VAULT_NAME),
  );
  if (value === undefined) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  return value;
}

// Writes the rotated refresh token into its field, preserving any sibling
// fields of the same secret (for example a shared client_secret field).
function writeRefreshToken(vault: VaultData, reference: string, value: string): void {
  const ref = parseSecretRef(reference, DEFAULT_VAULT_NAME);
  if (ref.vault !== DEFAULT_VAULT_NAME) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const fieldId = ref.field ?? DEFAULT_FIELD_ID;
  const existing = Object.hasOwn(vault.secrets, ref.secret) ? vault.secrets[ref.secret] : undefined;
  const fields: Record<string, Field> = existing === undefined ? {} : { ...existing.fields };
  fields[fieldId] = { value, label: "Refresh token", masked: true, multiline: false };
  vault.secrets[ref.secret] = {
    type: existing?.type ?? "oauth",
    fields,
    enabled: true,
  };
}

function validateExistingReferences(vault: VaultData, connection: OAuthLoginDefinition["connection"]): void {
  const auth = connection.auth;
  if (auth.clientSecret !== undefined) {
    requireSecret(vault, auth.clientSecret);
  }
  if (connection.tls !== undefined) {
    requireSecret(vault, connection.tls.certificateSecret);
    requireSecret(vault, connection.tls.privateKeySecret);
    if (connection.tls.passphraseSecret !== undefined) {
      requireSecret(vault, connection.tls.passphraseSecret);
    }
  }
}

function clientTls(vault: VaultData, connection: OAuthLoginDefinition["connection"]): ClientTls | undefined {
  if (connection.tls === undefined) {
    return undefined;
  }
  return {
    cert: requireSecret(vault, connection.tls.certificateSecret),
    key: requireSecret(vault, connection.tls.privateKeySecret),
    ...(connection.tls.passphraseSecret === undefined
      ? {}
      : { passphrase: requireSecret(vault, connection.tls.passphraseSecret) }),
  };
}

function clientAuthentication(
  vault: VaultData,
  auth: OAuthLoginDefinition["connection"]["auth"],
): oauth.ClientAuth {
  switch (auth.clientAuth) {
    case "basic":
      if (auth.clientSecret === undefined) throw new BlindDropError("INVALID_INPUT");
      return oauth.ClientSecretBasic(requireSecret(vault, auth.clientSecret));
    case "body":
      if (auth.clientSecret === undefined) throw new BlindDropError("INVALID_INPUT");
      return oauth.ClientSecretPost(requireSecret(vault, auth.clientSecret));
    case "none":
      if (auth.clientSecret !== undefined) throw new BlindDropError("INVALID_INPUT");
      return oauth.None();
  }
}

function sendCallbackResponse(response: ServerResponse, status: number, body: string): void {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "text/plain; charset=utf-8",
    "content-length": String(Buffer.byteLength(body, "utf8")),
    connection: "close",
  });
  response.end(body);
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

function callbackError(signal: AbortSignal): BlindDropError {
  return signal.reason instanceof BlindDropError
    ? signal.reason
    : new BlindDropError("SESSION_CLOSED");
}

async function callbackListener(port: number, signal: AbortSignal): Promise<CallbackListener> {
  let resolveResponse!: (url: URL) => void;
  let rejectResponse!: (error: BlindDropError) => void;
  let settled = false;
  let redirectUri = "";
  const response = new Promise<URL>((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  // A listen failure can occur before the caller receives this promise.
  void response.catch(() => undefined);

  const settle = (error: BlindDropError | undefined, url?: URL): void => {
    if (settled) return;
    settled = true;
    signal.removeEventListener("abort", onAbort);
    if (error !== undefined) rejectResponse(error);
    else resolveResponse(url as URL);
  };
  const onAbort = () => settle(callbackError(signal));

  const server = createServer(
    { maxHeaderSize: DEFAULT_LIMITS.headerBytes, requireHostHeader: true },
    (request: IncomingMessage, serverResponse: ServerResponse) => {
      const expectedHost = new URL(redirectUri).host;
      const rawUrl = request.url ?? "";
      let callbackUrl: URL | undefined;
      try {
        callbackUrl = new URL(rawUrl, redirectUri);
      } catch {
        // The single static rejection below handles malformed request targets.
      }
      const valid =
        !settled &&
        request.method === "GET" &&
        request.headers.host === expectedHost &&
        request.headers["transfer-encoding"] === undefined &&
        (request.headers["content-length"] === undefined || request.headers["content-length"] === "0") &&
        byteLength(rawUrl) <= MAX_CALLBACK_URL_BYTES &&
        callbackUrl?.origin === new URL(redirectUri).origin &&
        callbackUrl.username === "" &&
        callbackUrl.password === "" &&
        callbackUrl.hash === "" &&
        callbackUrl.pathname === CALLBACK_PATH;

      if (!valid || callbackUrl === undefined) {
        sendCallbackResponse(serverResponse, 400, "Authorization response rejected.\n");
        settle(new BlindDropError("INVALID_INPUT"));
      } else {
        sendCallbackResponse(serverResponse, 200, "Authorization response received. Return to BlindDrop.\n");
        settle(undefined, callbackUrl);
      }
      serverResponse.once("finish", () => server.close());
    },
  );
  server.requestTimeout = 5_000;
  server.headersTimeout = 5_000;
  server.maxRequestsPerSocket = 1;
  server.on("clientError", (error, socket) => {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    settle(new BlindDropError("INVALID_INPUT"));
    void closeServer(server);
  });
  server.on("error", () => settle(new BlindDropError("INPUT_UNAVAILABLE")));
  signal.addEventListener("abort", onAbort, { once: true });

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = () => reject(new BlindDropError("INPUT_UNAVAILABLE"));
      server.once("error", onError);
      server.listen(port, "127.0.0.1", () => {
        server.removeListener("error", onError);
        resolve();
      });
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new BlindDropError("INPUT_UNAVAILABLE");
    }
    redirectUri = `http://127.0.0.1:${address.port}${CALLBACK_PATH}`;
    if (signal.aborted) throw callbackError(signal);
    return { redirectUri, response, close: () => closeServer(server) };
  } catch (error) {
    signal.removeEventListener("abort", onAbort);
    await closeServer(server);
    throw error instanceof BlindDropError ? error : new BlindDropError("INPUT_UNAVAILABLE");
  }
}

function linkedController(parent: AbortSignal | undefined, timeoutMs: number): {
  signal: AbortSignal;
  close(): void;
} {
  const controller = new AbortController();
  const onAbort = () => controller.abort(
    parent?.reason instanceof BlindDropError
      ? parent.reason
      : new BlindDropError("SESSION_CLOSED"),
  );
  if (parent?.aborted) onAbort();
  else parent?.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(
    () => controller.abort(new BlindDropError("TIMEOUT")),
    timeoutMs,
  );
  return {
    signal: controller.signal,
    close() {
      clearTimeout(timer);
      parent?.removeEventListener("abort", onAbort);
    },
  };
}

function targetParameters(auth: OAuthLoginDefinition["connection"]["auth"]): URLSearchParams {
  const parameters = new URLSearchParams();
  if (auth.scope !== undefined) parameters.set("scope", auth.scope);
  if (auth.audience !== undefined) parameters.set("audience", auth.audience);
  if (auth.resource !== undefined) parameters.set("resource", auth.resource);
  return parameters;
}

function authorizationUrl(
  definition: OAuthLoginDefinition,
  redirectUri: string,
  state: string,
  challenge: string,
): URL {
  const url = new URL(definition.authorizationEndpoint);
  for (const [name, value] of Object.entries(definition.authorizationParameters)) {
    url.searchParams.set(name, value);
  }
  for (const [name, value] of targetParameters(definition.connection.auth)) {
    url.searchParams.set(name, value);
  }
  url.searchParams.set("client_id", definition.connection.auth.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (byteLength(url.href) > MAX_AUTHORIZATION_URL_BYTES) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return url;
}

export async function openSystemBrowser(url: string, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    throw callbackError(signal);
  }
  try {
    await open(url);
  } catch {
    if (signal.aborted) {
      throw callbackError(signal);
    }
    throw new BlindDropError("INPUT_UNAVAILABLE");
  }
}

export async function oauthLogin(options: OAuthLoginOptions): Promise<void> {
  const initial = loadVault(options.vaultPath, options.passphrase);
  validateExistingReferences(initial, options.definition.connection);
  const login = linkedController(options.signal, LOGIN_TIMEOUT_MS);
  let listener: CallbackListener | undefined;

  try {
    listener = await callbackListener(options.definition.redirectPort, login.signal);
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const challenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
    const state = oauth.generateRandomState();
    const url = authorizationUrl(options.definition, listener.redirectUri, state, challenge);
    await options.visitAuthorizationUrl(url.href, login.signal);
    const callbackUrl = await listener.response;

    const as: oauth.AuthorizationServer = {
      issuer: options.definition.issuer,
      authorization_endpoint: options.definition.authorizationEndpoint,
      token_endpoint: options.definition.connection.auth.tokenEndpoint,
    };
    const client: oauth.Client = { client_id: options.definition.connection.auth.clientId };
    let callbackParameters: URLSearchParams;
    try {
      callbackParameters = oauth.validateAuthResponse(as, client, callbackUrl, state);
    } catch {
      throw new BlindDropError("UPSTREAM_ERROR");
    }

    const token = linkedController(login.signal, DEFAULT_LIMITS.timeoutMs);
    let result: oauth.TokenEndpointResponse;
    try {
      const endpoint = new URL(options.definition.connection.auth.tokenEndpoint);
      const additional = targetParameters(options.definition.connection.auth);
      const response = await oauth.authorizationCodeGrantRequest(
        as,
        client,
        clientAuthentication(initial, options.definition.connection.auth),
        callbackParameters,
        listener.redirectUri,
        codeVerifier,
        {
          ...createOAuthTokenRequestOptions(
            endpoint,
            options.definition.connection,
            sendHttps,
            token.signal,
            DEFAULT_LIMITS,
            clientTls(initial, options.definition.connection),
          ),
          additionalParameters: additional.size === 0 ? undefined : additional,
        },
      );
      result = await oauth.processAuthorizationCodeResponse(as, client, response);
    } catch (error) {
      if (error instanceof BlindDropError) throw error;
      throw new BlindDropError("UPSTREAM_ERROR");
    } finally {
      token.close();
    }

    if (
      result.token_type !== "bearer" ||
      typeof result.access_token !== "string" ||
      result.access_token.length === 0 ||
      typeof result.refresh_token !== "string" ||
      result.refresh_token.length === 0
    ) {
      throw new BlindDropError("UPSTREAM_ERROR");
    }

    if (login.signal.aborted) throw callbackError(login.signal);
    const latest = loadVault(options.vaultPath, options.passphrase);
    validateExistingReferences(latest, options.definition.connection);
    writeRefreshToken(latest, options.definition.connection.auth.refreshSecret, result.refresh_token);
    saveVault(options.vaultPath, latest, options.passphrase);
    importConnection(options.vaultPath, options.passphrase, options.name, options.definition.connection);
  } finally {
    login.close();
    await listener?.close();
  }
}
