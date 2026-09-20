import { validateHeaderName, validateHeaderValue } from "node:http";
import { TextDecoder } from "node:util";

import { Sha256 } from "@aws-crypto/sha256-js";
import { SignatureV4 } from "@smithy/signature-v4";
import type { HttpRequest, QueryParameterBag } from "@smithy/types";
import { importPKCS8, SignJWT } from "jose";
import * as oauth from "oauth4webapi";

import { BlindDropError } from "./errors.js";
import {
  normalizeSnapshot,
  parseSecretRef,
  resolveField,
  resolveValue,
  type SessionSnapshot,
} from "./references.js";
import type {
  Authentication,
  ClientTls,
  Connection,
  Limits,
  PersistSecret,
  PreparedRequest,
  SecretBinding,
  SendHttps,
  TransportResponse,
  VaultData,
} from "./types.js";

interface TokenCache {
  accessToken: string;
  expiresAt: number;
}

interface PreparedAuthentication {
  request: PreparedRequest;
  tls?: ClientTls;
  patterns: string[];
}

const JSON_CONTENT_TYPE = /^application\/json(?:\s*;.*)?$/iu;
const FORM_CONTENT_TYPE = /^application\/x-www-form-urlencoded(?:\s*;.*)?$/iu;
const PATH_LITERAL_LIMIT = 1024;
const JWT_LIFETIME_SECONDS = 300;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function cloneRequest(request: PreparedRequest): PreparedRequest {
  return {
    url: new URL(request.url.href),
    method: request.method,
    headers: Object.assign(Object.create(null), request.headers) as Record<string, string>,
    body: request.body === undefined ? undefined : Buffer.from(request.body),
  };
}

function headerEntry(headers: Record<string, string>, name: string): [string, string] | undefined {
  const lower = name.toLowerCase();
  return Object.entries(headers).find(([candidate]) => candidate.toLowerCase() === lower);
}

function deleteHeader(headers: Record<string, string>, name: string): void {
  const lower = name.toLowerCase();
  for (const candidate of Object.keys(headers)) {
    if (candidate.toLowerCase() === lower) {
      delete headers[candidate];
    }
  }
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  try {
    validateHeaderName(name);
    validateHeaderValue(name, value);
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  deleteHeader(headers, name);
  headers[name] = value;
}

function setContentLength(request: PreparedRequest): void {
  deleteHeader(request.headers, "content-length");
  if (request.body !== undefined) {
    request.headers["content-length"] = String(request.body.length);
  }
}

function contentType(headers: Record<string, string>): string | undefined {
  return headerEntry(headers, "content-type")?.[1];
}

function addPattern(target: Set<string>, value: string | undefined): void {
  if (value) {
    target.add(value);
  }
}

function encodedFormValue(value: string): string {
  const parameters = new URLSearchParams();
  parameters.set("value", value);
  return parameters.toString().slice("value=".length);
}

function assertPathLiteral(value: string, prefix: boolean): void {
  let hasDotSegment = false;
  try {
    hasDotSegment = value.split("/").some((part) => {
      const decoded = decodeURIComponent(part);
      return decoded === "." || decoded === "..";
    });
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  if (
    (prefix && !value.startsWith("/")) ||
    Buffer.byteLength(value, "utf8") > PATH_LITERAL_LIMIT ||
    /[?#\\\u0000-\u001f\u007f]/u.test(value) ||
    hasDotSegment
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function asObjectBody(request: PreparedRequest): Record<string, unknown> {
  const type = contentType(request.headers);
  if (type !== undefined && !JSON_CONTENT_TYPE.test(type)) {
    throw new BlindDropError("INVALID_INPUT");
  }

  if (request.body === undefined || request.body.length === 0) {
    return Object.create(null) as Record<string, unknown>;
  }

  try {
    const value: unknown = JSON.parse(UTF8_DECODER.decode(request.body));
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new BlindDropError("INVALID_INPUT");
    }
    return Object.assign(Object.create(null), value) as Record<string, unknown>;
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("INVALID_INPUT");
  }
}

function asFormBody(request: PreparedRequest): URLSearchParams {
  const type = contentType(request.headers);
  if (type !== undefined && !FORM_CONTENT_TYPE.test(type)) {
    throw new BlindDropError("INVALID_INPUT");
  }
  try {
    return new URLSearchParams(
      request.body === undefined ? "" : UTF8_DECODER.decode(request.body),
    );
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function queryBag(url: URL): QueryParameterBag {
  const grouped = new Map<string, string[]>();
  for (const [name, value] of url.searchParams) {
    const values = grouped.get(name);
    if (values) {
      values.push(value);
    } else {
      grouped.set(name, [value]);
    }
  }

  const result: QueryParameterBag = Object.create(null) as QueryParameterBag;
  for (const [name, values] of grouped) {
    result[name] = values.length === 1 ? values[0] : values;
  }
  return result;
}

function fetchBody(body: unknown): Buffer | undefined {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), "utf8");
  }
  if (typeof body === "string") {
    return Buffer.from(body, "utf8");
  }
  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }
  if (ArrayBuffer.isView(body)) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  throw new BlindDropError("INVALID_INPUT");
}

function webResponse(response: TransportResponse): Response {
  return new Response(Uint8Array.from(response.body), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function createOAuthTokenRequestOptions(
  endpoint: URL,
  connection: Connection,
  send: SendHttps,
  signal: AbortSignal,
  limits: Limits,
  tls?: ClientTls,
  patterns?: Set<string>,
): oauth.TokenEndpointRequestOptions {
  return {
    signal,
    [oauth.customFetch]: async (url, options) => {
      let target: URL;
      try {
        target = new URL(url);
      } catch {
        throw new BlindDropError("DESTINATION_DENIED");
      }
      if (target.href !== endpoint.href || options.redirect !== "manual") {
        throw new BlindDropError("DESTINATION_DENIED");
      }
      const body = fetchBody(options.body);
      if ((body?.length ?? 0) > limits.requestBytes) {
        throw new BlindDropError("REQUEST_TOO_LARGE");
      }
      const headers = { ...options.headers };
      deleteHeader(headers, "content-length");
      if (body !== undefined) headers["content-length"] = String(body.length);

      if (patterns !== undefined) {
        const authorization = headerEntry(headers, "authorization")?.[1];
        addPattern(patterns, authorization);
        if (authorization?.toLowerCase().startsWith("basic ")) {
          addPattern(patterns, authorization.slice("Basic ".length));
        }
        if (body !== undefined) {
          for (const value of new URLSearchParams(body.toString("utf8")).values()) {
            if (patterns.has(value)) addPattern(patterns, encodedFormValue(value));
          }
        }
      }

      const response = await send({
        url: target,
        method: options.method,
        headers,
        body,
        allowPrivate: connection.allowPrivate,
        tls,
        signal,
        limits,
      });
      return webResponse(response);
    },
  };
}

function assertFixedHttpsEndpoint(value: string): URL {
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    throw new BlindDropError("INVALID_INPUT");
  }
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.hash !== ""
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return endpoint;
}

function tokenExpiry(expiresIn: number | undefined): number {
  if (expiresIn === undefined) {
    return Number.POSITIVE_INFINITY;
  }
  return Date.now() + Math.max(0, expiresIn) * 1000;
}

export class AuthSession {
  private readonly vaults: Map<string, VaultData>;
  private readonly defaultVault: string;
  private readonly persistSecret: PersistSecret | undefined;
  private readonly patterns = new Set<string>();
  private readonly tokens = new Map<string, TokenCache>();
  private readonly pendingTokens = new Map<string, Promise<TokenCache>>();
  private closed = false;

  constructor(
    source: VaultData | SessionSnapshot,
    options: { persistSecret?: PersistSecret } = {},
  ) {
    const snapshot = normalizeSnapshot(source);
    this.vaults = snapshot.vaults;
    this.defaultVault = snapshot.defaultVault;
    this.persistSecret = options.persistSecret;
  }

  async prepare(
    connectionName: string,
    connection: Connection,
    input: PreparedRequest,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
  ): Promise<PreparedAuthentication> {
    if (this.closed) {
      throw new BlindDropError("SESSION_CLOSED");
    }

    const request = cloneRequest(input);
    const tls = this.resolveTls(connection);

    try {
      await this.applyAuthentication(
        connectionName,
        connection,
        request,
        send,
        signal,
        limits,
        tls,
      );
      setContentLength(request);
      return { request, tls, patterns: [...this.patterns] };
    } catch (error) {
      if (error instanceof BlindDropError) {
        throw error;
      }
      throw new BlindDropError("UPSTREAM_ERROR");
    }
  }

  close(): void {
    this.closed = true;
    this.tokens.clear();
    this.pendingTokens.clear();
    this.patterns.clear();
  }

  private secret(reference: string): string {
    const value = resolveValue(this.vaults, parseSecretRef(reference, this.defaultVault));
    if (value === undefined) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
    addPattern(this.patterns, value);
    return value;
  }

  private resolveTls(connection: Connection): ClientTls | undefined {
    if (!connection.tls) {
      return undefined;
    }
    const cert = this.secret(connection.tls.certificateSecret);
    const key = this.secret(connection.tls.privateKeySecret);
    const passphrase = connection.tls.passphraseSecret === undefined
      ? undefined
      : this.secret(connection.tls.passphraseSecret);
    return { cert, key, passphrase };
  }

  private async applyAuthentication(
    connectionName: string,
    connection: Connection,
    request: PreparedRequest,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
    tls: ClientTls | undefined,
  ): Promise<void> {
    const auth = connection.auth;
    switch (auth.type) {
      case "none":
        return;
      case "bearer": {
        const value = `Bearer ${this.secret(auth.secret)}`;
        setHeader(request.headers, "authorization", value);
        addPattern(this.patterns, value);
        return;
      }
      case "basic":
        this.applyBasic(auth, request);
        return;
      case "header": {
        const value = this.secret(auth.secret);
        setHeader(request.headers, auth.name, value);
        return;
      }
      case "query": {
        const value = this.secret(auth.secret);
        request.url.searchParams.set(auth.name, value);
        addPattern(this.patterns, encodedFormValue(value));
        return;
      }
      case "bindings":
        this.applyBindings(auth.bindings, request);
        return;
      case "oauth2": {
        const token = await this.accessToken(
          connectionName,
          auth,
          connection,
          send,
          signal,
          limits,
          tls,
        );
        const value = `Bearer ${token}`;
        setHeader(request.headers, "authorization", value);
        addPattern(this.patterns, value);
        return;
      }
      case "jwt-bearer": {
        const token = await this.jwtBearerToken(
          connectionName,
          auth,
          connection,
          send,
          signal,
          limits,
          tls,
        );
        const value = `Bearer ${token}`;
        setHeader(request.headers, "authorization", value);
        addPattern(this.patterns, value);
        return;
      }
      case "aws-sigv4":
        await this.applyAws(auth, request);
        return;
    }
  }

  private applyBasic(
    auth: Extract<Authentication, { type: "basic" }>,
    request: PreparedRequest,
  ): void {
    if (auth.usernameSecret === undefined && auth.passwordSecret === undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const username = auth.usernameSecret === undefined ? "" : this.secret(auth.usernameSecret);
    const password = auth.passwordSecret === undefined ? "" : this.secret(auth.passwordSecret);
    if (username.includes(":")) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const encoded = Buffer.from(`${username}:${password}`, "utf8").toString("base64");
    const value = `Basic ${encoded}`;
    setHeader(request.headers, "authorization", value);
    addPattern(this.patterns, encoded);
    addPattern(this.patterns, value);
  }

  private applyBindings(bindings: SecretBinding[], request: PreparedRequest): void {
    const bodyKinds = new Set(bindings.flatMap((binding) =>
      binding.in === "json" || binding.in === "form" ? [binding.in] : []));
    const pathCount = bindings.filter((binding) => binding.in === "path").length;
    if (bindings.length === 0 || bodyKinds.size > 1 || pathCount > 1) {
      throw new BlindDropError("INVALID_INPUT");
    }

    let json: Record<string, unknown> | undefined;
    let form: URLSearchParams | undefined;

    for (const binding of bindings) {
      const source = this.secret(binding.secret);
      const prefix = "prefix" in binding ? binding.prefix ?? "" : "";
      const suffix = binding.suffix ?? "";
      const value = `${prefix}${source}${suffix}`;
      addPattern(this.patterns, value);

      switch (binding.in) {
        case "header":
          setHeader(request.headers, binding.name, value);
          break;
        case "query":
          request.url.searchParams.set(binding.name, value);
          addPattern(this.patterns, encodedFormValue(value));
          break;
        case "json":
          json ??= asObjectBody(request);
          json[binding.name] = value;
          addPattern(this.patterns, JSON.stringify(value));
          break;
        case "form":
          form ??= asFormBody(request);
          form.set(binding.name, value);
          addPattern(this.patterns, encodedFormValue(value));
          break;
        case "path": {
          assertPathLiteral(binding.prefix, true);
          assertPathLiteral(binding.suffix ?? "", false);
          const originalOrigin = request.url.origin;
          const encoded = encodeURIComponent(source);
          const pathname = `${binding.prefix}${encoded}${binding.suffix ?? ""}${request.url.pathname}`;
          request.url.pathname = pathname;
          if (request.url.origin !== originalOrigin) {
            throw new BlindDropError("DESTINATION_DENIED");
          }
          if (request.url.pathname !== pathname) {
            throw new BlindDropError("INVALID_INPUT");
          }
          addPattern(this.patterns, encoded);
          break;
        }
      }
    }

    if (json !== undefined) {
      request.body = Buffer.from(JSON.stringify(json), "utf8");
      setHeader(request.headers, "content-type", "application/json");
    } else if (form !== undefined) {
      request.body = Buffer.from(form.toString(), "utf8");
      setHeader(request.headers, "content-type", "application/x-www-form-urlencoded");
    }
  }

  private async accessToken(
    connectionName: string,
    auth: Extract<Authentication, { type: "oauth2" }>,
    connection: Connection,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
    tls: ClientTls | undefined,
  ): Promise<string> {
    const cached = this.tokens.get(connectionName);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.accessToken;
    }

    const existing = this.pendingTokens.get(connectionName);
    if (existing) {
      return (await existing).accessToken;
    }

    const pending = this.requestOAuthToken(auth, connection, send, signal, limits, tls);
    this.pendingTokens.set(connectionName, pending);
    try {
      const token = await pending;
      if (this.closed) {
        throw new BlindDropError("SESSION_CLOSED");
      }
      this.tokens.set(connectionName, token);
      return token.accessToken;
    } finally {
      if (this.pendingTokens.get(connectionName) === pending) {
        this.pendingTokens.delete(connectionName);
      }
    }
  }

  private async requestOAuthToken(
    auth: Extract<Authentication, { type: "oauth2" }>,
    connection: Connection,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
    tls: ClientTls | undefined,
  ): Promise<TokenCache> {
    const endpoint = assertFixedHttpsEndpoint(auth.tokenEndpoint);
    const as: oauth.AuthorizationServer = {
      issuer: endpoint.origin,
      token_endpoint: endpoint.href,
    };
    const client: oauth.Client = { client_id: auth.clientId };
    const clientSecret = auth.clientSecret === undefined ? undefined : this.secret(auth.clientSecret);

    let clientAuthentication: oauth.ClientAuth;
    switch (auth.clientAuth) {
      case "basic":
        if (clientSecret === undefined) throw new BlindDropError("INVALID_INPUT");
        clientAuthentication = oauth.ClientSecretBasic(clientSecret);
        break;
      case "body":
        if (clientSecret === undefined) throw new BlindDropError("INVALID_INPUT");
        clientAuthentication = oauth.ClientSecretPost(clientSecret);
        break;
      case "none":
        if (clientSecret !== undefined) throw new BlindDropError("INVALID_INPUT");
        clientAuthentication = oauth.None();
        break;
    }

    const options = createOAuthTokenRequestOptions(
      endpoint,
      connection,
      send,
      signal,
      limits,
      tls,
      this.patterns,
    );
    let result: oauth.TokenEndpointResponse;
    if (auth.grant === "client_credentials") {
      const parameters = new URLSearchParams();
      if (auth.scope !== undefined) parameters.set("scope", auth.scope);
      if (auth.audience !== undefined) parameters.set("audience", auth.audience);
      if (auth.resource !== undefined) parameters.set("resource", auth.resource);
      const response = await oauth.clientCredentialsGrantRequest(
        as,
        client,
        clientAuthentication,
        parameters,
        options,
      );
      result = await oauth.processClientCredentialsResponse(as, client, response);
    } else {
      if (auth.refreshSecret === undefined) {
        throw new BlindDropError("INVALID_INPUT");
      }
      const oldRefresh = this.secret(auth.refreshSecret);
      const additionalParameters = new URLSearchParams();
      if (auth.scope !== undefined) additionalParameters.set("scope", auth.scope);
      if (auth.audience !== undefined) additionalParameters.set("audience", auth.audience);
      if (auth.resource !== undefined) additionalParameters.set("resource", auth.resource);
      const response = await oauth.refreshTokenGrantRequest(
        as,
        client,
        clientAuthentication,
        oldRefresh,
        {
          ...options,
          additionalParameters:
            additionalParameters.size === 0 ? undefined : additionalParameters,
        },
      );
      result = await oauth.processRefreshTokenResponse(as, client, response);
      if (result.refresh_token !== undefined && result.refresh_token !== oldRefresh) {
        addPattern(this.patterns, result.refresh_token);
        if (this.persistSecret === undefined) {
          throw new BlindDropError("STORAGE_ERROR");
        }
        const ref = parseSecretRef(auth.refreshSecret, this.defaultVault);
        try {
          await this.persistSecret(ref, oldRefresh, result.refresh_token);
        } catch {
          throw new BlindDropError("STORAGE_ERROR");
        }
        const stored = resolveField(this.vaults, ref);
        if (stored === undefined || stored.value !== oldRefresh) {
          throw new BlindDropError("STORAGE_ERROR");
        }
        stored.value = result.refresh_token;
      }
    }

    if (result.token_type !== "bearer") {
      throw new BlindDropError("UPSTREAM_ERROR");
    }
    addPattern(this.patterns, result.access_token);
    addPattern(this.patterns, `Bearer ${result.access_token}`);
    addPattern(this.patterns, result.refresh_token);
    return { accessToken: result.access_token, expiresAt: tokenExpiry(result.expires_in) };
  }

  private async jwtBearerToken(
    connectionName: string,
    auth: Extract<Authentication, { type: "jwt-bearer" }>,
    connection: Connection,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
    tls: ClientTls | undefined,
  ): Promise<string> {
    const cached = this.tokens.get(connectionName);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.accessToken;
    }
    const existing = this.pendingTokens.get(connectionName);
    if (existing) {
      return (await existing).accessToken;
    }

    const pending = this.requestJwtBearerToken(auth, connection, send, signal, limits, tls);
    this.pendingTokens.set(connectionName, pending);
    try {
      const token = await pending;
      if (this.closed) throw new BlindDropError("SESSION_CLOSED");
      this.tokens.set(connectionName, token);
      return token.accessToken;
    } finally {
      if (this.pendingTokens.get(connectionName) === pending) {
        this.pendingTokens.delete(connectionName);
      }
    }
  }

  private async requestJwtBearerToken(
    auth: Extract<Authentication, { type: "jwt-bearer" }>,
    connection: Connection,
    send: SendHttps,
    signal: AbortSignal,
    limits: Limits,
    tls: ClientTls | undefined,
  ): Promise<TokenCache> {
    const endpoint = assertFixedHttpsEndpoint(auth.tokenEndpoint);
    let key: CryptoKey;
    try {
      key = await importPKCS8(this.secret(auth.privateKeySecret), "RS256");
    } catch {
      throw new BlindDropError("INVALID_INPUT");
    }
    const now = Math.floor(Date.now() / 1000);
    let builder = new SignJWT({ scope: auth.scope })
      .setProtectedHeader({ alg: "RS256", ...(auth.keyId === undefined ? {} : { kid: auth.keyId }) })
      .setIssuer(auth.issuer)
      .setAudience(endpoint.href)
      .setIssuedAt(now)
      .setExpirationTime(now + JWT_LIFETIME_SECONDS);
    if (auth.subject !== undefined) {
      builder = builder.setSubject(auth.subject);
    }
    const assertion = await builder.sign(key);
    addPattern(this.patterns, assertion);
    addPattern(this.patterns, assertion.split(".")[2]);

    const as: oauth.AuthorizationServer = { issuer: endpoint.origin, token_endpoint: endpoint.href };
    const client: oauth.Client = { client_id: auth.issuer };
    const response = await oauth.genericTokenEndpointRequest(
      as,
      client,
      () => undefined,
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
      { assertion },
      createOAuthTokenRequestOptions(
        endpoint,
        connection,
        send,
        signal,
        limits,
        tls,
        this.patterns,
      ),
    );
    const result = await oauth.processGenericTokenEndpointResponse(as, client, response);
    if (result.token_type !== "bearer") {
      throw new BlindDropError("UPSTREAM_ERROR");
    }
    addPattern(this.patterns, result.access_token);
    addPattern(this.patterns, `Bearer ${result.access_token}`);
    addPattern(this.patterns, result.refresh_token);
    return { accessToken: result.access_token, expiresAt: tokenExpiry(result.expires_in) };
  }

  private async applyAws(
    auth: Extract<Authentication, { type: "aws-sigv4" }>,
    request: PreparedRequest,
  ): Promise<void> {
    const accessKeyId = this.secret(auth.accessKeyIdSecret);
    const secretAccessKey = this.secret(auth.secretAccessKeySecret);
    const sessionToken = auth.sessionTokenSecret === undefined
      ? undefined
      : this.secret(auth.sessionTokenSecret);

    const headers: Record<string, string> = Object.create(null) as Record<string, string>;
    for (const [name, value] of Object.entries(request.headers)) {
      headers[name.toLowerCase()] = value;
    }
    headers.host = request.url.host;
    if (request.body !== undefined) {
      headers["content-length"] = String(request.body.length);
    } else {
      delete headers["content-length"];
    }

    const signable: HttpRequest = {
      protocol: request.url.protocol,
      hostname: request.url.hostname,
      port: request.url.port === "" ? undefined : Number(request.url.port),
      method: request.method,
      path: request.url.pathname,
      query: queryBag(request.url),
      headers,
      body: request.body,
    };
    const signer = new SignatureV4({
      credentials: { accessKeyId, secretAccessKey, sessionToken },
      region: auth.region,
      service: auth.service,
      sha256: Sha256,
      uriEscapePath: auth.service !== "s3",
    });
    const signed = await signer.sign(signable);
    request.headers = { ...signed.headers };
    request.body = signed.body === undefined ? undefined : Buffer.from(signed.body);
    const authorization = headerEntry(request.headers, "authorization")?.[1];
    addPattern(this.patterns, authorization);
    addPattern(this.patterns, authorization?.match(/Signature=([0-9a-f]+)/iu)?.[1]);
    addPattern(this.patterns, headerEntry(request.headers, "x-amz-security-token")?.[1]);
  }
}
