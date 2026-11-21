export interface Field {
  value: string;
  label: string;
  masked: boolean;
  multiline: boolean;
}

export interface Secret {
  type: string;
  fields: Record<string, Field>;
  enabled: boolean;
}

/**
 * A parsed vault-qualified secret reference: `vault#secret#field`. A missing
 * vault resolves to the session's default vault; a missing field resolves to
 * the secret's default field. See `src/references.ts`.
 */
export interface SecretRef {
  vault: string;
  secret: string;
  field?: string;
}

export interface VaultRegistryEntry {
  name: string;
  path: string;
}

export interface VaultRegistry {
  version: 1;
  vaults: VaultRegistryEntry[];
}

export type SecretBinding =
  | { in: "header" | "query" | "json" | "form"; name: string; secret: string; prefix?: string; suffix?: string }
  | { in: "path"; secret: string; prefix: string; suffix?: string };

export type Authentication =
  | { type: "none" }
  | { type: "bearer"; secret: string }
  | { type: "basic"; usernameSecret?: string; passwordSecret?: string }
  | { type: "header"; secret: string; name: string }
  | { type: "query"; secret: string; name: string }
  | { type: "bindings"; bindings: SecretBinding[] }
  // Exactly one of the literal `clientId` or the vault reference `clientIdSecret`.
  | { type: "oauth2"; tokenEndpoint: string; grant: "client_credentials" | "refresh_token"; clientId?: string; clientIdSecret?: string; clientSecret?: string; refreshSecret?: string; clientAuth: "basic" | "body" | "none"; scope?: string; audience?: string; resource?: string }
  | { type: "jwt-bearer"; tokenEndpoint: string; issuer: string; subject?: string; scope: string; privateKeySecret: string; keyId?: string }
  | { type: "aws-sigv4"; accessKeyIdSecret: string; secretAccessKeySecret: string; sessionTokenSecret?: string; region: string; service: string }
  // Modal account token used by the official SDK; never an HTTP credential.
  | { type: "modal"; tokenIdSecret: string; tokenSecretSecret: string };

export interface ClientTlsReferences {
  certificateSecret: string;
  privateKeySecret: string;
  passphraseSecret?: string;
}

/**
 * Owner-only browser consent settings for an OAuth refresh-grant connection.
 * The same shape as the `oauth login` definition. The broker reads only
 * `issuer`, to check an ID token that a refresh response may carry.
 */
export interface OAuthConsent {
  issuer: string;
  authorizationEndpoint: string;
  authorizationParameters?: Record<string, string>;
  /** 0 or absent selects any free loopback port. */
  redirectPort?: number;
}

/** The one deployed Modal Function a Modal connection may invoke. */
export interface ModalTarget {
  app: string;
  function: string;
  environment: string;
  /** Optional owner-written description or example of the Function's arguments. */
  usage?: string;
}

export interface Connection {
  origin: string;
  auth: Authentication;
  allowPrivate: boolean;
  enabled: boolean;
  tls?: ClientTlsReferences;
  /** Stable id of the bundled static recipe this connection was created from. */
  recipe?: string;
  /** Only with OAuth refresh-grant authentication. */
  consent?: OAuthConsent;
  /** Required with, and only with, Modal authentication. */
  modal?: ModalTarget;
}

export interface VaultData {
  version: 2;
  createdAt: string;
  updatedAt: string;
  secrets: Record<string, Secret>;
  connections: Record<string, Connection>;
}

export interface Grant {
  id: string;
  connections: string[];
  expiresAt: number;
}

export interface RequestInput {
  connection: string;
  method?: string;
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
  bodyBase64?: string;
  multipart?: { fields?: Record<string, string>; files: { name: string; filename: string; contentType?: string; dataBase64: string }[] };
  responseEncoding?: "utf8" | "base64";
}

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  bodyEncoding?: "base64";
}

export interface ModalInvokeInput {
  connection: string;
  args?: unknown[];
  kwargs?: Record<string, unknown>;
}

export interface ModalInvokeResult {
  result: unknown;
}

export type ConnectionTool = "execute_http" | "invoke_modal_function";

/**
 * Credential-free usage guidance derived from a bundled recipe and ordinary
 * connection configuration. Never contains a stored value, field label, note
 * or vault reference. See `connectionGuidance` in `src/recipes.ts`.
 */
export interface ConnectionGuidance {
  /** A known, compatible recipe id; null selects the generic guidance. */
  recipe: string | null;
  tool: ConnectionTool;
  summary: string;
  /** A complete input skeleton for `tool`, naming this connection. */
  example: Record<string, unknown>;
  /** True when the example contains placeholders or is not a documented operation. */
  schematic: boolean;
  notes: string[];
  /** Modal connections only: the owner-selected Function. */
  target?: ModalTarget;
}

export interface ConnectionMetadata extends ConnectionGuidance {
  name: string;
  origin: string;
  authType: Authentication["type"];
  /** False only for a connection whose vault is locked; calling it asks the owner to unlock. */
  available: boolean;
  reason?: "locked";
}

export interface Limits {
  requestBytes: number;
  responseBytes: number;
  headerBytes: number;
  timeoutMs: number;
  concurrency: number;
}

// Trusted internal contracts. None of these values are MCP tool results.
export interface PreparedRequest {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body?: Buffer;
}

export interface ClientTls {
  cert: string;
  key: string;
  passphrase?: string;
}

export interface TransportRequest extends PreparedRequest {
  allowPrivate: boolean;
  tls?: ClientTls;
  signal: AbortSignal;
  limits: Limits;
}

export interface TransportResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: string[];
  rawTrailers: string[];
  body: Buffer;
}

export interface TransportStreamResponse {
  status: number;
  statusText: string;
  rawHeaders: string[];
  body: AsyncIterable<Buffer>;
}

export interface StreamingSink {
  head(
    status: number,
    headers: Record<string, string>,
  ): void | Promise<void>;
  write(chunk: Buffer): Promise<void>;
}

export interface StreamingOptions {
  signal?: AbortSignal;
  extraPatterns?: readonly string[];
}

export interface ExecuteOptions {
  signal?: AbortSignal;
  extraPatterns?: readonly string[];
}

export type SendHttps = (request: TransportRequest) => Promise<TransportResponse>;
export type ConsumeHttpsStream = (
  response: TransportStreamResponse,
) => Promise<void>;
export type SendHttpsStreaming = (
  request: TransportRequest,
  consume: ConsumeHttpsStream,
) => Promise<void>;
export type PersistSecret = (ref: SecretRef, expectedValue: string, value: string) => Promise<void>;
