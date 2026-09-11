export interface Secret {
  value: string;
  enabled: boolean;
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
  | { type: "oauth2"; tokenEndpoint: string; grant: "client_credentials" | "refresh_token"; clientId: string; clientSecret?: string; refreshSecret?: string; clientAuth: "basic" | "body" | "none"; scope?: string; audience?: string; resource?: string }
  | { type: "jwt-bearer"; tokenEndpoint: string; issuer: string; subject?: string; scope: string; privateKeySecret: string; keyId?: string }
  | { type: "aws-sigv4"; accessKeyIdSecret: string; secretAccessKeySecret: string; sessionTokenSecret?: string; region: string; service: string };

export interface ClientTlsReferences {
  certificateSecret: string;
  privateKeySecret: string;
  passphraseSecret?: string;
}

export interface Connection {
  origin: string;
  auth: Authentication;
  allowPrivate: boolean;
  enabled: boolean;
  tls?: ClientTlsReferences;
}

export interface VaultData {
  version: 1;
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

export interface ConnectionMetadata {
  name: string;
  origin: string;
  authType: Authentication["type"];
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
export type PersistSecret = (name: string, expectedValue: string, value: string) => Promise<void>;
