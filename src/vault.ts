// Adapted from 1claw-cli/src/local-vault.ts at
// 5fa5e2c0af355f6d9530cea132668474a8c2acdf (MIT).

import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { z } from "zod";

import { BlindDropError } from "./errors.js";
import { DEFAULT_FIELD_ID, DEFAULT_VAULT_NAME } from "./references.js";
import type {
  Authentication,
  ClientTlsReferences,
  Connection,
  Secret,
  VaultData,
  VaultRegistry,
} from "./types.js";

const ALGORITHM = "aes-256-gcm";
const FILE_VERSION = 2;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH;

const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;
const MAX_VALUE_BYTES = 64 * 1024;
const MAX_PASSPHRASE_BYTES = 64 * 1024;
const MAX_LABEL_BYTES = 256;
const MAX_REGISTRY_BYTES = 256 * 1024;
const MAX_REGISTRY_ENTRIES = 256;
const PAYLOAD_VERSION = 2;
const REGISTRY_VERSION = 1;
const MAX_FIXED_LITERAL_BYTES = 1_024;
const MAX_STATIC_FIELD_BYTES = 4_096;
const MAX_SCOPE_BYTES = 8_192;
const MAX_OAUTH_TARGET_BYTES = 2_048;

const SCRYPT = {
  N: 1 << 17,
  r: 8,
  p: 1,
  keyLen: 32,
  maxmem: 256 * 1024 * 1024,
} as const;

const NAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/;
// Field ids are snake_case, matching the upstream credential source a developer
// copies from (aws_secret_access_key, private_key, client_secret). `#` is
// excluded, so it is a safe reference delimiter.
const FIELD_ID_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
// The archetype is display metadata; the runtime never branches on it. Kept a
// short lowercase token so a future archetype does not need a schema change.
const SECRET_TYPE_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
const RESERVED_NAMES = new Set(["constructor", "prototype"]);
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const QUERY_NAME_PATTERN = /^[^\u0000-\u001f\u007f]+$/;
const ABSOLUTE_URI_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?\[\]]|%[0-9A-Fa-f]{2})*$/u;
const ROUTING_HEADERS = new Set([
  "connection",
  "content-length",
  "expect",
  "forwarded",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
]);

const NameSchema = z.string().refine(isValidName);

const FieldIdSchema = z.string().refine((value) => FIELD_ID_PATTERN.test(value));

// A vault-qualified secret reference used by a connection auth/TLS slot:
// `vault#secret#field`, `secret#field` (default vault), or bare `secret`
// (default vault, default field). Vault and secret parts are ordinary names;
// the field part is a snake_case field id.
const SecretReferenceSchema = z.string().refine(isValidSecretReference);

const FixedLiteralSchema = z.string().refine(
  (value) =>
    Buffer.byteLength(value, "utf8") <= MAX_FIXED_LITERAL_BYTES &&
    !/[\u0000-\u001f\u007f]/u.test(value),
);

const StaticFieldSchema = z.string().min(1).refine(
  (value) =>
    Buffer.byteLength(value, "utf8") <= MAX_STATIC_FIELD_BYTES &&
    !/[\u0000-\u001f\u007f]/u.test(value),
);

const ScopeSchema = z.string().min(1).refine(
  (value) =>
    Buffer.byteLength(value, "utf8") <= MAX_SCOPE_BYTES &&
    !/[\u0000-\u001f\u007f]/u.test(value),
);

const OAuthTargetSchema = z.string().min(1).refine(
  (value) =>
    Buffer.byteLength(value, "utf8") <= MAX_OAUTH_TARGET_BYTES &&
    !/[\u0000-\u001f\u007f]/u.test(value),
);

const OAuthResourceSchema = OAuthTargetSchema.refine((value) => {
  if (value.includes("#") || !ABSOLUTE_URI_PATTERN.test(value)) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
});

const CredentialFieldNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(QUERY_NAME_PATTERN);

const CredentialHeaderNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(HEADER_NAME_PATTERN)
  .refine((name) => !ROUTING_HEADERS.has(name.toLowerCase()));

const PathPrefixSchema = FixedLiteralSchema
  .refine((value) => value.startsWith("/"))
  .refine(isSafePathLiteral);

const PathSuffixSchema = FixedLiteralSchema.refine(isSafePathLiteral);

const TokenEndpointSchema = z
  .string()
  .min(1)
  .max(2_048)
  .transform((value, context) => {
    if (/[\u0000-\u001f\u007f{}*]/u.test(value)) {
      context.addIssue({ code: "custom", message: "invalid token endpoint" });
      return z.NEVER;
    }

    let endpoint: URL;
    try {
      endpoint = new URL(value);
    } catch {
      context.addIssue({ code: "custom", message: "invalid token endpoint" });
      return z.NEVER;
    }

    if (
      endpoint.protocol !== "https:" ||
      endpoint.username !== "" ||
      endpoint.password !== "" ||
      endpoint.hash !== "" ||
      endpoint.origin === "null"
    ) {
      context.addIssue({ code: "custom", message: "invalid token endpoint" });
      return z.NEVER;
    }
    return endpoint.href;
  });

const FieldSchema = z
  .object({
    value: z
      .string()
      .min(1)
      .refine((value) => Buffer.byteLength(value, "utf8") <= MAX_VALUE_BYTES),
    label: z
      .string()
      .refine(
        (value) =>
          Buffer.byteLength(value, "utf8") <= MAX_LABEL_BYTES &&
          [...value].every((character) => {
            const code = character.codePointAt(0) ?? 0;
            return code > 31 && code !== 127;
          }),
      ),
    masked: z.boolean(),
    multiline: z.boolean(),
  })
  .strict();

const SecretSchema = z
  .object({
    type: z.string().refine((value) => SECRET_TYPE_PATTERN.test(value)),
    fields: z
      .record(FieldIdSchema, FieldSchema)
      .refine((fields) => Object.keys(fields).length >= 1),
    enabled: z.boolean(),
  })
  .strict();

// The pre-v0.5.1 payload: one opaque value per secret, bare-name references.
const SecretSchemaV1 = z
  .object({
    value: z
      .string()
      .min(1)
      .refine((value) => Buffer.byteLength(value, "utf8") <= MAX_VALUE_BYTES),
    enabled: z.boolean(),
  })
  .strict();

const SecretBindingSchema = z.discriminatedUnion("in", [
  z
    .object({
      in: z.literal("header"),
      name: CredentialHeaderNameSchema,
      secret: SecretReferenceSchema,
      prefix: FixedLiteralSchema.optional(),
      suffix: FixedLiteralSchema.optional(),
    })
    .strict(),
  z
    .object({
      in: z.literal("query"),
      name: CredentialFieldNameSchema,
      secret: SecretReferenceSchema,
      prefix: FixedLiteralSchema.optional(),
      suffix: FixedLiteralSchema.optional(),
    })
    .strict(),
  z
    .object({
      in: z.literal("json"),
      name: CredentialFieldNameSchema,
      secret: SecretReferenceSchema,
      prefix: FixedLiteralSchema.optional(),
      suffix: FixedLiteralSchema.optional(),
    })
    .strict(),
  z
    .object({
      in: z.literal("form"),
      name: CredentialFieldNameSchema,
      secret: SecretReferenceSchema,
      prefix: FixedLiteralSchema.optional(),
      suffix: FixedLiteralSchema.optional(),
    })
    .strict(),
  z
    .object({
      in: z.literal("path"),
      secret: SecretReferenceSchema,
      prefix: PathPrefixSchema,
      suffix: PathSuffixSchema.optional(),
    })
    .strict(),
]);

const AuthenticationSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("none") }).strict(),
  z.object({ type: z.literal("bearer"), secret: SecretReferenceSchema }).strict(),
  z
    .object({
      type: z.literal("basic"),
      usernameSecret: SecretReferenceSchema.optional(),
      passwordSecret: SecretReferenceSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("header"),
      secret: SecretReferenceSchema,
      name: CredentialHeaderNameSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal("query"),
      secret: SecretReferenceSchema,
      name: CredentialFieldNameSchema,
    })
    .strict(),
  z.object({ type: z.literal("bindings"), bindings: z.array(SecretBindingSchema).min(1).max(16) }).strict(),
  z
    .object({
      type: z.literal("oauth2"),
      tokenEndpoint: TokenEndpointSchema,
      grant: z.enum(["client_credentials", "refresh_token"]),
      clientId: StaticFieldSchema,
      clientSecret: SecretReferenceSchema.optional(),
      refreshSecret: SecretReferenceSchema.optional(),
      clientAuth: z.enum(["basic", "body", "none"]),
      scope: ScopeSchema.optional(),
      audience: OAuthTargetSchema.optional(),
      resource: OAuthResourceSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("jwt-bearer"),
      tokenEndpoint: TokenEndpointSchema,
      issuer: StaticFieldSchema,
      subject: StaticFieldSchema.optional(),
      scope: ScopeSchema,
      privateKeySecret: SecretReferenceSchema,
      keyId: StaticFieldSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("aws-sigv4"),
      accessKeyIdSecret: SecretReferenceSchema,
      secretAccessKeySecret: SecretReferenceSchema,
      sessionTokenSecret: SecretReferenceSchema.optional(),
      region: StaticFieldSchema,
      service: StaticFieldSchema,
    })
    .strict(),
]).superRefine((auth, context) => {
  if (auth.type === "basic" && auth.usernameSecret === undefined && auth.passwordSecret === undefined) {
    context.addIssue({ code: "custom", message: "basic authentication needs a secret" });
  }

  if (auth.type === "bindings") {
    const destinations = new Set<string>();
    let bodyFormat: "json" | "form" | undefined;
    let pathSeen = false;

    for (const binding of auth.bindings) {
      if (binding.in === "path") {
        if (pathSeen) {
          context.addIssue({ code: "custom", message: "duplicate path binding" });
        }
        pathSeen = true;
        continue;
      }

      const name = binding.in === "header" ? binding.name.toLowerCase() : binding.name;
      const destination = `${binding.in}:${name}`;
      if (destinations.has(destination)) {
        context.addIssue({ code: "custom", message: "duplicate binding destination" });
      }
      destinations.add(destination);

      if (binding.in === "json" || binding.in === "form") {
        if (bodyFormat !== undefined && bodyFormat !== binding.in) {
          context.addIssue({ code: "custom", message: "mixed body binding formats" });
        }
        bodyFormat = binding.in;
      }
    }
  }

  if (auth.type === "oauth2") {
    if (
      (auth.clientAuth === "basic" || auth.clientAuth === "body") &&
      auth.clientSecret === undefined
    ) {
      context.addIssue({ code: "custom", message: "client authentication needs a secret" });
    }
    if (auth.clientAuth === "none" && auth.clientSecret !== undefined) {
      context.addIssue({ code: "custom", message: "public client authentication cannot use a secret" });
    }
    if (auth.grant === "refresh_token" && auth.refreshSecret === undefined) {
      context.addIssue({ code: "custom", message: "refresh grant needs a secret" });
    }
    if (auth.grant === "client_credentials" && auth.refreshSecret !== undefined) {
      context.addIssue({ code: "custom", message: "client credentials cannot use a refresh secret" });
    }
  }
});

const ClientTlsReferencesSchema = z
  .object({
    certificateSecret: SecretReferenceSchema,
    privateKeySecret: SecretReferenceSchema,
    passphraseSecret: SecretReferenceSchema.optional(),
  })
  .strict();

const ConnectionSchema = z
  .object({
    origin: z.string().min(1).max(2_048),
    auth: AuthenticationSchema,
    allowPrivate: z.boolean(),
    enabled: z.boolean(),
    tls: ClientTlsReferencesSchema.optional(),
  })
  .strict()
  .superRefine((connection, context) => {
    if (connection.auth.type === "none" && connection.tls === undefined) {
      context.addIssue({ code: "custom", message: "unauthenticated connections need TLS credentials" });
    }
  });

const IsoTimestampSchema = z.string().refine((value) => {
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
});

const VaultSchema = z
  .object({
    version: z.literal(PAYLOAD_VERSION),
    createdAt: IsoTimestampSchema,
    updatedAt: IsoTimestampSchema,
    secrets: z.record(NameSchema, SecretSchema),
    connections: z.record(NameSchema, ConnectionSchema),
  })
  .strict();

// The one-version-back read path. A bare pre-v0.5.1 reference is still a valid
// reference under `ConnectionSchema` (a name is a one-part reference), so only
// the secret shape differs between the versions.
const VaultSchemaV1 = z
  .object({
    version: z.literal(1),
    createdAt: IsoTimestampSchema,
    updatedAt: IsoTimestampSchema,
    secrets: z.record(NameSchema, SecretSchemaV1),
    connections: z.record(NameSchema, ConnectionSchema),
  })
  .strict();

const RegistryEntrySchema = z
  .object({
    name: NameSchema,
    path: z.string().min(1).max(4_096).refine((value) => !value.includes("\0")),
  })
  .strict();

const RegistrySchema = z
  .object({
    version: z.literal(REGISTRY_VERSION),
    vaults: z.array(RegistryEntrySchema).max(MAX_REGISTRY_ENTRIES),
  })
  .strict();

function isValidName(name: string): boolean {
  return (
    NAME_PATTERN.test(name) &&
    !RESERVED_NAMES.has(name.toLowerCase())
  );
}

function isValidSecretReference(reference: string): boolean {
  const parts = reference.split("#");
  if (parts.length === 1) {
    return isValidName(parts[0]);
  }
  if (parts.length === 2) {
    return isValidName(parts[0]) && FIELD_ID_PATTERN.test(parts[1]);
  }
  if (parts.length === 3) {
    return isValidName(parts[0]) && isValidName(parts[1]) && FIELD_ID_PATTERN.test(parts[2]);
  }
  return false;
}

function isSafePathLiteral(value: string): boolean {
  if (/[?#\\]/u.test(value)) {
    return false;
  }
  return !value.split("/").some((segment) => {
    try {
      const decoded = decodeURIComponent(segment);
      return decoded === "." || decoded === "..";
    } catch {
      return true;
    }
  });
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

function assertPath(path: string): void {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function assertPassphrase(passphrase: string): void {
  if (
    typeof passphrase !== "string" ||
    passphrase.length === 0 ||
    Buffer.byteLength(passphrase, "utf8") > MAX_PASSPHRASE_BYTES
  ) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function parseVault(value: unknown, error: "INVALID_INPUT" | "VAULT_INVALID"): VaultData {
  try {
    const parsed = VaultSchema.safeParse(value);
    if (!parsed.success) {
      throw new BlindDropError(error);
    }

    const connections: Record<string, Connection> = {};
    for (const [name, connection] of Object.entries(parsed.data.connections)) {
      connections[name] = normalizeConnection(connection, error);
    }

    return {
      ...parsed.data,
      connections,
    };
  } catch (cause) {
    if (cause instanceof BlindDropError) {
      throw cause;
    }
    throw new BlindDropError(error);
  }
}

function normalizeOrigin(origin: string, error: "INVALID_INPUT" | "VAULT_INVALID"): string {
  const input = origin.trim();
  const schemeEnd = input.indexOf("://");
  if (input.length === 0 || input.includes("*") || schemeEnd < 0) {
    throw new BlindDropError(error);
  }

  const remainder = input.slice(schemeEnd + 3);
  const suffixIndex = remainder.search(/[/?#]/);
  const authority = suffixIndex < 0 ? remainder : remainder.slice(0, suffixIndex);
  const suffix = suffixIndex < 0 ? "" : remainder.slice(suffixIndex);

  if (authority.length === 0 || authority.includes("@") || (suffix !== "" && suffix !== "/")) {
    throw new BlindDropError(error);
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new BlindDropError(error);
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin === "null"
  ) {
    throw new BlindDropError(error);
  }

  return parsed.origin;
}

function normalizeConnection(
  connection: z.infer<typeof ConnectionSchema>,
  error: "INVALID_INPUT" | "VAULT_INVALID",
): Connection {
  return {
    ...connection,
    origin: normalizeOrigin(connection.origin, error),
  };
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  try {
    return scryptSync(passphrase, salt, SCRYPT.keyLen, {
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
      maxmem: SCRYPT.maxmem,
    });
  } catch {
    throw new BlindDropError("INTERNAL_ERROR");
  }
}

function encrypt(plaintext: string, passphrase: string): Buffer {
  let key: Buffer | undefined;
  try {
    const salt = randomBytes(SALT_LENGTH);
    const iv = randomBytes(IV_LENGTH);
    key = deriveKey(passphrase, salt);

    const cipher = createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([
      Buffer.from([FILE_VERSION]),
      salt,
      iv,
      tag,
      ciphertext,
    ]);
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("INTERNAL_ERROR");
  } finally {
    key?.fill(0);
  }
}

function decrypt(archive: Buffer, passphrase: string): string {
  if (archive.length <= HEADER_LENGTH || archive[0] !== FILE_VERSION) {
    throw new BlindDropError("VAULT_INVALID");
  }

  let offset = 1;
  const salt = archive.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = archive.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const tag = archive.subarray(offset, offset + TAG_LENGTH);
  offset += TAG_LENGTH;
  const ciphertext = archive.subarray(offset);

  const key = deriveKey(passphrase, salt);
  let plaintext: Buffer | undefined;
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch {
    throw new BlindDropError("UNLOCK_FAILED");
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
}

function serializeVault(vault: VaultData): Buffer {
  const plaintext = JSON.stringify(vault);
  if (Buffer.byteLength(plaintext, "utf8") + HEADER_LENGTH > MAX_ARCHIVE_BYTES) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return Buffer.from(plaintext, "utf8");
}

function readArchive(path: string): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, "r");
    const size = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(size) || size <= HEADER_LENGTH || size > MAX_ARCHIVE_BYTES) {
      throw new BlindDropError("VAULT_INVALID");
    }

    const archive = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const read = readSync(descriptor, archive, offset, size - offset, null);
      if (read === 0) {
        throw new BlindDropError("VAULT_INVALID");
      }
      offset += read;
    }

    const extra = Buffer.allocUnsafe(1);
    if (readSync(descriptor, extra, 0, 1, null) !== 0) {
      throw new BlindDropError("VAULT_INVALID");
    }
    return archive;
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    if (errorCode(error) === "ENOENT") {
      throw new BlindDropError("VAULT_NOT_FOUND");
    }
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The public operation has already completed or has a safer error.
      }
    }
  }
}

/** Validates readable encrypted-envelope structure without decrypting it. */
export function validateVaultArchive(path: string): number {
  const archive = readArchive(path);
  if (archive[0] !== FILE_VERSION) throw new BlindDropError("VAULT_INVALID");
  return archive.length;
}

function ensureParentDirectory(path: string): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }
}

function temporaryPath(path: string): string {
  let nonce: string;
  try {
    nonce = randomBytes(12).toString("hex");
  } catch {
    throw new BlindDropError("INTERNAL_ERROR");
  }
  return join(dirname(path), `.${basename(path)}.${process.pid}.${nonce}.tmp`);
}

function writeArchive(path: string, archive: Buffer, createOnly: boolean): void {
  ensureParentDirectory(path);
  const temporary = temporaryPath(path);
  let descriptor: number | undefined;
  let published = false;

  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, archive);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;

    if (createOnly) {
      linkSync(temporary, path);
      published = true;
      unlinkSync(temporary);
    } else {
      renameSync(temporary, path);
      published = true;
    }
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the original safe error below.
      }
    }

    if (!published) {
      try {
        unlinkSync(temporary);
      } catch {
        // The temp file may not have been created or may already be gone.
      }
    }

    if (error instanceof BlindDropError) {
      throw error;
    }
    if (createOnly && errorCode(error) === "EEXIST") {
      throw new BlindDropError("VAULT_EXISTS");
    }
    throw new BlindDropError("STORAGE_ERROR");
  }
}

export function defaultVaultPath(): string {
  try {
    return join(homedir(), ".config", "blinddrop", "vault.enc");
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }
}

export function validateName(name: string): void {
  if (typeof name !== "string" || !isValidName(name)) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

export function validateSecretReference(reference: string): void {
  if (typeof reference !== "string" || !isValidSecretReference(reference)) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

export function validateConnection(connection: unknown): Connection {
  try {
    const parsed = ConnectionSchema.safeParse(connection);
    if (!parsed.success) {
      throw new BlindDropError("INVALID_INPUT");
    }
    return normalizeConnection(parsed.data, "INVALID_INPUT");
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("INVALID_INPUT");
  }
}

export function createVault(path: string, passphrase: string): VaultData {
  assertPath(path);
  assertPassphrase(passphrase);
  if (existsSync(path)) {
    throw new BlindDropError("VAULT_EXISTS");
  }

  const now = new Date().toISOString();
  const vault = parseVault(
    {
      version: PAYLOAD_VERSION,
      createdAt: now,
      updatedAt: now,
      secrets: {},
      connections: {},
    },
    "INVALID_INPUT",
  );
  const plaintext = serializeVault(vault);
  let archive: Buffer;
  try {
    archive = encrypt(plaintext.toString("utf8"), passphrase);
  } finally {
    plaintext.fill(0);
  }
  writeArchive(path, archive, true);
  return vault;
}

export function loadVault(path: string, passphrase: string): VaultData {
  assertPath(path);
  assertPassphrase(passphrase);
  const archive = readArchive(path);
  const plaintext = decrypt(archive, passphrase);

  let decoded: unknown;
  try {
    decoded = JSON.parse(plaintext);
  } catch {
    throw new BlindDropError("VAULT_INVALID");
  }
  return parseDecodedVault(decoded, "VAULT_INVALID");
}

/**
 * Routes a decrypted payload by its schema version. The current version parses
 * directly; the one-version-back v1 payload is migrated in memory. Any other
 * value is an unsupported or damaged archive and fails explicitly rather than
 * being silently reset.
 */
function parseDecodedVault(decoded: unknown, error: "INVALID_INPUT" | "VAULT_INVALID"): VaultData {
  const version =
    typeof decoded === "object" && decoded !== null && "version" in decoded
      ? (decoded as { version: unknown }).version
      : undefined;
  if (version === PAYLOAD_VERSION) {
    return parseVault(decoded, error);
  }
  if (version === 1) {
    return parseVault(migrateFromV1(decoded, error), error);
  }
  throw new BlindDropError(error);
}

/** Appends the default field id to a bare pre-v0.5.1 reference. */
function migrateReference(reference: string): string {
  return reference.includes("#") ? reference : `${reference}#${DEFAULT_FIELD_ID}`;
}

function migrateAuthentication(auth: Authentication): Authentication {
  switch (auth.type) {
    case "none":
      return auth;
    case "bearer": case "header": case "query":
      return { ...auth, secret: migrateReference(auth.secret) };
    case "basic":
      return {
        ...auth,
        ...(auth.usernameSecret === undefined ? {} : { usernameSecret: migrateReference(auth.usernameSecret) }),
        ...(auth.passwordSecret === undefined ? {} : { passwordSecret: migrateReference(auth.passwordSecret) }),
      };
    case "bindings":
      return { ...auth, bindings: auth.bindings.map((binding) => ({ ...binding, secret: migrateReference(binding.secret) })) };
    case "oauth2":
      return {
        ...auth,
        ...(auth.clientSecret === undefined ? {} : { clientSecret: migrateReference(auth.clientSecret) }),
        ...(auth.refreshSecret === undefined ? {} : { refreshSecret: migrateReference(auth.refreshSecret) }),
      };
    case "jwt-bearer":
      return { ...auth, privateKeySecret: migrateReference(auth.privateKeySecret) };
    case "aws-sigv4":
      return {
        ...auth,
        accessKeyIdSecret: migrateReference(auth.accessKeyIdSecret),
        secretAccessKeySecret: migrateReference(auth.secretAccessKeySecret),
        ...(auth.sessionTokenSecret === undefined ? {} : { sessionTokenSecret: migrateReference(auth.sessionTokenSecret) }),
      };
  }
}

function migrateTls(tls: ClientTlsReferences): ClientTlsReferences {
  return {
    certificateSecret: migrateReference(tls.certificateSecret),
    privateKeySecret: migrateReference(tls.privateKeySecret),
    ...(tls.passphraseSecret === undefined ? {} : { passphraseSecret: migrateReference(tls.passphraseSecret) }),
  };
}

/**
 * Migrates a v1 payload to the v0.5.1 shape in memory: each single-value secret
 * becomes an `api-key` secret with one `value` field, and each connection's
 * bare references are rewritten to `secret#value`. The migrated object is
 * returned for the caller to validate as a current-version payload; the archive
 * on disk is untouched until the owner next saves it.
 */
function migrateFromV1(decoded: unknown, error: "INVALID_INPUT" | "VAULT_INVALID"): unknown {
  const parsed = VaultSchemaV1.safeParse(decoded);
  if (!parsed.success) {
    throw new BlindDropError(error);
  }

  const secrets: Record<string, Secret> = {};
  for (const [name, secret] of Object.entries(parsed.data.secrets)) {
    secrets[name] = {
      type: "api-key",
      fields: {
        [DEFAULT_FIELD_ID]: {
          value: secret.value,
          label: "Value",
          masked: true,
          multiline: false,
        },
      },
      enabled: secret.enabled,
    };
  }

  const connections: Record<string, Connection> = {};
  for (const [name, connection] of Object.entries(parsed.data.connections)) {
    connections[name] = {
      ...connection,
      auth: migrateAuthentication(connection.auth),
      ...(connection.tls === undefined ? {} : { tls: migrateTls(connection.tls) }),
    };
  }

  return {
    version: PAYLOAD_VERSION,
    createdAt: parsed.data.createdAt,
    updatedAt: parsed.data.updatedAt,
    secrets,
    connections,
  };
}

/** Validates one secret record, used by the broker to re-check its snapshot. */
export function validateSecret(secret: unknown): Secret {
  const parsed = SecretSchema.safeParse(secret);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return parsed.data;
}

export function saveVault(path: string, vault: VaultData, passphrase: string): void {
  assertPath(path);
  assertPassphrase(passphrase);
  const validated = parseVault(vault, "INVALID_INPUT");
  const persisted: VaultData = {
    ...validated,
    updatedAt: new Date().toISOString(),
  };
  const plaintext = serializeVault(persisted);
  let archive: Buffer;
  try {
    archive = encrypt(plaintext.toString("utf8"), passphrase);
  } finally {
    plaintext.fill(0);
  }
  writeArchive(path, archive, false);
}

/**
 * The vault registry: the set of encrypted vault files this installation knows,
 * each with a display name used as the reference vault qualifier. It holds no
 * passphrases and no secret values — only paths and names — so it is plaintext
 * at mode 0600. An empty registry has an in-memory default placeholder for
 * first use; that placeholder is not persisted unless it becomes a real vault.
 */
export function registryPath(configDir?: string): string {
  return join(configDir ?? dirname(defaultVaultPath()), "vaults.json");
}

/** Copies a validated registry and rejects duplicate names. */
function validateRegistry(registry: VaultRegistry): VaultRegistry {
  const names = new Set<string>();
  const vaults = [] as VaultRegistry["vaults"];
  for (const entry of registry.vaults) {
    if (names.has(entry.name)) {
      throw new BlindDropError("VAULT_INVALID");
    }
    names.add(entry.name);
    vaults.push({ name: entry.name, path: entry.path });
  }
  return { version: REGISTRY_VERSION, vaults };
}

/** The exact persisted registrations, without a synthetic first-use entry. */
export function loadStoredRegistry(configDir?: string): VaultRegistry {
  const path = registryPath(configDir);
  let contents: Buffer;
  try {
    contents = readFileSync(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return { version: REGISTRY_VERSION, vaults: [] };
    }
    throw new BlindDropError("STORAGE_ERROR");
  }
  if (contents.length > MAX_REGISTRY_BYTES) {
    throw new BlindDropError("VAULT_INVALID");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(contents.toString("utf8"));
  } catch {
    throw new BlindDropError("VAULT_INVALID");
  }
  const parsed = RegistrySchema.safeParse(decoded);
  if (!parsed.success) {
    throw new BlindDropError("VAULT_INVALID");
  }
  return validateRegistry(parsed.data);
}

/** UI view: an entirely empty registry exposes one unused default slot. */
export function loadRegistry(configDir?: string): VaultRegistry {
  const stored = loadStoredRegistry(configDir);
  if (stored.vaults.length > 0) return stored;
  return {
    version: REGISTRY_VERSION,
    vaults: [{ name: DEFAULT_VAULT_NAME, path: defaultVaultPath() }],
  };
}

export function saveRegistry(registry: VaultRegistry, configDir?: string): void {
  const parsed = RegistrySchema.safeParse(registry);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const stored = validateRegistry(parsed.data);
  const serialized = Buffer.from(JSON.stringify(stored), "utf8");
  if (serialized.length > MAX_REGISTRY_BYTES) {
    throw new BlindDropError("INVALID_INPUT");
  }
  writeArchive(registryPath(configDir), serialized, false);
}
