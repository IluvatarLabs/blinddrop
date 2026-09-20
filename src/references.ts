import { BlindDropError } from "./errors.js";
import type {
  Authentication,
  Connection,
  Field,
  Secret,
  SecretRef,
  VaultData,
} from "./types.js";

/**
 * The reserved name of the default vault: the vault an unqualified reference
 * resolves against, and the migration home of the pre-v0.5.1 single archive.
 */
export const DEFAULT_VAULT_NAME = "default";

/**
 * The field a bare `secret` reference resolves to. Migration writes every
 * pre-v0.5.1 single-value secret into a field with this id, preserving the
 * guarantee that replacing a secret keeps its reference.
 */
export const DEFAULT_FIELD_ID = "value";

/**
 * A snapshot of the vaults unlocked for one session, keyed by vault name. Only
 * unlocked vaults appear; a locked vault is simply absent, so nothing it holds
 * is reachable. `defaultVault` names the vault that unqualified references and
 * unqualified legacy references resolve against.
 */
export interface SessionSnapshot {
  defaultVault: string;
  vaults: Map<string, VaultData>;
  connections?: Record<string, Connection>;
}

/** Wraps one vault as the default of a single-vault session snapshot. */
export function singleVaultSnapshot(
  vault: VaultData,
  name: string = DEFAULT_VAULT_NAME,
): SessionSnapshot {
  return { defaultVault: name, vaults: new Map([[name, vault]]) };
}

/** Accepts either a bare vault (the common single-vault case) or a snapshot. */
export function normalizeSnapshot(
  source: VaultData | SessionSnapshot,
): SessionSnapshot {
  if (source instanceof Object && "vaults" in source && source.vaults instanceof Map) {
    return source;
  }
  return singleVaultSnapshot(source as VaultData);
}

/**
 * Parses a validated reference string. `vault#secret#field`, `secret#field`
 * (default vault) and bare `secret` (default vault, default field) are the only
 * shapes; anything else is rejected. `#` is outside the name and field-id
 * character sets, so the split is unambiguous.
 */
export function parseSecretRef(
  reference: string,
  defaultVault: string = DEFAULT_VAULT_NAME,
): SecretRef {
  const parts = reference.split("#");
  if (parts.length === 1) {
    return { vault: defaultVault, secret: parts[0] };
  }
  if (parts.length === 2) {
    return { vault: defaultVault, secret: parts[0], field: parts[1] };
  }
  if (parts.length === 3) {
    return { vault: parts[0], secret: parts[1], field: parts[2] };
  }
  throw new BlindDropError("INVALID_INPUT");
}

/** The canonical string form of a parsed reference. */
export function formatSecretRef(ref: SecretRef, defaultVault: string = DEFAULT_VAULT_NAME): string {
  const field = ref.field ?? DEFAULT_FIELD_ID;
  if (ref.vault === defaultVault) {
    return `${ref.secret}#${field}`;
  }
  return `${ref.vault}#${ref.secret}#${field}`;
}

/**
 * The field a bare reference resolves to: the field literally named `value`
 * (what migration writes), or, failing that, the sole field of a single-field
 * secret. A bare reference into a multi-field secret is ambiguous and
 * unresolvable, which is correct: multi-field secrets are addressed by field.
 */
export function defaultFieldId(secret: Secret): string | undefined {
  if (Object.hasOwn(secret.fields, DEFAULT_FIELD_ID)) {
    return DEFAULT_FIELD_ID;
  }
  const ids = Object.keys(secret.fields);
  return ids.length === 1 ? ids[0] : undefined;
}

/** Resolves a reference to its mutable field, or undefined when unreachable. */
export function resolveField(
  vaults: Map<string, VaultData>,
  ref: SecretRef,
): Field | undefined {
  const vault = vaults.get(ref.vault);
  if (vault === undefined) {
    return undefined;
  }
  const secret = Object.hasOwn(vault.secrets, ref.secret) ? vault.secrets[ref.secret] : undefined;
  if (secret === undefined || !secret.enabled) {
    return undefined;
  }
  const fieldId = ref.field ?? defaultFieldId(secret);
  if (fieldId === undefined) {
    return undefined;
  }
  return Object.hasOwn(secret.fields, fieldId) ? secret.fields[fieldId] : undefined;
}

/** The reachable, nonempty value a reference resolves to, or undefined. */
export function resolveValue(
  vaults: Map<string, VaultData>,
  ref: SecretRef,
): string | undefined {
  const field = resolveField(vaults, ref);
  return field !== undefined && field.value.length > 0 ? field.value : undefined;
}

function present(value: string | undefined): value is string {
  return value !== undefined;
}

/** The parsed references an authentication mechanism consumes. */
export function authSecretRefs(
  auth: Authentication,
  defaultVault: string = DEFAULT_VAULT_NAME,
): SecretRef[] {
  const parse = (reference: string): SecretRef => parseSecretRef(reference, defaultVault);
  switch (auth.type) {
    case "none": return [];
    case "bearer": case "header": case "query": return [parse(auth.secret)];
    case "basic": return [auth.usernameSecret, auth.passwordSecret].filter(present).map(parse);
    case "bindings": return auth.bindings.map((binding) => parse(binding.secret));
    case "oauth2": return [auth.clientSecret, auth.refreshSecret].filter(present).map(parse);
    case "jwt-bearer": return [parse(auth.privateKeySecret)];
    case "aws-sigv4":
      return [auth.accessKeyIdSecret, auth.secretAccessKeySecret, auth.sessionTokenSecret]
        .filter(present).map(parse);
  }
}

/** Every parsed reference a connection consumes across auth and TLS. */
export function connectionSecretRefs(
  connection: Connection,
  defaultVault: string = DEFAULT_VAULT_NAME,
): SecretRef[] {
  const tls = connection.tls;
  const tlsRefs = tls === undefined
    ? []
    : [tls.certificateSecret, tls.privateKeySecret, tls.passphraseSecret]
        .filter(present).map((reference) => parseSecretRef(reference, defaultVault));
  const all = [...authSecretRefs(connection.auth, defaultVault), ...tlsRefs];
  const seen = new Map<string, SecretRef>();
  for (const ref of all) {
    seen.set(formatSecretRef(ref, defaultVault), ref);
  }
  return [...seen.values()];
}

/**
 * Whether every reference a connection consumes resolves to a reachable,
 * enabled, nonempty field in the unlocked set. This is the least-privilege
 * eligibility rule: a connection whose secrets span a locked vault is not
 * resolvable and must not be granted or used.
 */
export function connectionResolvable(
  connection: Connection,
  vaults: Map<string, VaultData>,
  defaultVault: string = DEFAULT_VAULT_NAME,
): boolean {
  return connectionSecretRefs(connection, defaultVault)
    .every((ref) => resolveValue(vaults, ref) !== undefined);
}

function mapAuthentication(auth: Authentication, q: (ref: string) => string): Authentication {
  switch (auth.type) {
    case "none":
      return auth;
    case "bearer": case "header": case "query":
      return { ...auth, secret: q(auth.secret) };
    case "basic":
      return {
        ...auth,
        ...(auth.usernameSecret === undefined ? {} : { usernameSecret: q(auth.usernameSecret) }),
        ...(auth.passwordSecret === undefined ? {} : { passwordSecret: q(auth.passwordSecret) }),
      };
    case "bindings":
      return { ...auth, bindings: auth.bindings.map((binding) => ({ ...binding, secret: q(binding.secret) })) };
    case "oauth2":
      return {
        ...auth,
        ...(auth.clientSecret === undefined ? {} : { clientSecret: q(auth.clientSecret) }),
        ...(auth.refreshSecret === undefined ? {} : { refreshSecret: q(auth.refreshSecret) }),
      };
    case "jwt-bearer":
      return { ...auth, privateKeySecret: q(auth.privateKeySecret) };
    case "aws-sigv4":
      return {
        ...auth,
        accessKeyIdSecret: q(auth.accessKeyIdSecret),
        secretAccessKeySecret: q(auth.secretAccessKeySecret),
        ...(auth.sessionTokenSecret === undefined ? {} : { sessionTokenSecret: q(auth.sessionTokenSecret) }),
      };
  }
}

/** Rewrites reference strings without changing authentication configuration. */
export function mapConnectionReferences(connection: Connection, q: (ref: string) => string): Connection {
  const tls = connection.tls;
  return {
    ...connection,
    auth: mapAuthentication(connection.auth, q),
    ...(tls === undefined ? {} : { tls: {
      certificateSecret: q(tls.certificateSecret),
      privateKeySecret: q(tls.privateKeySecret),
      ...(tls.passphraseSecret === undefined ? {} : { passphraseSecret: q(tls.passphraseSecret) }),
    } }),
  };
}

/** Bind legacy/local references to their source vault before merging connections. */
export function qualifyConnection(vault: VaultData | undefined, vaultName: string, connection: Connection): Connection {
  return mapConnectionReferences(connection, reference => {
    const ref = parseSecretRef(reference, vaultName);
    const secret = ref.vault === vaultName ? vault?.secrets[ref.secret] : undefined;
    const field = ref.field ?? (secret ? defaultFieldId(secret) : undefined) ?? DEFAULT_FIELD_ID;
    return `${ref.vault}#${ref.secret}#${field}`;
  });
}
