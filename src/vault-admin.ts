// Owner operations shared by the terminal CLI and the owner UI server. Every
// function here takes the passphrase the caller already holds; nothing in this
// module prompts, prints, or opens a browser.

import { connectionContext, migrateConnections, writeConnections, type ConnectionContext } from "./connection-store.js";
import { BlindDropError } from "./errors.js";
import {
  connectionSecretRefs,
  DEFAULT_FIELD_ID,
  DEFAULT_VAULT_NAME,
  parseSecretRef,
  resolveValue,
  qualifyConnection,
} from "./references.js";
import type {
  Authentication,
  Connection,
  Field,
  Secret,
  VaultData,
} from "./types.js";
import {
  loadVault,
  saveVault,
  validateConnection,
  validateName,
  validateSecretReference,
} from "./vault.js";

/** A single-value owner secret: the shape the CLI and its `.env` batch create. */
function singleFieldSecret(value: string): Secret {
  return {
    type: "api-key",
    fields: {
      [DEFAULT_FIELD_ID]: { value, label: "Value", masked: true, multiline: false },
    },
    enabled: true,
  };
}


export interface ListedMetadata {
  secrets: { name: string; enabled: boolean }[];
  connections: {
    name: string;
    origin: string;
    authType: string;
    allowPrivate: boolean;
    enabled: boolean;
  }[];
}

/** One owner write may carry a whole .env file, not an unbounded import. */
const MAX_SECRET_BATCH = 64;

export interface ConnectionSetOptions {
  origin: string;
  auth: string;
  secret?: string;
  usernameSecret?: string;
  passwordSecret?: string;
  field?: string;
  allowPrivate?: boolean;
}

/**
 * Validates a reference and, when it targets the default vault this admin
 * command manages, requires it to resolve to an enabled, nonempty field. A
 * reference into another vault cannot be checked here (that vault may be
 * locked); the runtime enforces it when a session opens.
 */
function requireAvailableSecretRef(vault: VaultData, reference: string | undefined): string {
  if (reference === undefined) {
    throw new BlindDropError("INVALID_INPUT");
  }
  validateSecretReference(reference);
  const ref = parseSecretRef(reference, DEFAULT_VAULT_NAME);
  if (
    ref.vault === DEFAULT_VAULT_NAME &&
    resolveValue(new Map([[DEFAULT_VAULT_NAME, vault]]), ref) === undefined
  ) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  return reference;
}

/** Stores a batch into the loaded snapshot so one save publishes all of it. */
function applySecrets(vault: VaultData, secrets: Record<string, string>): void {
  const entries = Object.entries(secrets);
  if (entries.length > MAX_SECRET_BATCH) {
    throw new BlindDropError("INVALID_INPUT");
  }
  for (const [name, value] of entries) {
    validateName(name);
    if (typeof value !== "string" || value.length === 0) {
      throw new BlindDropError("INVALID_INPUT");
    }
    vault.secrets[name] = singleFieldSecret(value);
  }
}

function requireConnectionSecrets(vault: VaultData, connection: Connection): void {
  for (const ref of connectionSecretRefs(connection)) {
    if (ref.vault === DEFAULT_VAULT_NAME && resolveValue(new Map([[DEFAULT_VAULT_NAME, vault]]), ref) === undefined) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
  }
}

function parseConnection(vault: VaultData, options: ConnectionSetOptions): Connection {
  let auth: Authentication;

  if (options.auth === "basic") {
    if (options.secret !== undefined || options.field !== undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    auth = {
      type: "basic",
      ...(options.usernameSecret === undefined ? {} : {
        usernameSecret: requireAvailableSecretRef(vault, options.usernameSecret)
      }),
      ...(options.passwordSecret === undefined ? {} : {
        passwordSecret: requireAvailableSecretRef(vault, options.passwordSecret)
      })
    };
  } else {
    if (options.usernameSecret !== undefined || options.passwordSecret !== undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const secret = requireAvailableSecretRef(vault, options.secret);

    if (options.auth === "bearer") {
      if (options.field !== undefined) {
        throw new BlindDropError("INVALID_INPUT");
      }
      auth = { type: "bearer", secret };
    } else if (options.auth === "header" || options.auth === "query") {
      if (options.field === undefined) {
        throw new BlindDropError("INVALID_INPUT");
      }
      auth = { type: options.auth, secret, name: options.field };
    } else {
      throw new BlindDropError("INVALID_INPUT");
    }
  }

  return validateConnection({
    origin: options.origin,
    auth,
    allowPrivate: options.allowPrivate === true,
    enabled: true
  });
}

export function listMetadata(vault: VaultData, connections = vault.connections): ListedMetadata {
  return {
    secrets: Object.entries(vault.secrets)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, item]) => ({ name, enabled: item.enabled })),
    connections: Object.entries(connections)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, item]) => ({
        name,
        origin: item.origin,
        authType: item.auth.type,
        allowPrivate: item.allowPrivate,
        enabled: item.enabled
      }))
  };
}

export function setSecret(
  vaultPath: string,
  passphrase: string,
  name: string,
  value: string,
): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  vault.secrets[name] = singleFieldSecret(value);
  saveVault(vaultPath, vault, passphrase);
}

/** One load and one save for a whole batch, so agents see it all at once. */
export function setSecrets(
  vaultPath: string,
  passphrase: string,
  secrets: Record<string, string>,
): void {
  const vault = loadVault(vaultPath, passphrase);
  applySecrets(vault, secrets);
  saveVault(vaultPath, vault, passphrase);
}

export function enableSecret(vaultPath: string, passphrase: string, name: string): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  if (!Object.hasOwn(vault.secrets, name)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  vault.secrets[name].enabled = true;
  saveVault(vaultPath, vault, passphrase);
}

export function disableSecret(vaultPath: string, passphrase: string, name: string): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  if (!Object.hasOwn(vault.secrets, name)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  vault.secrets[name].enabled = false;
  saveVault(vaultPath, vault, passphrase);
}

export function removeSecret(vaultPath: string, passphrase: string, name: string): void {
  validateName(name);
  const { vault, connections, context } = migrateConnections(vaultPath, passphrase);
  if (!Object.hasOwn(vault.secrets, name)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  if (Object.values(connections).some(connection => connectionSecretRefs(connection, context.vaultName)
    .some(ref => ref.vault === context.vaultName && ref.secret === name))) {
    throw new BlindDropError("INVALID_INPUT");
  }
  delete vault.secrets[name];
  saveVault(vaultPath, vault, passphrase);
}

export function setConnection(
  vaultPath: string, passphrase: string, name: string, options: ConnectionSetOptions,
): void {
  const vault = loadVault(vaultPath, passphrase);
  importConnection(vaultPath, passphrase, name, parseConnection(vault, options));
}

/** Save secret values first; publish their reference-only connection afterward. */
export function importConnection(
  vaultPath: string, passphrase: string, name: string, definition: unknown,
  secrets?: Record<string, string>,
): void {
  validateName(name);
  const imported = validateConnection(definition);
  const { vault, connections, context } = migrateConnections(vaultPath, passphrase);
  if (secrets !== undefined) applySecrets(vault, secrets);
  requireConnectionSecrets(vault, imported);
  const qualified = qualifyConnection(vault, context.vaultName, imported);
  if (secrets !== undefined) saveVault(vaultPath, vault, passphrase);
  connections[name] = qualified;
  writeConnections(context.path, connections);
}

function changeConnection(vaultPath: string, passphrase: string, name: string, enabled?: boolean): void {
  validateName(name);
  const { connections, context } = migrateConnections(vaultPath, passphrase);
  if (!Object.hasOwn(connections, name)) throw new BlindDropError("CONNECTION_NOT_FOUND");
  if (enabled === undefined) delete connections[name];
  else connections[name].enabled = enabled;
  writeConnections(context.path, connections);
}

export function enableConnection(vaultPath: string, passphrase: string, name: string): void {
  changeConnection(vaultPath, passphrase, name, true);
}
export function disableConnection(vaultPath: string, passphrase: string, name: string): void {
  changeConnection(vaultPath, passphrase, name, false);
}
export function removeConnection(vaultPath: string, passphrase: string, name: string): void {
  changeConnection(vaultPath, passphrase, name);
}

export function changePassphrase(
  vaultPath: string,
  currentPassphrase: string,
  newPassphrase: string,
): void {
  const vault = loadVault(vaultPath, currentPassphrase);
  saveVault(vaultPath, vault, newPassphrase);
}

// --- v0.5.1 typed multi-field secrets and vault-qualified connections ---

/** One field of a typed secret as the owner submits it; an omitted value on a
 *  replace keeps the current stored value for that field id. */
export interface FieldInput {
  value?: string;
  label: string;
  masked: boolean;
  multiline: boolean;
}

/** An `.env` line becomes an api-key secret with a single `token` field, the
 *  archetype's default field (research 6.1); a bare reference resolves to it. */
function tokenSecret(value: string): Secret {
  return {
    type: "api-key",
    fields: { token: { value, label: "Token", masked: true, multiline: false } },
    enabled: true,
  };
}

function applyEnvSecrets(vault: VaultData, secrets: Record<string, string>): void {
  const entries = Object.entries(secrets);
  if (entries.length > MAX_SECRET_BATCH) {
    throw new BlindDropError("INVALID_INPUT");
  }
  for (const [name, value] of entries) {
    validateName(name);
    if (typeof value !== "string" || value.length === 0) {
      throw new BlindDropError("INVALID_INPUT");
    }
    vault.secrets[name] = tokenSecret(value);
  }
}

/**
 * Creates or replaces a typed, multi-field secret. Each field's label/masked/
 * multiline come from the submission; an omitted value keeps the current stored
 * value for that field id (so the page can edit metadata without re-entering
 * the secret). The full field set defines the secret; a field left out of the
 * submission is dropped. `saveVault` performs the deep field-id/label/value/
 * type/count validation.
 */
export interface TypedSecretInput {
  type: string;
  fields: Record<string, FieldInput>;
}

/** Build/replace a typed secret in memory. Omitted field values keep the current value. */
function applyTypedSecret(vault: VaultData, name: string, input: TypedSecretInput): void {
  validateName(name);
  const existing = Object.hasOwn(vault.secrets, name) ? vault.secrets[name] : undefined;
  const nextFields: Record<string, Field> = {};
  for (const [id, spec] of Object.entries(input.fields)) {
    const kept = existing !== undefined && Object.hasOwn(existing.fields, id)
      ? existing.fields[id].value
      : undefined;
    const value = spec.value !== undefined ? spec.value : kept;
    if (value === undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    nextFields[id] = { value, label: spec.label, masked: spec.masked, multiline: spec.multiline };
  }
  vault.secrets[name] = { type: input.type, fields: nextFields, enabled: existing?.enabled ?? true };
}

/** Apply a batch of typed secrets in memory (used when a connection is created with inline secrets). */
function applyTypedSecrets(vault: VaultData, secrets: Record<string, TypedSecretInput>): void {
  const entries = Object.entries(secrets);
  if (entries.length > MAX_SECRET_BATCH) {
    throw new BlindDropError("INVALID_INPUT");
  }
  for (const [name, spec] of entries) {
    applyTypedSecret(vault, name, spec);
  }
}

export function setSecretTyped(
  vaultPath: string,
  passphrase: string,
  name: string,
  type: string,
  fields: Record<string, FieldInput>,
): void {
  const vault = loadVault(vaultPath, passphrase);
  applyTypedSecret(vault, name, { type, fields });
  saveVault(vaultPath, vault, passphrase);
}

/** Removes one field from a secret; the last field cannot be removed (a secret
 *  needs at least one field). Any connection reference to the removed field
 *  becomes unresolvable and is surfaced as a missing reference. */
export function removeSecretField(
  vaultPath: string,
  passphrase: string,
  name: string,
  fieldId: string,
): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  if (!Object.hasOwn(vault.secrets, name)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  const secret = vault.secrets[name];
  if (!Object.hasOwn(secret.fields, fieldId)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  if (Object.keys(secret.fields).length <= 1) {
    throw new BlindDropError("INVALID_INPUT");
  }
  delete secret.fields[fieldId];
  saveVault(vaultPath, vault, passphrase);
}

/** Each `.env` entry becomes an api-key secret with a `token` field, in one write. */
export function importEnvSecrets(
  vaultPath: string,
  passphrase: string,
  secrets: Record<string, string>,
): void {
  const vault = loadVault(vaultPath, passphrase);
  applyEnvSecrets(vault, secrets);
  saveVault(vaultPath, vault, passphrase);
}

/**
 * Validates and qualifies references against the selected secret vault. Inline
 * secrets are saved first, then the reference-only definition is published in
 * owner configuration. References into other vaults are checked at session use.
 */
export function setConnectionQualified(
  vaultPath: string,
  passphrase: string,
  vaultName: string,
  name: string,
  definition: unknown,
  secrets?: Record<string, TypedSecretInput>,
  context: ConnectionContext = connectionContext(vaultPath),
): void {
  validateName(name);
  validateName(vaultName);
  const validated = validateConnection(definition);
  const { vault, connections } = migrateConnections(vaultPath, passphrase, context);
  if (secrets !== undefined) {
    applyTypedSecrets(vault, secrets);
  }
  const qualified = qualifyConnection(vault, vaultName, validated);
  const localVaults = new Map([[vaultName, vault]]);
  for (const ref of connectionSecretRefs(qualified, vaultName)) {
    if (ref.vault === vaultName && resolveValue(localVaults, ref) === undefined) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
  }
  if (secrets !== undefined) saveVault(vaultPath, vault, passphrase);
  connections[name] = qualified;
  writeConnections(context.path, connections);
}
