// Owner operations shared by the terminal CLI and the owner UI server. Every
// function here takes the passphrase the caller already holds; nothing in this
// module prompts, prints, or opens a browser.

import { BlindDropError } from "./errors.js";
import { connectionSecretNames } from "./references.js";
import type { Authentication, Connection, VaultData } from "./types.js";
import { loadVault, saveVault, validateConnection, validateName } from "./vault.js";

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

export interface ConnectionSetOptions {
  origin: string;
  auth: string;
  secret?: string;
  usernameSecret?: string;
  passwordSecret?: string;
  field?: string;
  allowPrivate?: boolean;
}

function connectionUsesSecret(connection: Connection, name: string): boolean {
  return connectionSecretNames(connection).includes(name);
}

function requireAvailableSecret(vault: VaultData, name: string | undefined): string {
  if (name === undefined) {
    throw new BlindDropError("INVALID_INPUT");
  }
  validateName(name);
  const secret = Object.hasOwn(vault.secrets, name) ? vault.secrets[name] : undefined;
  if (secret === undefined || !secret.enabled) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  return name;
}

function requireConnectionSecrets(vault: VaultData, connection: Connection): void {
  for (const secretName of connectionSecretNames(connection)) {
    requireAvailableSecret(vault, secretName);
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
        usernameSecret: requireAvailableSecret(vault, options.usernameSecret)
      }),
      ...(options.passwordSecret === undefined ? {} : {
        passwordSecret: requireAvailableSecret(vault, options.passwordSecret)
      })
    };
  } else {
    if (options.usernameSecret !== undefined || options.passwordSecret !== undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const secret = requireAvailableSecret(vault, options.secret);

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

export function listMetadata(vault: VaultData): ListedMetadata {
  return {
    secrets: Object.entries(vault.secrets)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, item]) => ({ name, enabled: item.enabled })),
    connections: Object.entries(vault.connections)
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
  vault.secrets[name] = { value, enabled: true };
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
  const vault = loadVault(vaultPath, passphrase);
  if (!Object.hasOwn(vault.secrets, name)) {
    throw new BlindDropError("SECRET_NOT_FOUND");
  }
  if (Object.values(vault.connections).some((connection) => connectionUsesSecret(connection, name))) {
    throw new BlindDropError("INVALID_INPUT");
  }
  delete vault.secrets[name];
  saveVault(vaultPath, vault, passphrase);
}

export function setConnection(
  vaultPath: string,
  passphrase: string,
  name: string,
  options: ConnectionSetOptions,
): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  vault.connections[name] = parseConnection(vault, options);
  saveVault(vaultPath, vault, passphrase);
}

export function importConnection(
  vaultPath: string,
  passphrase: string,
  name: string,
  definition: unknown,
): void {
  validateName(name);
  const imported = validateConnection(definition);
  const vault = loadVault(vaultPath, passphrase);
  requireConnectionSecrets(vault, imported);
  vault.connections[name] = imported;
  saveVault(vaultPath, vault, passphrase);
}

export function disableConnection(vaultPath: string, passphrase: string, name: string): void {
  validateName(name);
  const vault = loadVault(vaultPath, passphrase);
  if (!Object.hasOwn(vault.connections, name)) {
    throw new BlindDropError("CONNECTION_NOT_FOUND");
  }
  vault.connections[name].enabled = false;
  saveVault(vaultPath, vault, passphrase);
}

export function changePassphrase(
  vaultPath: string,
  currentPassphrase: string,
  newPassphrase: string,
): void {
  const vault = loadVault(vaultPath, currentPassphrase);
  saveVault(vaultPath, vault, newPassphrase);
}
