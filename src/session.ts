import { randomUUID } from "node:crypto";

import { Broker } from "./broker.js";
import { BlindDropError } from "./errors.js";
import {
  connectionResolvable,
  DEFAULT_VAULT_NAME,
  resolveField,
  qualifyConnection,
  type SessionSnapshot,
} from "./references.js";
import type { Connection, PersistSecret, VaultData } from "./types.js";
import { loadVault, saveVault, validateName } from "./vault.js";

export interface BrokerSession {
  broker: Broker;
  expiresAt: number;
}

/**
 * One vault to unlock for a session: the reference qualifier `name`, the
 * archive `path`, and the `passphrase` the caller already holds. The passphrase
 * lives only here and in the closure below; it is never persisted.
 */
export interface VaultUnlock {
  name: string;
  path: string;
  passphrase: string;
}

/**
 * Opens a session over one or more unlocked vaults. A connection is grantable
 * only when its definition is enabled AND every reference
 * it consumes resolves across the unlocked set — so a connection whose secrets
 * span a locked vault cannot be granted. This is the least-privilege property:
 * the owner locks a vault by starting a new session without it, and connections
 * that needed it drop out while the rest keep working.
 */
export function createBrokerSession(
  vaults: VaultUnlock[],
  requestedConnections: string[],
  ttlSeconds: number,
  options: { connections?: Record<string, Connection>; logPath?: string } = {},
): BrokerSession {
  if (vaults.length === 0) {
    throw new BlindDropError("INVALID_INPUT");
  }

  const snapshotVaults = new Map<string, VaultData>();
  const unlockByName = new Map<string, { path: string; passphrase: string }>();
  for (const unlock of vaults) {
    validateName(unlock.name);
    if (snapshotVaults.has(unlock.name)) {
      throw new BlindDropError("INVALID_INPUT");
    }
    snapshotVaults.set(unlock.name, loadVault(unlock.path, unlock.passphrase));
    unlockByName.set(unlock.name, { path: unlock.path, passphrase: unlock.passphrase });
  }

  const defaultVault = snapshotVaults.has(DEFAULT_VAULT_NAME)
    ? DEFAULT_VAULT_NAME
    : vaults[0].name;
  const definitions: Record<string, Connection> = options.connections ?? Object.create(null);
  if (options.connections === undefined) {
    for (const [vaultName, vault] of snapshotVaults) {
      for (const [name, connection] of Object.entries(vault.connections)) {
        if (Object.hasOwn(definitions, name)) throw new BlindDropError("INVALID_INPUT");
        definitions[name] = qualifyConnection(vault, vaultName, connection);
      }
    }
  }
  const snapshot: SessionSnapshot = { defaultVault, vaults: snapshotVaults, connections: definitions };

  const connections = [...new Set(requestedConnections)];
  for (const name of connections) {
    validateName(name);
    const connection = Object.hasOwn(definitions, name) ? definitions[name] : undefined;
    if (connection === undefined || !connection.enabled) {
      throw new BlindDropError("CONNECTION_NOT_FOUND");
    }
    if (!connectionResolvable(connection, snapshotVaults, defaultVault)) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
  }

  // OAuth refresh rotation must persist the replacement into the vault that
  // actually holds the refresh field, verifying the expected old value first.
  const persistSecret: PersistSecret = async (ref, expectedValue, value) => {
    const unlock = unlockByName.get(ref.vault);
    if (unlock === undefined) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
    const sessionField = resolveField(snapshotVaults, ref);
    if (sessionField === undefined || sessionField.value !== expectedValue) {
      throw new BlindDropError("STORAGE_ERROR");
    }

    const latest = loadVault(unlock.path, unlock.passphrase);
    const latestField = resolveField(new Map([[ref.vault, latest]]), ref);
    if (latestField === undefined || latestField.value !== expectedValue) {
      throw new BlindDropError("STORAGE_ERROR");
    }
    latestField.value = value;
    saveVault(unlock.path, latest, unlock.passphrase);
    sessionField.value = value;
  };

  const logVault = unlockByName.get(defaultVault) ?? unlockByName.get(vaults[0].name);
  if (logVault === undefined) {
    throw new BlindDropError("INTERNAL_ERROR");
  }

  const expiresAt = Date.now() + ttlSeconds * 1000;
  const broker = new Broker(
    snapshot,
    { id: randomUUID(), connections, expiresAt },
    { logPath: options.logPath ?? `${logVault.path}.events.jsonl`, persistSecret },
  );
  return { broker, expiresAt };
}
