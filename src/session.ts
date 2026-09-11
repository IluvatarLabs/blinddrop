import { randomUUID } from "node:crypto";

import { Broker } from "./broker.js";
import { BlindDropError } from "./errors.js";
import { connectionSecretNames } from "./references.js";
import type { PersistSecret, VaultData } from "./types.js";
import { loadVault, saveVault, validateName } from "./vault.js";

export interface BrokerSession {
  broker: Broker;
  expiresAt: number;
}

function availableSecret(vault: VaultData, name: string): boolean {
  const secret = Object.hasOwn(vault.secrets, name) ? vault.secrets[name] : undefined;
  return secret !== undefined && secret.enabled;
}

export function createBrokerSession(
  vaultPath: string,
  passphrase: string,
  requestedConnections: string[],
  ttlSeconds: number,
): BrokerSession {
  const vault = loadVault(vaultPath, passphrase);
  const connections = [...new Set(requestedConnections)];

  for (const name of connections) {
    validateName(name);
    const connection = Object.hasOwn(vault.connections, name)
      ? vault.connections[name]
      : undefined;
    if (connection === undefined || !connection.enabled) {
      throw new BlindDropError("CONNECTION_NOT_FOUND");
    }
    for (const secretName of connectionSecretNames(connection)) {
      if (!availableSecret(vault, secretName)) {
        throw new BlindDropError("SECRET_NOT_FOUND");
      }
    }
  }

  const persistSecret: PersistSecret = async (name, expectedValue, value) => {
    validateName(name);
    const sessionSecret = Object.hasOwn(vault.secrets, name) ? vault.secrets[name] : undefined;
    if (sessionSecret === undefined || !sessionSecret.enabled) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
    if (sessionSecret.value !== expectedValue) {
      throw new BlindDropError("STORAGE_ERROR");
    }

    const latest = loadVault(vaultPath, passphrase);
    const storedSecret = Object.hasOwn(latest.secrets, name) ? latest.secrets[name] : undefined;
    if (storedSecret === undefined || !storedSecret.enabled) {
      throw new BlindDropError("SECRET_NOT_FOUND");
    }
    if (storedSecret.value !== expectedValue) {
      throw new BlindDropError("STORAGE_ERROR");
    }

    storedSecret.value = value;
    saveVault(vaultPath, latest, passphrase);
    sessionSecret.value = value;
  };

  const expiresAt = Date.now() + ttlSeconds * 1000;
  const broker = new Broker(
    vault,
    { id: randomUUID(), connections, expiresAt },
    { logPath: `${vaultPath}.events.jsonl`, persistSecret },
  );
  return { broker, expiresAt };
}
