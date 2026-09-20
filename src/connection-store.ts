// Reference-only owner configuration. Reuses the same atomic 0600 writer as settings.
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { BlindDropError } from "./errors.js";
import { readGroups, writeGroups, writeOwnerFile } from "./owner-files.js";
import { mapConnectionReferences, parseSecretRef, qualifyConnection } from "./references.js";
import type { Connection, VaultData } from "./types.js";
import { defaultVaultPath, loadRegistry, loadVault, saveVault, validateConnection, validateName } from "./vault.js";

export interface ConnectionContext { path: string; vaultName: string; configDir?: string }
export const connectionsPath = (configDir: string): string => join(configDir, "connections.json");

/** Registered vaults share the app's list; a standalone --vault keeps a portable sidecar. */
export function connectionContext(vaultPath: string): ConnectionContext {
  const configDir = dirname(defaultVaultPath());
  const entry = loadRegistry(configDir).vaults.find(v => resolve(v.path) === resolve(vaultPath));
  return entry ? { path: connectionsPath(configDir), vaultName: entry.name, configDir }
    : { path: `${vaultPath}.connections.json`, vaultName: "default" };
}

function validateConnections(value: unknown): Record<string, Connection> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new BlindDropError("INVALID_INPUT");
  const result: Record<string, Connection> = Object.create(null);
  for (const [name, definition] of Object.entries(value)) {
    validateName(name);
    result[name] = validateConnection(definition);
  }
  return result;
}

export function readConnections(path: string): Record<string, Connection> {
  let text: string;
  try { text = readFileSync(path, "utf8"); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return Object.create(null);
    throw new BlindDropError("STORAGE_ERROR");
  }
  try {
    if (Buffer.byteLength(text) > 4 * 1024 * 1024) throw new Error();
    const data = JSON.parse(text);
    if (data.version !== 1) throw new Error();
    return validateConnections(data.connections);
  } catch { throw new BlindDropError("STORAGE_ERROR"); }
}

export function writeConnections(path: string, connections: Record<string, Connection>): void {
  const text = JSON.stringify({ version: 1, connections: validateConnections(connections) }) + "\n";
  if (Buffer.byteLength(text) > 4 * 1024 * 1024) throw new BlindDropError("INVALID_INPUT");
  writeOwnerFile(path, text);
}

/**
 * Publish configuration before removing its old copy. A failed archive write is
 * retryable: an identical connection is reused, never overwritten or duplicated.
 * Different connections sharing a name retain both, with a source-vault suffix.
 */
export function migrateConnections(
  vaultPath: string, passphrase: string, context = connectionContext(vaultPath),
): { vault: VaultData; connections: Record<string, Connection>; context: ConnectionContext } {
  const vault = loadVault(vaultPath, passphrase);
  const connections = readConnections(context.path);
  const standalone = `${vaultPath}.connections.json`;
  const importSidecar = standalone !== context.path && existsSync(standalone);
  const source = Object.entries(vault.connections);
  if (importSidecar) {
    for (const [name, definition] of Object.entries(readConnections(standalone))) {
      source.push([name, mapConnectionReferences(definition, reference => {
        const ref = parseSecretRef(reference);
        return `${ref.vault === "default" ? context.vaultName : ref.vault}#${ref.secret}#${ref.field ?? "value"}`;
      })]);
    }
  }
  if (!source.length) return { vault, connections, context };
  const groups = context.configDir ? readGroups(context.configDir) : undefined;
  for (const [name, definition] of source) {
    const qualified = qualifyConnection(vault, context.vaultName, definition);
    let target = name, suffix = 1;
    while (Object.hasOwn(connections, target) && !isDeepStrictEqual(connections[target], qualified)) {
      const ending = `-${context.vaultName.slice(0, 20).replace(/[._-]+$/, "")}${suffix === 1 ? "" : `-${suffix}`}`;
      target = name.slice(0, 64 - ending.length).replace(/[._-]+$/, "") + ending;
      suffix++;
    }
    connections[target] = qualified;
    if (groups) {
      const oldKey = `${context.vaultName}#${name}`;
      if (Object.hasOwn(groups.connections, oldKey)) {
        groups.connections[target] = [...new Set([...(groups.connections[target] ?? []), ...groups.connections[oldKey]])];
        delete groups.connections[oldKey];
      }
    }
  }
  writeConnections(context.path, connections);
  if (groups) writeGroups(context.configDir!, groups);
  if (Object.keys(vault.connections).length) {
    vault.connections = {};
    saveVault(vaultPath, vault, passphrase);
  }
  if (importSidecar) {
    try { unlinkSync(standalone); } catch { throw new BlindDropError("STORAGE_ERROR"); }
  }
  return { vault, connections, context };
}
