// Complete owner-setup backup and fresh-state restore. The folder reuses the
// existing registry, connection, group and settings formats; vault bytes stay
// encrypted and are never opened with a passphrase here.

import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  rmdirSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import process from "node:process";

import { connectionsPath, readConnections, writeConnections } from "./connection-store.js";
import { BlindDropError } from "./errors.js";
import {
  backupVault,
  readGroups,
  readSettings,
  settingsPath,
  groupsPath,
  writeGroups,
  writeSettings,
  type GroupsMeta,
  type OwnerSettings,
} from "./owner-files.js";
import type { Connection, VaultRegistry } from "./types.js";
import { loadStoredRegistry, registryPath, saveRegistry, validateVaultArchive } from "./vault.js";

export interface SetupBackupResult {
  path: string;
  vaults: number;
  size: number;
}

interface ValidatedSetup {
  registry: VaultRegistry;
  connections: Record<string, Connection>;
  groups: GroupsMeta;
  settings: OwnerSettings;
  archives: Array<{ backupPath: string; sourcePath: string; size: number }>;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

function assertPath(path: string): void {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function temporaryDirectory(path: string): string {
  try {
    const nonce = randomBytes(12).toString("hex");
    return join(dirname(path), `.${basename(path)}.${process.pid}.${nonce}.tmp`);
  } catch {
    throw new BlindDropError("INTERNAL_ERROR");
  }
}

function removeTree(path: string): void {
  try {
    rmSync(path, { recursive: true, force: true });
  } catch {
    // Preserve the operation's original safe error.
  }
}

function pathExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw new BlindDropError("STORAGE_ERROR");
  }
}

function makePrivateDirectory(path: string): void {
  try {
    mkdirSync(path, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (errorCode(error) === "EEXIST") throw new BlindDropError("VAULT_EXISTS");
    throw new BlindDropError("STORAGE_ERROR");
  }
}

function backupArchivePath(index: number): string {
  return join("vaults", `${String(index).padStart(3, "0")}.enc`);
}

/** Checks only the public envelope shape; authentication is proven on unlock. */
function validateEncryptedEnvelope(path: string, missing: "VAULT_NOT_FOUND" | "VAULT_INVALID"): number {
  try {
    return validateVaultArchive(path);
  } catch (error) {
    if (error instanceof BlindDropError && error.code === "VAULT_NOT_FOUND") {
      throw new BlindDropError(missing);
    }
    throw error;
  }
}

function requireRegularReadableFile(path: string): void {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile()) throw new BlindDropError("VAULT_INVALID");
    readFileSync(path);
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    if (errorCode(error) === "ENOENT") throw new BlindDropError("VAULT_INVALID");
    throw new BlindDropError("STORAGE_ERROR");
  }
}

function invalidBackup<T>(read: () => T): T {
  try {
    return read();
  } catch (error) {
    if (error instanceof BlindDropError && error.code === "STORAGE_ERROR") {
      throw new BlindDropError("VAULT_INVALID");
    }
    if (error instanceof BlindDropError) throw error;
    throw new BlindDropError("VAULT_INVALID");
  }
}

function mappedSettings(
  settings: OwnerSettings,
  paths: Map<string, string>,
): OwnerSettings {
  const map = (path: string): string | undefined => paths.get(resolve(path));
  return {
    ...settings,
    lastVault: settings.lastVault === null ? null : map(settings.lastVault) ?? null,
    recentVaults: settings.recentVaults.flatMap(path => {
      const mapped = map(path);
      return mapped === undefined ? [] : [mapped];
    }),
    ui: { ...settings.ui },
  };
}

/** Creates one complete folder and publishes it with a single sibling rename. */
export function backupSetup(configDir: string, targetPath: string): SetupBackupResult {
  assertPath(configDir);
  assertPath(targetPath);
  if (pathExists(targetPath)) throw new BlindDropError("VAULT_EXISTS");

  for (const path of [groupsPath(configDir), settingsPath(configDir)]) {
    if (pathExists(path)) requireRegularReadableFile(path);
  }
  const stored = loadStoredRegistry(configDir);
  const canonical = join(configDir, "vault.enc");
  const includeCanonical = existsSync(canonical) &&
    !stored.vaults.some(entry => entry.name === "default" || resolve(entry.path) === resolve(canonical));
  const registry: VaultRegistry = {
    version: 1,
    vaults: includeCanonical
      ? [{ name: "default", path: canonical }, ...stored.vaults]
      : stored.vaults,
  };
  if (registry.vaults.length === 0) throw new BlindDropError("VAULT_NOT_FOUND");
  const connections = readConnections(connectionsPath(configDir));
  const groups = readGroups(configDir);
  const settings = readSettings(configDir);
  const archives = registry.vaults.map((entry, index) => ({
    entry,
    backupPath: backupArchivePath(index),
    size: validateEncryptedEnvelope(entry.path, "VAULT_NOT_FOUND"),
  }));
  const pathMap = new Map(archives.map(item => [resolve(item.entry.path), item.backupPath]));
  const backupRegistry: VaultRegistry = {
    version: 1,
    vaults: archives.map(item => ({ name: item.entry.name, path: item.backupPath })),
  };

  const stage = temporaryDirectory(targetPath);
  let published = false;
  try {
    makePrivateDirectory(stage);
    makePrivateDirectory(join(stage, "vaults"));
    saveRegistry(backupRegistry, stage);
    writeConnections(connectionsPath(stage), connections);
    writeGroups(stage, groups);
    writeSettings(stage, mappedSettings(settings, pathMap));
    for (const item of archives) {
      backupVault(item.entry.path, join(stage, item.backupPath));
    }
    if (pathExists(targetPath)) throw new BlindDropError("VAULT_EXISTS");
    renameSync(stage, targetPath);
    published = true;
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (!published) removeTree(stage);
  }

  return {
    path: targetPath,
    vaults: archives.length,
    size: archives.reduce((total, item) => total + item.size, 0),
  };
}

function validateSetupFolder(sourcePath: string): ValidatedSetup {
  assertPath(sourcePath);
  try {
    if (!lstatSync(sourcePath).isDirectory()) throw new BlindDropError("VAULT_INVALID");
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    if (errorCode(error) === "ENOENT") throw new BlindDropError("VAULT_INVALID");
    throw new BlindDropError("STORAGE_ERROR");
  }

  const metadata = [
    registryPath(sourcePath),
    connectionsPath(sourcePath),
    groupsPath(sourcePath),
    settingsPath(sourcePath),
  ];
  for (const path of metadata) requireRegularReadableFile(path);

  const registry = invalidBackup(() => loadStoredRegistry(sourcePath));
  if (registry.vaults.length === 0) throw new BlindDropError("VAULT_INVALID");
  const connections = invalidBackup(() => readConnections(connectionsPath(sourcePath)));
  const groups = invalidBackup(() => readGroups(sourcePath));
  const settings = invalidBackup(() => readSettings(sourcePath));
  const allowedSettingsPaths = new Set<string>();
  const archives = registry.vaults.map((entry, index) => {
    const expected = backupArchivePath(index);
    if (entry.path !== expected) throw new BlindDropError("VAULT_INVALID");
    const source = join(sourcePath, expected);
    requireRegularReadableFile(source);
    const size = validateEncryptedEnvelope(source, "VAULT_INVALID");
    allowedSettingsPaths.add(expected);
    return { backupPath: expected, sourcePath: source, size };
  });
  if (settings.lastVault !== null && !allowedSettingsPaths.has(settings.lastVault)) {
    throw new BlindDropError("VAULT_INVALID");
  }
  if (settings.recentVaults.some(path => !allowedSettingsPaths.has(path))) {
    throw new BlindDropError("VAULT_INVALID");
  }
  return { registry, connections, groups, settings, archives };
}

function assertEmptyDestination(configDir: string): boolean {
  try {
    const stat = lstatSync(configDir);
    if (!stat.isDirectory() || readdirSync(configDir).length !== 0) {
      throw new BlindDropError("VAULT_EXISTS");
    }
    return true;
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    if (errorCode(error) === "ENOENT") return false;
    throw new BlindDropError("STORAGE_ERROR");
  }
}

/** Restores a validated folder into one empty app root and leaves every vault locked. */
export function restoreSetup(configDir: string, sourcePath: string): SetupBackupResult {
  assertPath(configDir);
  const setup = validateSetupFolder(sourcePath);
  const destination = resolve(configDir);
  const destinationExisted = assertEmptyDestination(destination);
  try {
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }

  const stage = temporaryDirectory(destination);
  let published = false;
  let removedDestination = false;
  try {
    makePrivateDirectory(stage);
    makePrivateDirectory(join(stage, "vaults"));

    const restoredPaths = new Map<string, string>();
    const restoredVaults = setup.registry.vaults.map((entry, index) => {
      const relative = entry.name === "default"
        ? "vault.enc"
        : join("vaults", `${String(index).padStart(3, "0")}.enc`);
      const finalPath = join(destination, relative);
      restoredPaths.set(entry.path, finalPath);
      backupVault(setup.archives[index].sourcePath, join(stage, relative));
      return { name: entry.name, path: finalPath };
    });

    saveRegistry({ version: 1, vaults: restoredVaults }, stage);
    writeConnections(connectionsPath(stage), setup.connections);
    writeGroups(stage, setup.groups);
    writeSettings(stage, {
      ...setup.settings,
      lastVault: setup.settings.lastVault === null
        ? null
        : restoredPaths.get(setup.settings.lastVault) ?? null,
      recentVaults: setup.settings.recentVaults.flatMap(path => {
        const mapped = restoredPaths.get(path);
        return mapped === undefined ? [] : [mapped];
      }),
      ui: { ...setup.settings.ui },
    });

    if (assertEmptyDestination(destination)) {
      rmdirSync(destination);
      removedDestination = true;
    }
    renameSync(stage, destination);
    published = true;
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (!published) {
      removeTree(stage);
      if (destinationExisted && removedDestination && !existsSync(destination)) {
        try {
          mkdirSync(destination, { mode: 0o700 });
        } catch {
          // The destination remains empty and no partial setup was published.
        }
      }
    }
  }

  return {
    path: destination,
    vaults: setup.archives.length,
    size: setup.archives.reduce((total, item) => total + item.size, 0),
  };
}
