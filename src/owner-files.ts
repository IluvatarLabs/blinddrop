// Owner-only files that live beside the vault and in the owner's config
// directory: the settings file, the GUI group sidecar, the use-event log
// reader and the encrypted-archive backup copier. None of this is agent
// reachable and none of it holds a secret value. Nothing here prompts or
// prints.

import { randomBytes, randomInt } from "node:crypto";
import {
  closeSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import process from "node:process";

import { z } from "zod";

import { BlindDropError } from "./errors.js";
import { validateName } from "./vault.js";

/** One page load reads the tail twice; keep it bounded and cheap. */
const MAX_LOG_TAIL_BYTES = 4 * 1024 * 1024;
const MAX_UI_BYTES = 4_096;
const MAX_RECENT_VAULTS = 10;
const MAX_GROUPS = 64;
const MAX_GROUPS_PER_CONNECTION = 16;
export const MAX_ACTIVITY_LIMIT = 2_000;
export const DEFAULT_ACTIVITY_LIMIT = 200;

export interface OwnerSettings {
  appearance: "system" | "light" | "dark";
  sessionPort: number;
  sessionFile: boolean;
  lockOnSleep: boolean;
  lockOnScreenLock: boolean;
  idleLockMinutes: number;
  openAtLogin: boolean;
  showDockIcon: boolean;
  lastVault: string | null;
  recentVaults: string[];
  lastBackupAt: string | null;
  ui: Record<string, unknown>;
}

/**
 * Owner-side group labels for connections. In v0.5.1 connections span multiple
 * vaults, so the sidecar is a single global file in the config directory keyed
 * by connection name, accepting legacy `vault#name` keys for migration. The archive never
 * stores groups and agents never see them.
 */
export interface GroupsMeta {
  version: 1;
  groups: string[];
  connections: Record<string, string[]>;
}

export interface UseEventRecord {
  timestamp: string;
  grantId: string;
  connection: string | null;
  outcome: "success" | "denied" | "blocked" | "failed";
  code: string | null;
  httpStatus: number | null;
}

const DYNAMIC_PORT_MIN = 49_152;
const DYNAMIC_PORT_MAX_EXCLUSIVE = 65_536;

export const SETTINGS_DEFAULTS: Omit<OwnerSettings, "sessionPort"> = {
  appearance: "system",
  sessionFile: true,
  lockOnSleep: true,
  lockOnScreenLock: false,
  idleLockMinutes: 0,
  openAtLogin: false,
  showDockIcon: true,
  lastVault: null,
  recentVaults: [],
  lastBackupAt: null,
  ui: {},
};

const UiSchema = z
  .record(z.string(), z.unknown())
  .refine((value) => Buffer.byteLength(JSON.stringify(value), "utf8") <= MAX_UI_BYTES);

/** Every field is optional: a patch and a stored file are validated alike. */
const SettingsSchema = z
  .object({
    appearance: z.enum(["system", "light", "dark"]),
    sessionPort: z.number().int().min(1).max(65_535),
    sessionFile: z.boolean(),
    lockOnSleep: z.boolean(),
    lockOnScreenLock: z.boolean(),
    idleLockMinutes: z.union([z.literal(0), z.literal(1), z.literal(5), z.literal(15), z.literal(30), z.literal(60)]),
    openAtLogin: z.boolean(),
    showDockIcon: z.boolean(),
    lastVault: z.string().min(1).nullable(),
    recentVaults: z.array(z.string().min(1)).max(MAX_RECENT_VAULTS),
    lastBackupAt: z.string().min(1).nullable(),
    ui: UiSchema,
  })
  .partial()
  .strict();

const GroupsSchema = z
  .object({
    version: z.literal(1).optional(),
    groups: z.array(z.string()).max(MAX_GROUPS),
    connections: z.record(z.string(), z.array(z.string()).max(MAX_GROUPS_PER_CONNECTION)),
  })
  .strict();

const UseEventSchema = z
  .object({
    timestamp: z.string(),
    grantId: z.string(),
    connection: z.string().nullable(),
    outcome: z.enum(["success", "denied", "blocked", "failed"]),
    code: z.string().nullable(),
    httpStatus: z.number().int().min(100).max(999).nullable().optional(),
  })
  .strict();

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

function temporaryPath(path: string): string {
  let nonce: string;
  try {
    nonce = randomBytes(12).toString("hex");
  } catch {
    throw new BlindDropError("INTERNAL_ERROR");
  }
  return join(dirname(path), `.${basename(path)}.${process.pid}.${nonce}.tmp`);
}

/**
 * Publishes an owner metadata file through an exclusive 0600 sibling and one
 * rename, the same way `session-file.ts` and the archive writer publish theirs.
 */
export function writeOwnerFile(path: string, contents: string): void {
  assertPath(path);
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }

  const temporary = temporaryPath(path);
  let descriptor: number | undefined;
  let published = false;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    published = true;
  } catch (error) {
    if (error instanceof BlindDropError) throw error;
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the original safe error above.
      }
    }
    if (!published) {
      try {
        unlinkSync(temporary);
      } catch {
        // The temporary file may never have been created.
      }
    }
  }
}

export function settingsPath(configDir: string): string {
  return join(configDir, "settings.json");
}

export function groupsPath(configDir: string): string {
  return join(configDir, "groups.json");
}

export function activityLogPath(vaultPath: string): string {
  return `${vaultPath}.events.jsonl`;
}

function defaultSettings(sessionPort?: number): OwnerSettings {
  return {
    ...SETTINGS_DEFAULTS,
    sessionPort: sessionPort ?? randomInt(DYNAMIC_PORT_MIN, DYNAMIC_PORT_MAX_EXCLUSIVE),
    ui: {},
    recentVaults: [],
  };
}

function mergeSettings(base: OwnerSettings, patch: Partial<OwnerSettings>): OwnerSettings {
  const merged: OwnerSettings = { ...base, ...patch };
  merged.recentVaults = [...new Set(merged.recentVaults)].slice(0, MAX_RECENT_VAULTS);
  merged.ui = { ...merged.ui };
  return merged;
}

function readStoredSettings(configDir: string): Partial<OwnerSettings> | undefined {
  const path = settingsPath(configDir);
  assertPath(path);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw new BlindDropError("STORAGE_ERROR");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }
  const parsed = SettingsSchema.safeParse(value);
  if (!parsed.success) {
    throw new BlindDropError("STORAGE_ERROR");
  }
  return parsed.data;
}

/** Missing settings, or a valid legacy file without a port, gets one saved random port. */
export function readSettings(configDir: string): OwnerSettings {
  const stored = readStoredSettings(configDir);
  const generatedPort = stored?.sessionPort === undefined;
  const merged = mergeSettings(defaultSettings(stored?.sessionPort), stored ?? {});
  if (stored === undefined || generatedPort) {
    writeOwnerFile(settingsPath(configDir), `${JSON.stringify(merged)}\n`);
  }
  return merged;
}

/** Validates the owner's patch, merges it over the stored file and republishes. */
export function writeSettings(configDir: string, patch: unknown): OwnerSettings {
  const parsed = SettingsSchema.safeParse(patch);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const stored = readStoredSettings(configDir);
  const port = parsed.data.sessionPort ?? stored?.sessionPort;
  const merged = mergeSettings(defaultSettings(port), { ...(stored ?? {}), ...parsed.data });
  writeOwnerFile(settingsPath(configDir), `${JSON.stringify(merged)}\n`);
  return merged;
}

/** A connection group key is `vault#name`; both parts are ordinary names. */
function connectionKeyParts(key: string): [string, string] {
  const parts = key.split("#");
  if (parts.length === 1) return ["default", key];
  if (parts.length !== 2) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return [parts[0], parts[1]];
}

function validateGroups(value: unknown): GroupsMeta {
  const parsed = GroupsSchema.safeParse(value);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const groups = parsed.data.groups;
  for (const group of groups) validateName(group);
  if (new Set(groups).size !== groups.length) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const known = new Set(groups);
  const connections: Record<string, string[]> = {};
  for (const [key, assigned] of Object.entries(parsed.data.connections)) {
    const [vault, name] = connectionKeyParts(key);
    validateName(vault);
    validateName(name);
    if (new Set(assigned).size !== assigned.length) {
      throw new BlindDropError("INVALID_INPUT");
    }
    for (const group of assigned) {
      if (!known.has(group)) throw new BlindDropError("INVALID_INPUT");
    }
    connections[key] = [...assigned];
  }
  return { version: 1, groups: [...groups], connections };
}

/** The single global sidecar; a missing one means no groups yet. */
export function readGroups(configDir: string): GroupsMeta {
  const path = groupsPath(configDir);
  assertPath(path);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { version: 1, groups: [], connections: {} };
  }
  try {
    return validateGroups(JSON.parse(text));
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }
}

export function writeGroups(configDir: string, meta: unknown): GroupsMeta {
  const validated = validateGroups(meta);
  writeOwnerFile(groupsPath(configDir), `${JSON.stringify(validated)}\n`);
  return validated;
}

/** Reads the last {@link MAX_LOG_TAIL_BYTES} of the log, newest event first. */
function tailEvents(logPath: string): UseEventRecord[] {
  assertPath(logPath);
  let descriptor: number | undefined;
  let text: string;
  let truncated: boolean;
  try {
    descriptor = openSync(logPath, "r");
    const size = fstatSync(descriptor).size;
    const start = size > MAX_LOG_TAIL_BYTES ? size - MAX_LOG_TAIL_BYTES : 0;
    const length = size - start;
    const buffer = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const chunk = readSync(descriptor, buffer, read, length - read, start + read);
      if (chunk === 0) break;
      read += chunk;
    }
    text = buffer.subarray(0, read).toString("utf8");
    truncated = start > 0;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return [];
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The read has already produced its result or its safe error.
      }
    }
  }

  const lines = text.split("\n");
  // A tail that started mid-file cut through its first line.
  const first = truncated ? 1 : 0;
  const events: UseEventRecord[] = [];
  for (let index = lines.length - 1; index >= first; index -= 1) {
    const line = lines[index];
    if (line.length === 0) continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      continue;
    }
    const parsed = UseEventSchema.safeParse(value);
    if (parsed.success) events.push({ ...parsed.data, httpStatus: parsed.data.httpStatus ?? null });
  }
  return events;
}

export function readActivity(
  logPath: string,
  options: { connection?: string; limit: number },
): UseEventRecord[] {
  if (!Number.isSafeInteger(options.limit) || options.limit < 1 ||
      options.limit > MAX_ACTIVITY_LIMIT) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const events = options.connection === undefined
    ? tailEvents(logPath)
    : tailEvents(logPath).filter((event) => event.connection === options.connection);
  return events.slice(0, options.limit);
}

/** The newest event per connection, for the list's `lastUsed`/`lastOutcome`. */
export function lastUse(logPath: string): Map<string, { timestamp: string; outcome: string }> {
  const latest = new Map<string, { timestamp: string; outcome: string }>();
  for (const event of tailEvents(logPath)) {
    if (event.connection === null || latest.has(event.connection)) continue;
    latest.set(event.connection, { timestamp: event.timestamp, outcome: event.outcome });
  }
  return latest;
}

/** A running session keeps its own append descriptor; that is accepted. */
export function clearActivity(logPath: string): void {
  assertPath(logPath);
  try {
    truncateSync(logPath, 0);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw new BlindDropError("STORAGE_ERROR");
  }
}

/** Copies the encrypted archive bytes; it never decrypts and never overwrites. */
export function backupVault(vaultPath: string, targetPath: string): { path: string; size: number } {
  assertPath(vaultPath);
  assertPath(targetPath);

  let archive: Buffer;
  try {
    archive = readFileSync(vaultPath);
  } catch (error) {
    if (errorCode(error) === "ENOENT") throw new BlindDropError("VAULT_NOT_FOUND");
    throw new BlindDropError("STORAGE_ERROR");
  }

  let descriptor: number | undefined;
  let created = false;
  let published = false;
  try {
    descriptor = openSync(targetPath, "wx", 0o600);
    created = true;
    writeFileSync(descriptor, archive);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    published = true;
  } catch (error) {
    if (errorCode(error) === "EEXIST") throw new BlindDropError("VAULT_EXISTS");
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the original safe error above.
      }
    }
    if (created && !published) {
      try {
        unlinkSync(targetPath);
      } catch {
        // A partial copy that cannot be removed is reported by its own error.
      }
    }
  }

  return { path: targetPath, size: archive.length };
}
