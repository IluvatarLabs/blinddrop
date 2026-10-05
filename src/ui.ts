// The owner's own loopback server: one page and a small JSON API for the
// operations the owner performs by hand. It is a separate listener with a
// separate token from the agent session in http.ts, and the two never
// authorize each other. Terminal input and browser launching stay in the CLI
// so a desktop host can import this module directly.
//
// v0.5.1: the server holds several vaults at once, each independently lockable,
// each passphrase in memory only. The agent session is implicit and spans ALL
// connections whose secrets are unlocked: unlocking or creating a vault, every
// owner write to any archive, and locking a vault all restart it from the new
// snapshot; locking every vault or closing ends it.

import { connectionsPath, migrateConnections, readConnections, writeConnections } from "./connection-store.js";
import { isUtf8 } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { basename, dirname, join, resolve } from "node:path";

import { z } from "zod";

import { BlindDropError, publicError, type ErrorCode } from "./errors.js";
import { errorStatus, startHttpSession, type HttpSession } from "./http.js";
import {
  activityLogPath,
  backupVault,
  clearActivity,
  DEFAULT_ACTIVITY_LIMIT,
  lastUse,
  readActivity,
  readGroups,
  readSettings,
  writeGroups,
  writeSettings,
} from "./owner-files.js";
import {
  connectionResolvable,
  connectionSecretRefs,
  DEFAULT_FIELD_ID,
  DEFAULT_VAULT_NAME,
  mapConnectionReferences,
  parseSecretRef,
  resolveValue,
  qualifyConnection,
} from "./references.js";
import { deleteSessionFile, writeSessionFile } from "./session-file.js";
import { createBrokerSession, type VaultUnlock } from "./session.js";
import { backupSetup, restoreSetup } from "./setup-backup.js";
import type { Connection, VaultData } from "./types.js";
import {
  changePassphrase,
  disableSecret,
  enableSecret,
  importEnvSecrets,
  removeSecret,
  removeSecretField,
  setConnectionQualified,
  setSecretTyped,
} from "./vault-admin.js";
import {
  createVault,
  defaultVaultPath,
  loadRegistry,
  loadStoredRegistry,
  loadVault,
  saveRegistry,
  validateName,
  validateConnection,
} from "./vault.js";

/** A pasted PEM or certificate has to fit in one owner request. */
const MAX_REQUEST_BYTES = 1_048_576;
/** The maximum the agent listener accepts; the session renews itself on expiry. */
const SESSION_TTL_SECONDS = 86_400;
const CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'unsafe-inline'; " +
  "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; form-action 'none'; " +
  "base-uri 'none'; frame-ancestors 'none'";
const BEARER = /^Bearer ([A-Za-z0-9_-]+)$/i;
const PAGE = readFileSync(new URL("../ui/index.html", import.meta.url));
/** One version for the CLI banner and the page; the package file is the source. */
export const VERSION = z
  .object({ version: z.string() })
  .parse(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")))
  .version;

const FieldInputSchema = z
  .object({
    value: z.string().optional(),
    label: z.string(),
    masked: z.boolean(),
    multiline: z.boolean(),
  })
  .strict();
const TypedSecretInputSchema = z
  .object({ type: z.string(), fields: z.record(z.string(), FieldInputSchema) })
  .strict();

const EmptyBody = z.object({}).strict();
const VaultCreateBody = z.object({ name: z.string(), path: z.string(), passphrase: z.string() }).strict();
const VaultOpenBody = z.object({ name: z.string(), path: z.string() }).strict();
const VaultUnlockBody = z.object({ name: z.string(), passphrase: z.string() }).strict();
const VaultNameBody = z.object({ name: z.string() }).strict();
const SecretSetBody = z
  .object({
    vault: z.string(),
    name: z.string(),
    type: z.string(),
    fields: z.record(z.string(), FieldInputSchema),
  })
  .strict();
const SecretFieldRemoveBody = z.object({ vault: z.string(), name: z.string(), fieldId: z.string() }).strict();
const SecretNameBody = z.object({ vault: z.string(), name: z.string() }).strict();
const ImportEnvBody = z.object({ vault: z.string(), secrets: z.record(z.string(), z.string()) }).strict();
const ConnectionSetBody = z
  .object({
    vault: z.string().default("default"),
    name: z.string(),
    origin: z.string(),
    auth: z.unknown(),
    allowPrivate: z.boolean().optional(),
    tls: z.unknown().optional(),
  })
  .strict();
const ConnectionImportBody = z
  .object({
    vault: z.string().default("default"),
    name: z.string(),
    definition: z.unknown(),
    secrets: z.record(z.string(), TypedSecretInputSchema).optional(),
  })
  .strict();
const ConnectionNameBody = z.object({ vault: z.string().optional(), name: z.string() }).strict();
const GroupsBody = z
  .object({
    groups: z.array(z.string()),
    connections: z.record(z.string(), z.array(z.string())),
  })
  .strict();
const BackupBody = z.object({ vault: z.string(), path: z.string() }).strict();
const SetupPathBody = z.object({ path: z.string() }).strict();
const PasswdBody = z.object({ vault: z.string(), current: z.string(), new: z.string() }).strict();

export interface OwnerUiOptions {
  /** Register an explicitly selected archive before opening the owner page. */
  vaultPath?: string;
  port?: number;
  sessionPort?: number;
  sessionFile?: string;
  configDir?: string;
}

export interface OwnerUi {
  url: string;
  token: string;
  launchUrl: string;
  closed: Promise<void>;
  lockAll(): Promise<void>;
  close(): Promise<void>;
}

interface ActiveSession {
  http: HttpSession;
  filePath?: string;
}

interface RegistryEntry {
  name: string;
  path: string;
}

function values(request: IncomingMessage, name: string): string[] {
  const result: string[] = [];
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i].toLowerCase() === name) result.push(request.rawHeaders[i + 1]);
  }
  return result;
}

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return parsed.data;
}

function boundedPort(port: number | undefined, fallback: number): number {
  const value = port ?? fallback;
  if (!Number.isSafeInteger(value) || value < 0 || value > 65_535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return value;
}

function assertVaultPath(path: unknown): string {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return path;
}

function byName(left: [string, unknown], right: [string, unknown]): number {
  return left[0].localeCompare(right[0]);
}

/**
 * Throwing from a Readable async iterator destroys the request/socket. Keep the
 * response alive long enough to return a static 400/413 instead.
 */
function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (error?: unknown) => {
      request.pause();
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onError);
      if (error !== undefined) reject(error);
      else resolve(Buffer.concat(chunks, size));
    };
    const onData = (value: Buffer) => {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) finish(new BlindDropError("REQUEST_TOO_LARGE"));
      else chunks.push(chunk);
    };
    const onEnd = () => finish();
    const onError = () => finish(new BlindDropError("INVALID_INPUT"));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onError);
  });
}

function send(response: ServerResponse, status: number, value: unknown): void {
  if (response.destroyed || response.headersSent) return;
  const body = Buffer.from(JSON.stringify(value), "utf8");
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": String(body.length)
  });
  response.end(body);
}

function sendError(response: ServerResponse, error: unknown): void {
  if (response.destroyed) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const safe = publicError(error);
  send(response, errorStatus(safe.code), { error: safe });
}

/** One owner-facing loopback server. No process-global lifecycle. */
export async function startOwnerUi(options: OwnerUiOptions): Promise<OwnerUi> {
  const port = boundedPort(options.port, 0);
  const sessionPortOverride = options.sessionPort === undefined
    ? undefined
    : boundedPort(options.sessionPort, 0);
  const defaultPath = defaultVaultPath();
  const configDir = options.configDir ?? dirname(defaultPath);
  const connectionFile = connectionsPath(configDir);
  const sessionFilePath = options.sessionFile ?? join(configDir, "session.json");
  // Activity is global; the running session logs to the default vault's log.
  const logPath = activityLogPath(defaultPath);

  if (options.vaultPath && existsSync(options.vaultPath)) {
    const entries = loadStoredRegistry(configDir).vaults;
    if (!entries.some(entry => resolve(entry.path) === resolve(options.vaultPath!))) {
      const firstRegistration = entries.length === 0;
      let name = firstRegistration || resolve(options.vaultPath) === resolve(defaultPath)
        ? DEFAULT_VAULT_NAME
        : basename(options.vaultPath, ".enc").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 50).replace(/^[._-]+|[._-]+$/g, "") || "vault";
      const base = name;
      for (let i = 2; entries.some(entry => entry.name === name && name !== DEFAULT_VAULT_NAME); i++) name = `${base}-${i}`;
      registerVault(name, options.vaultPath);
    }
  }

  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token, "utf8");
  // Vault name -> its held passphrase. Only unlocked vaults appear; passphrases
  // live only here and in the session closure, never on disk or in a response.
  const passphrases = new Map<string, Buffer>();
  let active: ActiveSession | undefined;
  let sessionError: ErrorCode | null = null;
  let syncChain: Promise<void> = Promise.resolve();
  let authority = "";
  let pageOrigin = "";
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });

  function holdVault(name: string, value: string): void {
    passphrases.get(name)?.fill(0);
    passphrases.set(name, Buffer.from(value, "utf8"));
  }

  function releaseVault(name: string): void {
    passphrases.get(name)?.fill(0);
    passphrases.delete(name);
  }

  function releaseAll(): void {
    for (const buffer of passphrases.values()) buffer.fill(0);
    passphrases.clear();
  }

  function registryEntries(): RegistryEntry[] {
    return loadRegistry(configDir).vaults;
  }

  function requireEntry(name: string): RegistryEntry {
    validateName(name);
    const entry = registryEntries().find(item => item.name === name);
    if (entry === undefined) throw new BlindDropError("VAULT_NOT_FOUND");
    return entry;
  }

  /** The path and held passphrase of a vault that must be unlocked to write it. */
  function requireUnlocked(name: string): { path: string; passphrase: string } {
    const entry = requireEntry(name);
    const buffer = passphrases.get(name);
    if (buffer === undefined) throw new BlindDropError("ACCESS_DENIED");
    return { path: entry.path, passphrase: buffer.toString("utf8") };
  }

  /** Operational owner data is available only after at least one vault unlock. */
  function requireAnyUnlocked(): void {
    if (passphrases.size === 0) throw new BlindDropError("ACCESS_DENIED");
  }

  /** `default` names the default path and only that; no other name may claim it. */
  function assertVaultReservation(name: string, path: string): void {
    validateName(name);
    assertVaultPath(path);
    const collision = loadStoredRegistry(configDir).vaults
      .find(entry => resolve(entry.path) === resolve(path) && entry.name !== name);
    if (collision) throw new BlindDropError("INVALID_INPUT");
  }

  function registerVault(name: string, path: string): void {
    const registry = loadStoredRegistry(configDir);
    const existing = registry.vaults.find(item => item.name === name);
    if (existing !== undefined) {
      if (resolve(existing.path) === resolve(path)) return;
      if (name !== DEFAULT_VAULT_NAME || existsSync(existing.path)) throw new BlindDropError("INVALID_INPUT");
      existing.path = path;
    } else registry.vaults.push({ name, path });
    saveRegistry(registry, configDir);
  }

  function unregisterVault(name: string): void {
    const registry = loadStoredRegistry(configDir);
    saveRegistry({ version: 1, vaults: registry.vaults.filter(item => item.name !== name) }, configDir);
  }

  /** Every unlocked vault as a session unlock, in registry order (default first). */
  function unlockedList(): VaultUnlock[] {
    const list: VaultUnlock[] = [];
    for (const entry of registryEntries()) {
      const buffer = passphrases.get(entry.name);
      if (buffer !== undefined) {
        list.push({ name: entry.name, path: entry.path, passphrase: buffer.toString("utf8") });
      }
    }
    return list;
  }

  /** The loaded data of every unlocked vault, keyed by vault name. */
  function unlockedSnapshot(): Map<string, VaultData> {
    const snapshot = new Map<string, VaultData>();
    for (const entry of registryEntries()) {
      const buffer = passphrases.get(entry.name);
      if (buffer !== undefined) {
        snapshot.set(entry.name, loadVault(entry.path, buffer.toString("utf8")));
      }
    }
    return snapshot;
  }

  /**
   * The eligible connections across ALL unlocked vaults: enabled, and every
   * referenced field resolves in the unlocked set. A connection whose secrets
   * span a locked vault is not eligible, so locking a vault drops exactly the
   * connections that needed it. Names are the session's address space, so the
   * union is deduplicated by name.
   */
  function eligibleConnections(snapshot: Map<string, VaultData>, connections: Record<string, Connection>): string[] {
    return Object.entries(connections).filter(([, connection]) =>
      connection.enabled && connectionResolvable(connection, snapshot)
    ).map(([name]) => name).sort();
  }

  function migrateEntry(name: string, path: string, passphrase: string): void {
    migrateConnections(path, passphrase, { path: connectionFile, vaultName: name, configDir });
  }

  function storeConnection(input: z.infer<typeof ConnectionImportBody>): void {
    const definition = validateConnection(input.definition);
    validateName(input.name);
    if (input.secrets !== undefined && Object.keys(input.secrets).length > 0) {
      const { path, passphrase } = requireUnlocked(input.vault);
      setConnectionQualified(path, passphrase, input.vault, input.name, definition, input.secrets,
        { path: connectionFile, vaultName: input.vault, configDir });
    } else {
      const connections = readConnections(connectionFile);
      const vault = unlockedSnapshot().get(input.vault);
      let needsFieldMetadata = false;
      mapConnectionReferences(definition, reference => {
        needsFieldMetadata ||= parseSecretRef(reference, input.vault).field === undefined;
        return reference;
      });
      if (vault === undefined && needsFieldMetadata) requireUnlocked(input.vault);
      connections[input.name] = qualifyConnection(vault, input.vault, definition);
      writeConnections(connectionFile, connections);
    }
  }

  function editConnection(name: string, enabled?: boolean): void {
    validateName(name);
    const connections = readConnections(connectionFile);
    if (!Object.hasOwn(connections, name)) throw new BlindDropError("CONNECTION_NOT_FOUND");
    if (enabled === undefined) delete connections[name];
    else connections[name].enabled = enabled;
    writeConnections(connectionFile, connections);
  }

  function forget(entry: ActiveSession): void {
    if (active === entry) active = undefined;
    if (entry.filePath !== undefined) {
      const path = entry.filePath;
      entry.filePath = undefined;
      try {
        deleteSessionFile(path);
      } catch {
        // Best effort: a stale file carries a dead token that readers reject on expiry.
      }
    }
  }

  async function stopActiveSession(): Promise<void> {
    const previous = active;
    if (previous !== undefined) {
      // Forget first: the entry's `closed` handler must not treat a deliberate
      // stop as an expiry and queue another sync behind this one.
      forget(previous);
      try {
        await previous.http.close();
      } catch {
        // A listener that will not close is already unusable to an agent.
      }
    }
  }

  /**
   * The single owner of `active`. Steps: stop what runs, decide whether a
   * session may run at all, start one from the current unlocked snapshot,
   * publish it, and renew it when it expires while any vault stays unlocked.
   */
  async function runSync(): Promise<void> {
    await stopActiveSession();
    if (stopped || passphrases.size === 0) {
      sessionError = null;
      return;
    }

    let entry: ActiveSession | undefined;
    try {
      const settings = readSettings(configDir);
      const unlocks = unlockedList();
      const snapshot = new Map<string, VaultData>();
      for (const unlock of unlocks) {
        snapshot.set(unlock.name, loadVault(unlock.path, unlock.passphrase));
      }
      const connections = readConnections(connectionFile);
      const eligible = eligibleConnections(snapshot, connections);
      if (eligible.length === 0) {
        sessionError = null;
        return;
      }
      const session = createBrokerSession(unlocks, eligible, SESSION_TTL_SECONDS, { connections, logPath });
      let http: HttpSession;
      try {
        http = await startHttpSession(session.broker, session.expiresAt, {
          port: sessionPortOverride ?? settings.sessionPort
        });
      } catch (error) {
        session.broker.close();
        throw error;
      }
      entry = { http };
      active = entry;
      void http.closed.then(() => {
        const expired = active === entry;
        forget(entry!);
        if (expired && !stopped && passphrases.size > 0) void syncSession();
      });
      if (settings.sessionFile) {
        writeSessionFile(sessionFilePath, {
          mcpUrl: http.mcpUrl,
          token: http.token,
          expiresAt: http.expiresAt,
          connections: http.connections
        });
        entry.filePath = sessionFilePath;
      }
      sessionError = null;
    } catch (error) {
      if (entry !== undefined) {
        forget(entry);
        try {
          await entry.http.close();
        } catch {
          // The start already failed; report that code, not the cleanup's.
        }
      }
      // The vaults stay unlocked for editing; the page reports the reason.
      sessionError = publicError(error).code;
    }
  }

  /** Overlapping owner/session operations run one after another. */
  function serializeOwner<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = syncChain.then(operation, operation);
    syncChain = result.then(() => undefined, () => undefined);
    return result;
  }

  function syncSession(): Promise<void> {
    return serializeOwner(runSync);
  }

  /** Stop agent traffic while a bounded synchronous snapshot reads owner files. */
  function withSessionPaused<T>(operation: () => T): Promise<T> {
    return serializeOwner(async () => {
      await stopActiveSession();
      try {
        return operation();
      } finally {
        if (!stopped) await runSync();
      }
    });
  }

  function verify(supplied: string): void {
    const bytes = Buffer.from(supplied, "utf8");
    if (bytes.length !== tokenBytes.length || !timingSafeEqual(bytes, tokenBytes)) {
      throw new BlindDropError("ACCESS_DENIED");
    }
  }

  function state(): unknown {
    return {
      version: VERSION,
      configDir,
      sessionFilePath,
      logPath,
      vaults: registryEntries().map(entry => ({
        name: entry.name,
        path: entry.path,
        exists: existsSync(entry.path),
        unlocked: passphrases.has(entry.name)
      })),
      session: active === undefined ? null : {
        mcpUrl: active.http.mcpUrl,
        connections: active.http.connections,
        expiresAt: active.http.expiresAt,
        sessionFile: active.filePath ?? null
      },
      sessionError
    };
  }

  /** Convenience state only: an unusable config directory never blocks the vault. */
  function recordVault(path: string): void {
    try {
      const current = readSettings(configDir);
      writeSettings(configDir, {
        lastVault: path,
        recentVaults: [path, ...current.recentVaults.filter(entry => entry !== path)].slice(0, 10)
      });
    } catch {
      // The vault is open; settings are a convenience the page can retry.
    }
  }

  function listing(): unknown {
    const snapshot = unlockedSnapshot();
    const groups = readGroups(configDir);
    const latest = lastUse(logPath);
    const running = active?.http.connections ?? {};

    const definitions = readConnections(connectionFile);
    const usedBy = new Map<string, Set<string>>();
    for (const [name, connection] of Object.entries(definitions)) {
      for (const ref of connectionSecretRefs(connection)) {
        const key = `${ref.vault}#${ref.secret}`;
        const holders = usedBy.get(key) ?? new Set<string>();
        holders.add(name);
        usedBy.set(key, holders);
      }
    }

    const vaults: unknown[] = [];
    const connections: unknown[] = [];
    for (const entry of registryEntries()) {
      const vault = snapshot.get(entry.name);
      if (vault === undefined) continue;
      vaults.push({
        name: entry.name,
        secrets: Object.entries(vault.secrets).sort(byName).map(([name, item]) => ({
          name,
          type: item.type,
          enabled: item.enabled,
          usedBy: [...(usedBy.get(`${entry.name}#${name}`) ?? [])].sort((left, right) => left.localeCompare(right)),
          fields: Object.entries(item.fields).map(([id, field]) => ({
            id,
            label: field.label,
            masked: field.masked,
            multiline: field.multiline,
            set: field.value.length > 0
          }))
        }))
      });
    }
    for (const [name, item] of Object.entries(definitions).sort(byName)) {
      const missingRefs = connectionSecretRefs(item).filter(ref => resolveValue(snapshot, ref) === undefined)
        .map(ref => `${ref.vault}#${ref.secret}#${ref.field ?? DEFAULT_FIELD_ID}`);
      const used = latest.get(name);
      connections.push({ name, origin: item.origin, authType: item.auth.type, definition: item,
        groups: Object.hasOwn(groups.connections, name) ? groups.connections[name] : [],
        missingRefs, inSession: Object.hasOwn(running, name),
        lastUsed: used?.timestamp ?? null, lastOutcome: used?.outcome ?? null });
    }
    return { vaults, connections, groups: groups.groups };
  }

  function activityQuery(url: URL): { connection?: string; limit: number } {
    const connections = url.searchParams.getAll("connection");
    const limits = url.searchParams.getAll("limit");
    if (connections.length > 1 || limits.length > 1) {
      throw new BlindDropError("INVALID_INPUT");
    }
    let limit = DEFAULT_ACTIVITY_LIMIT;
    if (limits.length === 1) {
      if (!/^[0-9]{1,4}$/.test(limits[0])) throw new BlindDropError("INVALID_INPUT");
      limit = Number(limits[0]);
    }
    if (connections.length === 0) return { limit };
    validateName(connections[0]);
    return { connection: connections[0], limit };
  }

  /** Every archive write restarts the session, so agents see the new snapshot. */
  async function written(): Promise<{ ok: true }> {
    await syncSession();
    return { ok: true };
  }

  type Handler = (body: unknown, url: URL) => unknown | Promise<unknown>;
  const routes = new Map<string, Partial<Record<"GET" | "POST", Handler>>>([
    ["/api/state", { GET: () => state() }],
    ["/api/list", { GET: () => { requireAnyUnlocked(); return listing(); } }],
    ["/api/vault/create", {
      POST: async body => {
        const input = parse(VaultCreateBody, body);
        assertVaultReservation(input.name, input.path);
        const existing = registryEntries().find(entry => entry.name === input.name);
        if (existing && resolve(existing.path) !== resolve(input.path) && existsSync(existing.path)) throw new BlindDropError("INVALID_INPUT");
        createVault(input.path, input.passphrase);
        registerVault(input.name, input.path);
        holdVault(input.name, input.passphrase);
        await syncSession();
        recordVault(input.path);
        return state();
      }
    }],
    ["/api/vault/open", {
      POST: async body => {
        const input = parse(VaultOpenBody, body);
        assertVaultReservation(input.name, input.path);
        if (!existsSync(input.path)) throw new BlindDropError("VAULT_NOT_FOUND");
        registerVault(input.name, input.path);
        await syncSession();
        return state();
      }
    }],
    ["/api/vault/unlock", {
      POST: async body => {
        const input = parse(VaultUnlockBody, body);
        const entry = requireEntry(input.name);
        migrateEntry(input.name, entry.path, input.passphrase);
        holdVault(input.name, input.passphrase);
        await syncSession();
        recordVault(entry.path);
        return state();
      }
    }],
    ["/api/vault/lock", {
      POST: async body => {
        const input = parse(VaultNameBody, body);
        validateName(input.name);
        releaseVault(input.name);
        await syncSession();
        return state();
      }
    }],
    ["/api/vault/remove", {
      POST: async body => {
        const input = parse(VaultNameBody, body);
        validateName(input.name);
        if (input.name === DEFAULT_VAULT_NAME) throw new BlindDropError("INVALID_INPUT");
        requireEntry(input.name);
        releaseVault(input.name);
        unregisterVault(input.name);
        await syncSession();
        return state();
      }
    }],
    ["/api/activity", {
      GET: (_body, url) => {
        requireAnyUnlocked();
        return { events: readActivity(logPath, activityQuery(url)) };
      }
    }],
    ["/api/activity/clear", {
      POST: body => {
        requireAnyUnlocked();
        parse(EmptyBody, body);
        clearActivity(logPath);
        return { ok: true };
      }
    }],
    ["/api/secret/set", {
      POST: body => {
        const input = parse(SecretSetBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        setSecretTyped(path, passphrase, input.name, input.type, input.fields);
        return written();
      }
    }],
    ["/api/secret/field/remove", {
      POST: body => {
        const input = parse(SecretFieldRemoveBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        removeSecretField(path, passphrase, input.name, input.fieldId);
        return written();
      }
    }],
    ["/api/secret/enable", {
      POST: body => {
        const input = parse(SecretNameBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        enableSecret(path, passphrase, input.name);
        return written();
      }
    }],
    ["/api/secret/disable", {
      POST: body => {
        const input = parse(SecretNameBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        disableSecret(path, passphrase, input.name);
        return written();
      }
    }],
    ["/api/secret/remove", {
      POST: body => {
        const input = parse(SecretNameBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        removeSecret(path, passphrase, input.name);
        return written();
      }
    }],
    ["/api/secret/import-env", {
      POST: body => {
        const input = parse(ImportEnvBody, body);
        const { path, passphrase } = requireUnlocked(input.vault);
        importEnvSecrets(path, passphrase, input.secrets);
        return written();
      }
    }],
    ["/api/connection/set", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(ConnectionSetBody, body);
        const definition = {
          origin: input.origin,
          auth: input.auth,
          allowPrivate: input.allowPrivate === true,
          enabled: true,
          ...(input.tls === undefined ? {} : { tls: input.tls })
        };
        storeConnection({ vault: input.vault, name: input.name, definition });
        return written();
      }
    }],
    ["/api/connection/import", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(ConnectionImportBody, body);
        storeConnection(input);
        return written();
      }
    }],
    ["/api/connection/enable", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(ConnectionNameBody, body);
        editConnection(input.name, true);
        return written();
      }
    }],
    ["/api/connection/disable", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(ConnectionNameBody, body);
        editConnection(input.name, false);
        return written();
      }
    }],
    ["/api/connection/remove", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(ConnectionNameBody, body);
        editConnection(input.name, undefined);
        const key = input.name;
        const groups = readGroups(configDir);
        if (Object.hasOwn(groups.connections, key)) {
          const retained = Object.fromEntries(
            Object.entries(groups.connections).filter(([entry]) => entry !== key)
          );
          writeGroups(configDir, { groups: groups.groups, connections: retained });
        }
        return written();
      }
    }],
    ["/api/groups", {
      POST: body => {
        requireAnyUnlocked();
        const input = parse(GroupsBody, body);
        const definitions = readConnections(connectionFile);
        for (const key of Object.keys(input.connections)) {
          if (!Object.hasOwn(definitions, key)) throw new BlindDropError("INVALID_INPUT");
        }
        const meta = writeGroups(configDir, input);
        // Agents never see groups, so no session restart.
        return { groups: meta.groups, connections: meta.connections };
      }
    }],
    ["/api/settings", {
      GET: () => readSettings(configDir),
      POST: async body => {
        const before = readSettings(configDir);
        const after = writeSettings(configDir, body);
        if (passphrases.size > 0 && (before.sessionPort !== after.sessionPort ||
            before.sessionFile !== after.sessionFile)) {
          await syncSession();
        }
        return after;
      }
    }],
    ["/api/vault/backup", {
      POST: body => {
        const input = parse(BackupBody, body);
        const { path } = requireUnlocked(input.vault);
        const copied = backupVault(path, input.path);
        const lastBackupAt = new Date().toISOString();
        writeSettings(configDir, { lastBackupAt });
        return { ...copied, lastBackupAt };
      }
    }],
    ["/api/setup/backup", {
      POST: body => {
        const input = parse(SetupPathBody, body);
        return withSessionPaused(() => backupSetup(configDir, input.path));
      }
    }],
    ["/api/setup/restore", {
      POST: body => {
        const input = parse(SetupPathBody, body);
        if (passphrases.size > 0 || active !== undefined ||
            registryEntries().some(entry => existsSync(entry.path))) {
          throw new BlindDropError("VAULT_EXISTS");
        }
        return serializeOwner(() => {
          if (passphrases.size > 0 || active !== undefined ||
              registryEntries().some(entry => existsSync(entry.path))) {
            throw new BlindDropError("VAULT_EXISTS");
          }
          restoreSetup(configDir, input.path);
          return state();
        });
      }
    }],
    ["/api/passwd", {
      POST: async body => {
        const input = parse(PasswdBody, body);
        const buffer = passphrases.get(input.vault);
        if (buffer === undefined) throw new BlindDropError("ACCESS_DENIED");
        const entry = requireEntry(input.vault);
        const supplied = Buffer.from(input.current, "utf8");
        try {
          if (supplied.length !== buffer.length || !timingSafeEqual(supplied, buffer)) {
            throw new BlindDropError("UNLOCK_FAILED");
          }
        } finally {
          supplied.fill(0);
        }
        changePassphrase(entry.path, input.current, input.new);
        holdVault(input.vault, input.new);
        return written();
      }
    }],
    ["/api/shutdown", {
      POST: body => {
        parse(EmptyBody, body);
        return { ok: true };
      }
    }]
  ]);

  const server = createServer((request, response) => {
    void handle(request, response).catch(error => sendError(response, error));
  });
  // The ordinary Node parser rejects malformed framing. Never echo its diagnostics.
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("connect", (_request, socket) => socket.destroy());
  server.on("upgrade", (_request, socket) => socket.destroy());

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (stopped) throw new BlindDropError("SESSION_CLOSED");
    response.on("error", () => undefined);
    request.on("error", () => undefined);

    const hosts = values(request, "host");
    if (hosts.length !== 1 || hosts[0] !== authority) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    const origins = values(request, "origin");
    if (origins.length > 1 || (origins.length === 1 && origins[0] !== pageOrigin)) {
      throw new BlindDropError("ACCESS_DENIED");
    }
    const fetchSites = values(request, "sec-fetch-site");
    if (fetchSites.length > 1 ||
        (fetchSites.length === 1 && fetchSites[0] !== "same-origin" && fetchSites[0] !== "none")) {
      throw new BlindDropError("ACCESS_DENIED");
    }

    const target = request.url ?? "";
    if (!target.startsWith("/") || target.startsWith("//") || target.includes("#")) {
      throw new BlindDropError("INVALID_INPUT");
    }
    let url: URL;
    try {
      url = new URL(target, pageOrigin);
    } catch {
      throw new BlindDropError("INVALID_INPUT");
    }
    const path = url.pathname;

    const bearer = values(request, "authorization");
    const query = url.searchParams.getAll("t");
    if (path === "/") {
      if (bearer.length !== 0 || query.length !== 1) throw new BlindDropError("ACCESS_DENIED");
      verify(query[0]);
    } else {
      if (query.length !== 0 || bearer.length !== 1) throw new BlindDropError("ACCESS_DENIED");
      verify(BEARER.exec(bearer[0])?.[1] ?? "");
    }

    const verb = request.method === "GET" || request.method === "POST" ? request.method : undefined;
    const route = path === "/" || verb === undefined ? undefined : routes.get(path)?.[verb];
    if (path === "/" ? request.method !== "GET" : route === undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }

    const raw = await readBody(request);
    let body: unknown;
    if (request.method === "POST") {
      const contentType = values(request, "content-type");
      if (contentType.length !== 1 || !contentType[0].startsWith("application/json")) {
        throw new BlindDropError("INVALID_INPUT");
      }
      if (!isUtf8(raw)) throw new BlindDropError("INVALID_INPUT");
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new BlindDropError("INVALID_INPUT");
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        throw new BlindDropError("INVALID_INPUT");
      }
    }

    if (route === undefined) {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy": CONTENT_SECURITY_POLICY,
        "content-length": String(PAGE.length)
      });
      response.end(PAGE);
      return;
    }

    if (path === "/api/shutdown") {
      response.once("close", () => { void close(); });
    }
    send(response, 200, await route(body, url));
  }

  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    closePromise = (async () => {
      releaseAll();
      await syncSession();
      tokenBytes.fill(0);
      const socketClosed = new Promise<void>(resolve => server.close(() => resolve()));
      server.closeAllConnections();
      await socketClosed;
      finish();
    })();
    return closePromise;
  }

  async function lockAll(): Promise<void> {
    releaseAll();
    await syncSession();
  }

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = () => reject(new BlindDropError("PORT_UNAVAILABLE"));
      server.once("error", onError);
      server.listen(port, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    });
  } catch (error) {
    await close();
    throw error;
  }
  server.on("error", () => { void close(); });
  const address = server.address();
  if (!address || typeof address === "string") {
    await close();
    throw new BlindDropError("INTERNAL_ERROR");
  }
  authority = `127.0.0.1:${address.port}`;
  pageOrigin = `http://${authority}`;
  return { url: `${pageOrigin}/`, token, launchUrl: `${pageOrigin}/?t=${token}`, closed, lockAll, close };
}
