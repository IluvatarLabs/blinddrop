// The owner's own loopback server: one page and a small JSON API for the
// operations the owner performs by hand. It is a separate listener with a
// separate token from the agent session in http.ts, and the two never
// authorize each other. Terminal input and page launching stay in the CLI so
// a desktop host can import this module directly; owner OAuth consent opens
// the system browser through the shared oauth-login launcher.
//
// v0.5.1: the server holds several vaults at once, each independently lockable,
// each passphrase in memory only. 0.6.2: the agent endpoint is one listener for
// the runtime's lifetime, started before any unlock. Unlocks, locks, owner
// writes, the setup-backup pause and renewal change only what it authorizes: a
// broker over every connection whose secrets are unlocked, plus the locked
// connections whose calls ask the owner to unlock. Closing the runtime ends it.
// The Mac app can also supply Electron's safeStorage and Touch ID so a vault
// the owner marks unlocks with a touch or without asking; its passphrase is
// then also kept sealed in quick-unlock.ts's file, never in a response.

import { connectionsPath, migrateConnections, readConnections, writeConnections } from "./connection-store.js";
import { isUtf8 } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { basename, dirname, join, resolve } from "node:path";
import { parseEnv } from "node:util";

import { z } from "zod";

import { DEFAULT_LIMITS } from "./broker.js";
import { BlindDropError, publicError, type ErrorCode } from "./errors.js";
import { errorStatus, startAgentEndpoint, type AgentAccess, type AgentEndpoint } from "./http.js";
import { obtainRefreshGrant, openSystemBrowser, type RefreshGrantRequest } from "./oauth-login.js";
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
  type OwnerSettings,
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
import {
  quickUnlockEntry,
  readQuickUnlock,
  removeQuickUnlock,
  saveQuickUnlock,
  type QuickUnlockEntry,
  type QuickUnlockMode,
} from "./quick-unlock.js";
import { connectionGuidance, RECIPES } from "./recipes.js";
import { deleteSessionFile, writeSessionFile } from "./session-file.js";
import { createBrokerSession, type VaultUnlock } from "./session.js";
import { backupSetup, restoreSetup } from "./setup-backup.js";
import type { Connection, ConnectionMetadata, Field, RequestInput, SecretRef, VaultData } from "./types.js";
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
  saveVault,
  validateName,
  validateConnection,
  validateVaultArchive,
} from "./vault.js";

/** A pasted PEM or certificate has to fit in one owner request. */
const MAX_REQUEST_BYTES = 1_048_576;
/** The agent token's lifetime, the existing 24-hour limit. */
const SESSION_TTL_SECONDS = 86_400;
/**
 * A connection test's one-off session outlives the broker's request timeout,
 * so a slow provider answers TIMEOUT rather than SESSION_EXPIRED.
 */
const TEST_TTL_SECONDS = DEFAULT_LIMITS.timeoutMs / 1000 + 5;
/**
 * Renewal runs this long before the token expires, so the new token is in
 * the session file before the old one stops working.
 */
const RENEWAL_LEAD_MS = 60_000;
/** An agent's unlock ask counts for this long; agents repeat asks while they wait. */
const UNLOCK_ASK_MS = 5_000;
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
    /** Stored field ids the editor removed; other unlisted stored fields are kept. */
    remove: z.array(z.string()).optional(),
  })
  .strict();
const SecretFieldRemoveBody = z.object({ vault: z.string(), name: z.string(), fieldId: z.string() }).strict();
const SecretNameBody = z.object({ vault: z.string(), name: z.string() }).strict();
const ParseEnvBody = z.object({ vault: z.string(), text: z.string() }).strict();
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
/** The groups store's per-connection bound (src/owner-files.ts). */
const MAX_CONNECTION_GROUPS = 16;
const OAuthStartBody = z
  .object({
    vault: z.string().default("default"),
    name: z.string(),
    definition: z.unknown(),
    groups: z.array(z.string()).max(MAX_CONNECTION_GROUPS).optional(),
    reauthorize: z.boolean().optional(),
  })
  .strict();
const OAuthCancelBody = z.object({ id: z.string() }).strict();

export interface OwnerUiOptions {
  /** Register an explicitly selected archive before opening the owner page. */
  vaultPath?: string;
  /** Prefer only an archive explicitly supplied for this process start. */
  startupVaultPath?: string;
  port?: number;
  sessionPort?: number;
  sessionFile?: string;
  configDir?: string;
  /**
   * Native notification of each new unlock request `id`, so the app can bring
   * its unlock forward. Called once per id, after the request path has
   * answered; it never delays or fails an agent request.
   */
  onUnlockRequested?: (request: UnlockRequest) => void;
  /** An agent's call unlocked a Without asking vault, with no request or window. */
  onUnlocked?: () => void;
  /** Host/test seam that opens the consent page; defaults to the system-browser launcher. */
  visitAuthorizationUrl?: (url: string, signal: AbortSignal) => Promise<void>;
  /**
   * The Mac app's Touch ID and Without asking unlock. Without it, as in
   * `blinddrop ui`, every vault unlocks with its passphrase only.
   */
  quickUnlock?: QuickUnlockHost;
}

/** Electron's safeStorage and Touch ID calls, supplied by the Mac app. */
export interface QuickUnlockHost {
  isEncryptionAvailable(): boolean;
  encryptString(plainText: string): Buffer;
  decryptString(encrypted: Buffer): string;
  canPromptTouchID(): boolean;
  promptTouchID(reason: string): Promise<void>;
}

export type UnlockMode = "passphrase" | QuickUnlockMode;
const UNLOCK_MODES: readonly string[] = ["passphrase", "touch-id", "without-asking"];

/**
 * A Touch ID or Without asking attempt: the vault is unlocked, it is on
 * Passphrase, or why it falls back to the passphrase. `rejected`: the stored
 * passphrase did not open the vault and is kept, because a failed decryption
 * cannot tell a changed passphrase from a damaged archive. `cancelled`: Lock
 * All ended it. `failed`: any other error.
 */
export type QuickUnlockResult =
  | "unlocked"
  | "passphrase"
  | "touch-id-unavailable"
  | "touch-id-failed"
  | "unreadable"
  | "rejected"
  | "cancelled"
  | "failed";

export type UnlockModeResult = "saved" | "touch-id-unavailable" | "touch-id-failed" | "encryption-unavailable";

/** The non-secret state of the one owner OAuth consent attempt. */
interface OAuthAttemptView {
  id: string;
  name: string;
  reauthorize: boolean;
  status: "waiting" | "saving" | "succeeded" | "failed" | "cancelled";
  /** The bound loopback callback, shown for registration help. */
  redirectUri: string | null;
  error: { code: ErrorCode; message: string } | null;
  saved: { grant: boolean; connection: boolean; groups: boolean };
  startedAt: string;
  finishedAt: string | null;
}

interface OAuthAttempt {
  view: OAuthAttemptView;
  controller: AbortController;
  /** Every vault the connection references, including the grant's destination. */
  vaults: ReadonlySet<string>;
  /** Settles when the attempt is terminal; never rejects. */
  done: Promise<void>;
}

function oauthPending(attempt: OAuthAttempt): boolean {
  return attempt.view.status === "waiting" || attempt.view.status === "saving";
}

/**
 * Consent writes its grant into the refresh field. Another connection may
 * share that field as its own refresh grant (Duplicate or an explicit choice),
 * and signing in renews it for both; a field another connection uses as a
 * different credential is never overwritten.
 */
function assertGrantTarget(
  stored: Record<string, Connection>,
  refreshSecret: string,
  self: string | undefined,
): void {
  const target = parseSecretRef(refreshSecret);
  const isTarget = (ref: SecretRef): boolean => ref.vault === target.vault &&
    ref.secret === target.secret && (ref.field ?? DEFAULT_FIELD_ID) === target.field;
  for (const [other, saved] of Object.entries(stored)) {
    if (other === self) continue;
    const grant = saved.auth.type === "oauth2" ? saved.auth.refreshSecret : undefined;
    const sharedGrant = grant !== undefined && isTarget(parseSecretRef(grant));
    if (!sharedGrant && connectionSecretRefs(saved).some(isTarget)) throw new BlindDropError("INVALID_INPUT");
  }
}

export interface OwnerUi {
  url: string;
  token: string;
  launchUrl: string;
  closed: Promise<void>;
  hasUnlockedVaults(): boolean;
  lockAll(): Promise<void>;
  lockForEvent(reason: "sleep" | "screen-lock" | "idle", idleSeconds?: number): Promise<boolean>;
  close(): Promise<void>;
  /** The agent unlock request the owner state reports, or null. */
  unlockRequest(): UnlockRequest | null;
  /**
   * Seals the vault's held passphrase for Touch ID or Without asking, after one
   * Touch ID confirmation for Touch ID; Passphrase deletes it.
   */
  setUnlockMode(name: string, mode: UnlockMode): Promise<UnlockModeResult>;
  /**
   * `owner`: the owner asked, so a Touch ID or Without asking vault unlocks
   * through the passphrase unlock's own path, prompting for Touch ID.
   * Otherwise, for an agent request's passphrase prompt, it never prompts: it
   * answers the app's attempt in progress, the fallback it left, or passphrase.
   */
  quickUnlock(name: string, owner?: boolean): Promise<QuickUnlockResult>;
  /**
   * Before the app shows its window for an agent's request: one Touch ID
   * prompt at a time for each named Touch ID vault, or for a request that names
   * none, the vault the Unlock screen would select. Resolves whether any vault
   * was unlocked, or null when Lock All or Quit ended it: a later request asks
   * again.
   */
  quickUnlockRequest(request: UnlockRequest): Promise<boolean | null>;
}

/** The owner-state view of agents' recent asks to unlock a locked vault. */
export interface UnlockRequest {
  id: string;
  /** The connection every recent ask named, or null. */
  connection: string | null;
  /** Sorted locked vaults asked for; [] only for the primary unlock. */
  vaults: string[];
}

interface UnlockAskRecord {
  at: number;
  connection: string | null;
  vaults: readonly string[];
}

/**
 * The locked vaults a connection needs when unlocking them is all it lacks:
 * every vault it references is registered with an existing file, at least one
 * is locked, and every reference into an unlocked vault resolves. Otherwise
 * undefined: it is usable already, or no unlock can make it usable and it
 * keeps today's omission and errors.
 */
function lockedVaults(
  connection: Connection,
  available: ReadonlySet<string>,
  unlocked: Map<string, VaultData>,
): string[] | undefined {
  const refs = connectionSecretRefs(connection);
  const needed = [...new Set(refs.map(ref => ref.vault).filter(vault => !unlocked.has(vault)))].sort();
  if (needed.length === 0 || !needed.every(vault => available.has(vault))) return undefined;
  return refs.every(ref => !unlocked.has(ref.vault) || resolveValue(unlocked, ref) !== undefined)
    ? needed
    : undefined;
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

/**
 * The provider's own short error text from an error response body, for the
 * owner's connection test: the first non-empty string among the common JSON
 * error fields, or the first XML `<Message>`, on one line and at most 200
 * characters. Nothing else of the body leaves the runtime.
 */
function providerMessage(body: string): string | undefined {
  const field = (value: unknown, key: string): unknown =>
    typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
  let text: unknown;
  try {
    const json: unknown = JSON.parse(body);
    const errors = field(json, "errors");
    text = [
      field(json, "message"),
      field(json, "error"),
      field(field(json, "error"), "message"),
      field(json, "msg"),
      field(json, "detail"),
      field(json, "error_description"),
      Array.isArray(errors) ? field(errors[0], "message") : undefined,
    ].find(value => typeof value === "string" && value.trim() !== "");
  } catch {
    text = /<Message>([\s\S]*?)<\/Message>/.exec(body)?.[1];
  }
  if (typeof text !== "string") return undefined;
  const line = text.replace(/\s+/g, " ").trim();
  return line === "" ? undefined : Array.from(line).slice(0, 200).join("");
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
  readSettings(configDir);
  const connectionFile = connectionsPath(configDir);
  const sessionFilePath = options.sessionFile ?? join(configDir, "session.json");
  // Activity is global; the running session logs to the default vault's log.
  const logPath = activityLogPath(defaultPath);
  // Vault name -> its held passphrase. Only unlocked vaults appear; passphrases
  // live only here and in the session closure, never in a response, and on
  // disk only as the Mac app seals them for Touch ID and Without asking.
  const passphrases = new Map<string, Buffer>();
  // The one owner consent attempt. In memory only: quitting or relaunching
  // leaves none, and nothing about it is ever persisted.
  let oauthAttempt: OAuthAttempt | undefined;
  // Touch ID and Without asking attempts in progress, one per vault, so
  // repeated asks join the running attempt until Lock All; Without asking
  // vaults being unlocked where an agent's call asked, which stay out of the
  // unlock request; and attempts that fell back to the passphrase while agents keep
  // asking, so the app does not try them again until the asks stop.
  const quickUnlocks = new Map<string, Promise<QuickUnlockResult>>();
  const silentUnlocks = new Set<string>();
  const declined = new Map<string, QuickUnlockResult>();
  // One system Touch ID prompt at a time.
  let touchIdPrompts: Promise<void> = Promise.resolve();
  // Lock All ends Touch ID and Without asking unlocks in progress or waiting.
  let lockAllCount = 0;
  // A Touch ID unlock restarts that vault's idle clock, on the wall clock as
  // system idle time counts sleep: a touch may not count as input to macOS.
  const touchUnlockedAt = new Map<string, number>();

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
  const startupEntry = options.startupVaultPath === undefined
    ? undefined
    : loadStoredRegistry(configDir).vaults.find(
      entry => resolve(entry.path) === resolve(options.startupVaultPath!),
    );
  if (options.startupVaultPath !== undefined && startupEntry === undefined) {
    throw new BlindDropError("VAULT_NOT_FOUND");
  }
  const startupVault = startupEntry?.name ?? null;

  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token, "utf8");
  // The agent endpoint and what it authorizes. Only runSync (and the backup
  // pause) changes them, inside the owner queue.
  let endpoint: AgentEndpoint | undefined;
  let endpointAccess: AgentAccess | undefined;
  let agentToken = "";
  let tokenExpiresAt = 0;
  let renewalTimer: NodeJS.Timeout | undefined;
  let unlockedAtLastSync = false;
  let sessionFilePublished = false;
  let unlockAsks: UnlockAskRecord[] = [];
  let unlockRequest: UnlockRequest | null = null;
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
    declined.delete(name);
  }

  function releaseVault(name: string): void {
    passphrases.get(name)?.fill(0);
    passphrases.delete(name);
    touchUnlockedAt.delete(name);
    abortOAuth(name);
  }

  function releaseAll(): void {
    for (const buffer of passphrases.values()) buffer.fill(0);
    passphrases.clear();
    touchUnlockedAt.clear();
    abortOAuth();
  }

  /**
   * Ends a pending consent attempt that needs the released vault (any attempt
   * when no vault is named). Synchronous and never awaits the attempt, so a
   * lock is not delayed; its listener closes and a late callback is refused.
   */
  function abortOAuth(vault?: string): void {
    const attempt = oauthAttempt;
    if (attempt === undefined || !oauthPending(attempt)) return;
    if (vault !== undefined && !attempt.vaults.has(vault)) return;
    attempt.controller.abort(new BlindDropError("SESSION_CLOSED"));
  }

  /**
   * An owner edit, disable or removal of the connection being reauthorized
   * supersedes its pending consent, so a late commit cannot restore the
   * definition captured when sign-in started.
   */
  function abortReauthorization(name: string): void {
    if (oauthAttempt?.view.reauthorize === true && oauthAttempt.view.name === name) abortOAuth();
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
    const same = existing !== undefined && resolve(existing.path) === resolve(path);
    if (existing !== undefined && !same) {
      if (existsSync(existing.path)) throw new BlindDropError("INVALID_INPUT");
      releaseVault(name);
      existing.path = path;
    } else if (existing === undefined) registry.vaults.push({ name, path });
    if (!same) saveRegistry(registry, configDir);
    // Accepted and saved, so a failed open keeps the vault's choice. A sealed
    // passphrase belongs to the archive it opened: a vault created or opened
    // under this name starts on Passphrase. A file that cannot be read is left
    // as it is; only Passphrase or a removal rewrites it.
    if (unlockChoices()(name) !== "unreadable") removeQuickUnlock(configDir, name);
  }

  function hasRegisteredVaults(): boolean {
    return loadStoredRegistry(configDir).vaults.length > 0;
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

  /**
   * The one unlock path: a typed passphrase, and the app's Touch ID and
   * Without asking. A silent unlock for an agent changes no owner state, so
   * it does not record the last unlocked vault.
   */
  async function unlockVault(name: string, passphrase: string, record = true): Promise<void> {
    const entry = requireEntry(name);
    migrateEntry(name, entry.path, passphrase);
    holdVault(name, passphrase);
    // An unlock: requests running on the previous broker finish on it.
    await syncSession("drain");
    if (record) recordVault(entry.path);
  }

  /**
   * One system Touch ID prompt at a time; a cancelled or failed prompt rejects.
   * A prompt still waiting its turn is shown only if it is still needed.
   */
  function promptTouchID(host: QuickUnlockHost, reason: string, needed: () => boolean): Promise<void> {
    const prompt = touchIdPrompts.then(() => needed()
      ? host.promptTouchID(reason)
      : Promise.reject(new BlindDropError("SESSION_CLOSED")));
    touchIdPrompts = prompt.then(() => undefined, () => undefined);
    return prompt;
  }

  /**
   * A Touch ID or Without asking attempt. `force`: the owner asked, so an
   * attempt that fell back while agents keep asking is tried again.
   */
  function quickUnlock(name: string, force = false): Promise<QuickUnlockResult> {
    const running = quickUnlocks.get(name);
    if (running !== undefined) return running;
    settleUnlockRequest();
    const remembered = declined.get(name);
    if (!force && remembered !== undefined) return Promise.resolve(remembered);
    // An error after the touch (a damaged archive, a storage failure) is a
    // fallback like any other. An attempt Lock All ended (lockAll) leaves
    // nothing behind for the attempts of the next period.
    const current = (): boolean => quickUnlocks.get(name) === attempt;
    const attempt: Promise<QuickUnlockResult> = attemptQuickUnlock(name, force)
      .catch((): QuickUnlockResult => "failed").then(result => {
        settleUnlockRequest();
        if (current() && result !== "unlocked" && result !== "passphrase" && result !== "cancelled" &&
            unlockAsks.length > 0) declined.set(name, result);
        return result;
      }).finally(() => { if (current()) quickUnlocks.delete(name); });
    quickUnlocks.set(name, attempt);
    return attempt;
  }

  /**
   * An agent's call found these vaults locked ([] while every vault is
   * locked). Its Without asking vaults unlock here, after the call is
   * answered, with no prompt, window or unlock request; the agent's next send
   * completes. One whose attempt fell back joins the request instead.
   */
  function unlockWithoutAsking(vaults: readonly string[]): void {
    let entries: Record<string, QuickUnlockEntry>;
    try {
      entries = options.quickUnlock === undefined ? {} : readQuickUnlock(configDir);
    } catch {
      return;
    }
    const names = vaults.length > 0 ? vaults : Object.keys(entries);
    const lockAllAtAsk = lockAllCount;
    for (const name of names) {
      if (!Object.hasOwn(entries, name) || entries[name].mode !== "without-asking" ||
          passphrases.has(name) || silentUnlocks.has(name) || declined.has(name)) continue;
      silentUnlocks.add(name);
      setImmediate(() => {
        // After Lock All this attempt and its ask are gone (lockAll), and a
        // later ask may be unlocking the vault again.
        const done = (): void => {
          if (lockAllCount === lockAllAtAsk) { silentUnlocks.delete(name); settleUnlockRequest(); }
        };
        if (lockAllCount !== lockAllAtAsk || stopped) done();
        // The native layer owns its own failures, as with onUnlockRequested.
        else void quickUnlock(name).then(result => { if (result === "unlocked") options.onUnlocked?.(); })
          .catch(() => undefined).finally(done);
      });
    }
  }

  async function attemptQuickUnlock(name: string, owner: boolean): Promise<QuickUnlockResult> {
    const host = options.quickUnlock;
    const lockAllAtStart = lockAllCount;
    if (stopped) throw new BlindDropError("SESSION_CLOSED");
    requireEntry(name);
    if (passphrases.has(name)) return "unlocked";
    const chosen = host === undefined ? undefined : quickUnlockEntry(configDir, name);
    if (host === undefined || chosen === undefined) return "passphrase";
    if (chosen.mode === "touch-id") {
      if (!host.canPromptTouchID()) return "touch-id-unavailable";
      const needed = (): boolean => !stopped && lockAllCount === lockAllAtStart && !passphrases.has(name) &&
        quickUnlockEntry(configDir, name)?.mode === "touch-id";
      try {
        await promptTouchID(host, `unlock the vault “${name}”`, needed);
      } catch {
        if (needed()) return "touch-id-failed";
      }
      if (stopped) throw new BlindDropError("SESSION_CLOSED");
      if (lockAllCount !== lockAllAtStart) return "cancelled";
      if (passphrases.has(name)) return "unlocked";
    }
    // Read again: the owner may have chosen Passphrase while Touch ID was up.
    const entry = quickUnlockEntry(configDir, name);
    if (entry === undefined || entry.mode !== chosen.mode) return "passphrase";
    let passphrase: string;
    try {
      passphrase = host.decryptString(Buffer.from(entry.sealed, "base64"));
    } catch {
      return "unreadable";
    }
    try {
      // Only a Without asking unlock where an agent's call asked is silent.
      await unlockVault(name, passphrase, owner || chosen.mode === "touch-id");
    } catch (error) {
      if (!(error instanceof BlindDropError) || error.code !== "UNLOCK_FAILED") throw error;
      // Kept: the next successful passphrase unlock seals the passphrase again.
      return "rejected";
    }
    if (chosen.mode === "touch-id") touchUnlockedAt.set(name, Date.now());
    return "unlocked";
  }

  /**
   * The Touch ID part of an agent's request, before any window: each named
   * Touch ID vault, one prompt at a time, or for a request that names none,
   * the vault the Unlock screen would select. Stops at Lock All or Quit.
   */
  async function quickUnlockRequest(request: UnlockRequest): Promise<boolean | null> {
    const lockAllAtStart = lockAllCount;
    const ended = (): boolean => lockAllCount !== lockAllAtStart || stopped;
    let names: readonly string[];
    let entries: Record<string, QuickUnlockEntry>;
    try {
      entries = options.quickUnlock === undefined ? {} : readQuickUnlock(configDir);
      if (request.vaults.length > 0) names = request.vaults;
      else {
        // Never a vault whose file is missing.
        const vaults = loadStoredRegistry(configDir).vaults.filter(entry => existsSync(entry.path));
        const last = readSettings(configDir).lastVault;
        const selected = vaults.find(entry => entry.name === startupVault) ??
          vaults.find(entry => entry.path === last) ?? vaults[0];
        names = selected === undefined ? [] : [selected.name];
      }
    } catch {
      // Unreadable choices or settings leave every vault to the passphrase prompt.
      return false;
    }
    let unlocked = false;
    for (const name of names) {
      if (ended()) break;
      if (!Object.hasOwn(entries, name) || entries[name].mode !== "touch-id") continue;
      if (await quickUnlock(name) === "unlocked") unlocked = true;
    }
    return ended() ? null : unlocked;
  }

  async function setUnlockMode(name: string, mode: UnlockMode): Promise<UnlockModeResult> {
    if (stopped) throw new BlindDropError("SESSION_CLOSED");
    if (!UNLOCK_MODES.includes(mode)) throw new BlindDropError("INVALID_INPUT");
    requireEntry(name);
    if (mode === "passphrase") {
      removeQuickUnlock(configDir, name);
      return "saved";
    }
    const host = options.quickUnlock;
    if (host === undefined) throw new BlindDropError("INVALID_INPUT");
    requireUnlocked(name);
    if (!host.isEncryptionAvailable()) return "encryption-unavailable";
    if (mode === "touch-id") {
      if (!host.canPromptTouchID()) return "touch-id-unavailable";
      const lockAllAtStart = lockAllCount;
      try {
        await promptTouchID(host, `turn on Touch ID for the vault “${name}”`,
          () => !stopped && lockAllCount === lockAllAtStart && passphrases.has(name));
      } catch {
        // After Lock All the vault is locked and nothing is saved.
        if (lockAllCount !== lockAllAtStart) throw new BlindDropError("ACCESS_DENIED");
        return "touch-id-failed";
      }
    }
    // The passphrase held now; the vault may have been locked during the prompt.
    const { passphrase } = requireUnlocked(name);
    saveQuickUnlock(configDir, name, { mode, sealed: host.encryptString(passphrase).toString("base64") });
    return "saved";
  }

  /**
   * A passphrase that just opened the vault, typed or changed in the app,
   * replaces a Touch ID or Without asking vault's sealed one, which may have
   * stopped working. Only a vault the owner already set to one of those
   * reaches the Keychain. The unlock or change has already succeeded, so a
   * failure here keeps the stored one, which then falls back with its reason.
   */
  function resealQuickUnlock(name: string, passphrase: string): void {
    const host = options.quickUnlock;
    if (host === undefined) return;
    try {
      const entry = quickUnlockEntry(configDir, name);
      if (entry === undefined) return;
      saveQuickUnlock(configDir, name, { mode: entry.mode, sealed: host.encryptString(passphrase).toString("base64") });
    } catch {
      // Kept; see above.
    }
  }

  /** The Mac app's per-vault choice; an unreadable file reports every vault as `unreadable`. */
  function unlockChoices(): (name: string) => UnlockMode | "unreadable" {
    try {
      const entries = readQuickUnlock(configDir);
      return name => Object.hasOwn(entries, name) ? entries[name].mode : "passphrase";
    } catch {
      return () => "unreadable";
    }
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
    abortReauthorization(input.name);
  }

  function editConnection(name: string, enabled?: boolean): void {
    validateName(name);
    const connections = readConnections(connectionFile);
    if (!Object.hasOwn(connections, name)) throw new BlindDropError("CONNECTION_NOT_FOUND");
    if (enabled === undefined) delete connections[name];
    else connections[name].enabled = enabled;
    writeConnections(connectionFile, connections);
    abortReauthorization(name);
  }

  /**
   * Nothing served: every tool call and SDK route answers `code` and asks for
   * nothing. The setup-backup pause answers BUSY; a failed recomputation
   * answers its own static error rather than an empty listing.
   */
  function refusedAccess(code: ErrorCode): AgentAccess {
    return { names: [], locked: new Map(), lockedItems: [], primary: false, unavailable: code, expiresAt: tokenExpiresAt };
  }

  /** A new agent token for the existing 24-hour limit, renewed shortly before it ends. */
  function replaceToken(): void {
    agentToken = randomBytes(32).toString("base64url");
    tokenExpiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    clearTimeout(renewalTimer);
    renewalTimer = setTimeout(() => { void serializeOwner(() => runSync("close", true)); },
      Math.max(0, tokenExpiresAt - RENEWAL_LEAD_MS - Date.now()));
  }

  /**
   * What agents may use now, computed here and never per request: one broker
   * over the eligible connections, from the vault data this sync decrypts, and
   * the locked connections, which need only `connections.json` and the
   * registry while every vault is locked.
   */
  function computeAccess(): AgentAccess {
    const registered = loadStoredRegistry(configDir).vaults;
    const available = new Set(registered
      .filter(entry => existsSync(entry.path))
      .map(entry => entry.name));
    const unlocks = unlockedList();
    // Registered vaults whose files are all gone are a missing archive, not an
    // empty setup: refuse rather than list nothing. With no registered vault
    // at all, the empty list below stands.
    if (registered.length > 0 && available.size === 0 && unlocks.length === 0) {
      return refusedAccess("VAULT_NOT_FOUND");
    }
    const snapshot = new Map<string, VaultData>();
    for (const unlock of unlocks) {
      snapshot.set(unlock.name, loadVault(unlock.path, unlock.passphrase));
    }
    const connections = readConnections(connectionFile);
    const names = unlocks.length === 0 ? [] : eligibleConnections(snapshot, connections);
    const locked = new Map<string, string[]>();
    const lockedItems: ConnectionMetadata[] = [];
    for (const [name, connection] of Object.entries(connections).sort(byName)) {
      const vaults = connection.enabled ? lockedVaults(connection, available, snapshot) : undefined;
      if (vaults === undefined) continue;
      locked.set(name, vaults);
      // Credential-free guidance from the definition; no vault name or reference.
      lockedItems.push({
        name,
        origin: connection.origin,
        authType: connection.auth.type,
        ...connectionGuidance(name, connection),
        available: false,
        reason: "locked",
      });
    }
    const access: AgentAccess = {
      names,
      locked,
      lockedItems,
      primary: unlocks.length === 0 && available.size > 0,
      expiresAt: tokenExpiresAt,
    };
    if (names.length > 0) {
      access.broker = createBrokerSession(unlocks, names, SESSION_TTL_SECONDS,
        { connections, logPath, expiresAt: tokenExpiresAt }).broker;
    }
    return access;
  }

  /** Writes the session file while the endpoint runs with `sessionFile` on; deletes it otherwise. */
  function publishSessionFile(on: boolean, names: readonly string[]): void {
    if (endpoint !== undefined && on) {
      writeSessionFile(sessionFilePath, {
        mcpUrl: endpoint.mcpUrl,
        token: agentToken,
        expiresAt: tokenExpiresAt,
        connections: endpoint.urls(names),
      });
      sessionFilePublished = true;
    } else {
      sessionFilePublished = false;
      deleteSessionFile(sessionFilePath);
    }
  }

  /** Binds the endpoint on the saved port (or the override) with the collision fallback. */
  async function startEndpoint(settings: OwnerSettings): Promise<void> {
    // Refused until this sync computes the access, before any request is read.
    const started = await startAgentEndpoint(
      sessionPortOverride ?? settings.sessionPort, agentToken, refusedAccess("BUSY"), recordAsk);
    endpoint = started;
    endpointAccess = undefined;
    void started.closed.then(() => {
      if (endpoint !== started) return;
      // The listener failed on its own: withdraw it and start another.
      endpoint = undefined;
      endpointAccess = undefined;
      sessionFilePublished = false;
      try {
        deleteSessionFile(sessionFilePath);
      } catch {
        // Best effort: the file's listener is gone, which readers detect.
      }
      if (!stopped) void syncSession();
    });
    if (sessionPortOverride !== 0 && started.port !== settings.sessionPort) {
      writeSettings(configDir, { sessionPort: started.port });
    }
  }

  /** Closes the listener and every broker; the session file goes with it. */
  async function closeEndpoint(): Promise<void> {
    const running = endpoint;
    endpoint = undefined;
    endpointAccess = undefined;
    sessionFilePublished = false;
    try {
      deleteSessionFile(sessionFilePath);
    } catch {
      // Best effort: a stale file names a listener that no longer accepts.
    }
    await running?.close();
  }

  /**
   * The single owner of what the agent endpoint authorizes. It starts the
   * endpoint when none runs, replaces the token when every vault has become
   * locked by any path or on renewal, recomputes access, publishes the
   * session file and then swaps the access in. `drain` (an unlock) lets
   * requests running on the previous broker finish; every other change, and
   * any failure, closes every broker at once.
   */
  async function runSync(mode: "drain" | "close" = "close", renew = false): Promise<void> {
    if (stopped) {
      clearTimeout(renewalTimer);
      await closeEndpoint();
      return;
    }
    const anyUnlocked = passphrases.size > 0;
    if (renew || agentToken === "" || (unlockedAtLastSync && !anyUnlocked)) replaceToken();
    unlockedAtLastSync = anyUnlocked;

    let failure: unknown;
    let settings: OwnerSettings | undefined;
    try {
      settings = readSettings(configDir);
      if (endpoint === undefined) await startEndpoint(settings);
    } catch (error) {
      failure = error;
    }
    const running = endpoint;
    if (running === undefined) {
      // The runtime keeps running without a listener and reports why.
      try {
        deleteSessionFile(sessionFilePath);
      } catch {
        // Best effort: the file's listener is gone, which readers detect.
      }
      sessionError = publicError(failure).code;
      return;
    }
    let access: AgentAccess;
    try {
      access = computeAccess();
    } catch (error) {
      failure ??= error;
      // Fail closed: no broker, and agents get this static error, not an empty list.
      access = refusedAccess(publicError(error).code);
    }
    try {
      // The new token reaches the file before the old one stops working.
      publishSessionFile(settings?.sessionFile ?? sessionFilePublished, access.names);
    } catch (error) {
      failure ??= error;
    }
    running.update(agentToken, access, mode === "drain" && failure === undefined);
    endpointAccess = access;
    sessionError = failure === undefined ? null : publicError(failure).code;
  }

  /** Overlapping owner/session operations run one after another. */
  function serializeOwner<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = syncChain.then(operation, operation);
    syncChain = result.then(() => undefined, () => undefined);
    return result;
  }

  function syncSession(mode: "drain" | "close" = "close"): Promise<void> {
    return serializeOwner(() => runSync(mode));
  }

  /**
   * Applies changed `sessionPort` and `sessionFile` settings: a port change
   * moves the listener, which closes every broker; turning `sessionFile` off
   * deletes the session file and replaces the token and broker, as renewal
   * does, so no agent keeps access; turning it on writes the file.
   */
  async function applySessionSettings(before: OwnerSettings, after: OwnerSettings): Promise<void> {
    const moved = sessionPortOverride === undefined && before.sessionPort !== after.sessionPort &&
      endpoint?.port !== after.sessionPort;
    const revoked = before.sessionFile && !after.sessionFile;
    if (moved) await closeEndpoint();
    if (moved || revoked) {
      await runSync("close", revoked);
    } else if (before.sessionFile !== after.sessionFile) {
      try {
        publishSessionFile(after.sessionFile, endpointAccess?.names ?? []);
      } catch (error) {
        sessionError = publicError(error).code;
      }
    }
  }

  /**
   * Stop agent traffic while a bounded synchronous snapshot reads owner
   * files: every broker closes first, then calls answer BUSY and ask nothing.
   */
  function withSessionPaused<T>(operation: () => T): Promise<T> {
    return serializeOwner(async () => {
      endpoint?.update(agentToken, refusedAccess("BUSY"), false);
      try {
        return operation();
      } finally {
        if (!stopped) await runSync();
      }
    });
  }

  /**
   * Recomputes the unlock request from the asks of the last five seconds,
   * lazily, with no timer. An ask an unlock has answered drops out (a primary
   * ask once any vault is unlocked), so unlocked vaults leave the set without
   * a new id; the id changes only when the set gains a vault.
   */
  function settleUnlockRequest(): void {
    const now = Date.now();
    const locked = (vault: string): boolean => !passphrases.has(vault);
    unlockAsks = unlockAsks.filter(ask => now - ask.at < UNLOCK_ASK_MS &&
      (ask.vaults.length === 0 ? passphrases.size === 0 : ask.vaults.some(locked)));
    if (unlockAsks.length === 0) {
      unlockRequest = null;
      declined.clear();
      return;
    }
    // Without asking vaults being unlocked where the call asked stay out of
    // the request, and a call that names no vault waits for them.
    const waiting = (vault: string): boolean => locked(vault) && !silentUnlocks.has(vault);
    const asks = unlockAsks.filter(ask => ask.vaults.length === 0 ? silentUnlocks.size === 0 : ask.vaults.some(waiting));
    if (asks.length === 0) {
      unlockRequest = null;
      return;
    }
    const vaults = [...new Set(asks.flatMap(ask => ask.vaults.filter(waiting)))].sort();
    const connections = new Set(asks.map(ask => ask.connection));
    const previous = unlockRequest;
    const gained = previous === null || vaults.some(vault => !previous.vaults.includes(vault));
    unlockRequest = {
      id: gained || previous === null ? randomBytes(16).toString("base64url") : previous.id,
      connection: connections.size === 1 ? asks[0].connection : null,
      vaults,
    };
    if (gained) notifyUnlockRequested(unlockRequest);
  }

  function currentUnlockRequest(): UnlockRequest | null {
    settleUnlockRequest();
    return unlockRequest === null ? null : { ...unlockRequest, vaults: [...unlockRequest.vaults] };
  }

  /** An agent request found these vaults locked ([] for the primary unlock). */
  function recordAsk(connection: string | null, vaults: readonly string[]): void {
    // A request no call has renewed for five seconds clears first, so this
    // call raises a new request rather than renewing a stale one.
    settleUnlockRequest();
    unlockAsks.push({ at: Date.now(), connection, vaults: [...vaults] });
    unlockWithoutAsking(vaults);
    settleUnlockRequest();
  }

  /** Fire-and-forget: the native layer's work never runs in, or fails, the request path. */
  function notifyUnlockRequested(request: UnlockRequest): void {
    const callback = options.onUnlockRequested;
    // After Quit no ask becomes a window.
    if (callback === undefined || stopped) return;
    const copy: UnlockRequest = { id: request.id, connection: request.connection, vaults: [...request.vaults] };
    setImmediate(() => {
      try {
        void Promise.resolve(callback(copy)).catch(() => undefined);
      } catch {
        // The native layer owns its own failures.
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
    const registered = new Set(loadStoredRegistry(configDir).vaults.map(entry => entry.name));
    // The Mac app's per-vault unlock choice; `blinddrop ui` has none.
    const choice = options.quickUnlock === undefined ? undefined : unlockChoices();
    return {
      version: VERSION,
      startupVault,
      configDir,
      sessionFilePath,
      logPath,
      vaults: registryEntries().map(entry => ({
        name: entry.name,
        path: entry.path,
        registered: registered.has(entry.name),
        exists: existsSync(entry.path),
        unlocked: passphrases.has(entry.name),
        ...(choice === undefined ? {} : { unlock: choice(entry.name) }),
      })),
      // Present whenever the endpoint runs, including while every vault is locked.
      session: endpoint === undefined ? null : {
        mcpUrl: endpoint.mcpUrl,
        connections: endpoint.urls(endpointAccess?.names ?? []),
        expiresAt: tokenExpiresAt,
        sessionFile: sessionFilePublished ? sessionFilePath : null
      },
      sessionError,
      unlockRequest: currentUnlockRequest(),
      oauth: oauthAttempt?.view ?? null
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
    // Agents reach the endpoint only through the published session file.
    const running = new Set(endpoint === undefined || !sessionFilePublished ? [] : endpointAccess?.names ?? []);

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
        guidance: connectionGuidance(name, item),
        groups: Object.hasOwn(groups.connections, name) ? groups.connections[name] : [],
        missingRefs, inSession: running.has(name),
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

  /**
   * Validates a complete Save and connect request, then starts one consent
   * attempt without awaiting it and outside the owner queue. The client values
   * are resolved now and held only by the running attempt.
   */
  function startOAuth(input: z.infer<typeof OAuthStartBody>): OAuthAttemptView {
    validateName(input.vault);
    validateName(input.name);
    const raw = validateConnection(input.definition);
    if (raw.auth.type !== "oauth2" || raw.auth.grant !== "refresh_token" ||
        raw.auth.refreshSecret === undefined || raw.consent === undefined ||
        parseSecretRef(raw.auth.refreshSecret, input.vault).field === undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const groups = input.groups;
    if (groups !== undefined) {
      for (const group of groups) validateName(group);
      if (new Set(groups).size !== groups.length) throw new BlindDropError("INVALID_INPUT");
    }

    const snapshot = unlockedSnapshot();
    const definition = qualifyConnection(snapshot.get(input.vault), input.vault, raw);
    const { auth, consent, tls } = definition;
    if (auth.type !== "oauth2" || auth.refreshSecret === undefined || consent === undefined) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const refreshSecret = auth.refreshSecret;
    // Consent overwrites the refresh field, so no other credential may share it.
    if ([auth.clientIdSecret, auth.clientSecret, tls?.certificateSecret, tls?.privateKeySecret,
      tls?.passphraseSecret].includes(refreshSecret)) {
      throw new BlindDropError("INVALID_INPUT");
    }
    const vaults = new Set(connectionSecretRefs(definition).map(ref => ref.vault));
    for (const vault of vaults) requireUnlocked(vault);
    const value = (reference: string): string => {
      const resolved = resolveValue(snapshot, parseSecretRef(reference));
      if (resolved === undefined) throw new BlindDropError("SECRET_NOT_FOUND");
      return resolved;
    };
    const clientId = auth.clientIdSecret === undefined ? auth.clientId : value(auth.clientIdSecret);
    if (clientId === undefined) throw new BlindDropError("INVALID_INPUT");
    const clientSecret = auth.clientSecret === undefined ? undefined : value(auth.clientSecret);
    const clientTls = tls === undefined ? undefined : {
      cert: value(tls.certificateSecret),
      key: value(tls.privateKeySecret),
      ...(tls.passphraseSecret === undefined ? {} : { passphrase: value(tls.passphraseSecret) }),
    };
    const stored = readConnections(connectionFile);
    const exists = Object.hasOwn(stored, input.name);
    if (input.reauthorize === true && !exists) throw new BlindDropError("CONNECTION_NOT_FOUND");
    assertGrantTarget(stored, refreshSecret, input.name);
    if (input.reauthorize !== true && exists) throw new BlindDropError("INVALID_INPUT");

    // A new attempt supersedes a pending one; a terminal record is replaced.
    const previous = oauthAttempt;
    abortOAuth();
    const view: OAuthAttemptView = {
      id: randomBytes(16).toString("base64url"),
      name: input.name,
      reauthorize: input.reauthorize === true,
      status: "waiting",
      redirectUri: null,
      error: null,
      saved: { grant: false, connection: false, groups: false },
      startedAt: new Date().toISOString(),
      finishedAt: null,
    };
    const controller = new AbortController();
    const attempt: OAuthAttempt = { view, controller, vaults, done: Promise.resolve() };
    oauthAttempt = attempt;
    attempt.done = runOAuth(attempt, {
      issuer: consent.issuer,
      authorizationEndpoint: consent.authorizationEndpoint,
      redirectPort: consent.redirectPort ?? 0,
      authorizationParameters: consent.authorizationParameters ?? {},
      connection: definition,
      clientId,
      ...(clientSecret === undefined ? {} : { clientSecret }),
      ...(clientTls === undefined ? {} : { tls: clientTls }),
      signal: controller.signal,
      visitAuthorizationUrl: options.visitAuthorizationUrl ?? openSystemBrowser,
      onListening: uri => { view.redirectUri = uri; },
    }, definition, refreshSecret, groups, previous?.done);
    return view;
  }

  /** Runs one consent attempt to a terminal state. Never rejects. */
  async function runOAuth(
    attempt: OAuthAttempt,
    request: RefreshGrantRequest,
    definition: Connection,
    refreshSecret: string,
    groups: string[] | undefined,
    previous: Promise<void> | undefined,
  ): Promise<void> {
    // A superseded attempt's listener may still hold a fixed callback port.
    if (previous !== undefined) await previous;
    let refreshToken: string;
    try {
      ({ refreshToken } = await obtainRefreshGrant(request));
    } catch (error) {
      settleOAuth(attempt, attempt.controller.signal.aborted ? "cancelled" : "failed", error);
      return;
    }
    attempt.view.status = "saving";
    try {
      const committed = await serializeOwner(
        () => commitOAuth(attempt, definition, refreshSecret, refreshToken, groups),
      );
      if (committed) settleOAuth(attempt, "succeeded");
      else settleOAuth(attempt, "cancelled", new BlindDropError("SESSION_CLOSED"));
    } catch (error) {
      settleOAuth(attempt, "failed", error);
    }
  }

  /**
   * Saves a completed consent inside the owner queue: grant, then connection,
   * then groups. Every check and write is synchronous, so no lock or quit can
   * interleave before the last write. Returns false, writing nothing, when the
   * attempt was cancelled, superseded or stopped; a vanished vault throws.
   */
  async function commitOAuth(
    attempt: OAuthAttempt,
    definition: Connection,
    refreshSecret: string,
    refreshToken: string,
    groups: string[] | undefined,
  ): Promise<boolean> {
    if (oauthAttempt !== attempt || attempt.controller.signal.aborted || stopped) return false;
    for (const vault of attempt.vaults) {
      if (!passphrases.has(vault)) throw new BlindDropError("ACCESS_DENIED");
    }
    const { view } = attempt;
    try {
      // Connections saved while the browser was open are checked again.
      const connections = readConnections(connectionFile);
      assertGrantTarget(connections, refreshSecret, view.reauthorize ? view.name : undefined);
      storeRefreshGrant(refreshSecret, refreshToken);
      view.saved.grant = true;
      // A connection created under this name during consent is never replaced;
      // the page retries the remaining save without repeating consent.
      if (!view.reauthorize && Object.hasOwn(connections, view.name)) {
        throw new BlindDropError("INVALID_INPUT");
      }
      connections[view.name] = definition;
      writeConnections(connectionFile, connections);
      view.saved.connection = true;
      if (groups !== undefined) {
        assignGroups(view.name, groups);
        view.saved.groups = true;
      }
    } finally {
      // Every archive write restarts the session from the new snapshot.
      if (view.saved.grant) await runSync();
    }
    return true;
  }

  /**
   * Writes a refresh grant into its qualified field in the latest archive with
   * the currently held passphrase. Sibling fields, the secret's type and
   * enabled state, and an existing field's display settings are kept.
   */
  function storeRefreshGrant(reference: string, refreshToken: string): void {
    const ref = parseSecretRef(reference);
    const fieldId = ref.field ?? DEFAULT_FIELD_ID;
    const { path, passphrase } = requireUnlocked(ref.vault);
    const vault = loadVault(path, passphrase);
    const secret = Object.hasOwn(vault.secrets, ref.secret) ? vault.secrets[ref.secret] : undefined;
    const previous = secret !== undefined && Object.hasOwn(secret.fields, fieldId)
      ? secret.fields[fieldId]
      : undefined;
    const field: Field = previous === undefined
      ? { value: refreshToken, label: "Refresh token", masked: true, multiline: false }
      : { ...previous, value: refreshToken };
    vault.secrets[ref.secret] = secret === undefined
      ? { type: "oauth", fields: { [fieldId]: field }, enabled: true }
      : { ...secret, fields: { ...secret.fields, [fieldId]: field } };
    saveVault(path, vault, passphrase);
  }

  /** Sets one connection's groups with the page's groups-payload semantics. */
  function assignGroups(name: string, assigned: string[]): void {
    const meta = readGroups(configDir);
    const connections = { ...meta.connections };
    if (assigned.length > 0) connections[name] = [...assigned];
    else delete connections[name];
    const groups = [...meta.groups, ...assigned.filter(group => !meta.groups.includes(group))];
    writeGroups(configDir, { groups, connections });
  }

  function settleOAuth(
    attempt: OAuthAttempt,
    status: "succeeded" | "failed" | "cancelled",
    error?: unknown,
  ): void {
    attempt.view.status = status;
    attempt.view.error = error === undefined ? null : publicError(error);
    attempt.view.finishedAt = new Date().toISOString();
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
        // An unlock: requests running on the previous broker finish on it.
        await syncSession("drain");
        recordVault(input.path);
        return state();
      }
    }],
    ["/api/vault/open", {
      POST: async body => {
        const input = parse(VaultOpenBody, body);
        assertVaultReservation(input.name, input.path);
        if (!existsSync(input.path)) throw new BlindDropError("VAULT_NOT_FOUND");
        validateVaultArchive(input.path);
        registerVault(input.name, input.path);
        await syncSession();
        return state();
      }
    }],
    ["/api/vault/unlock", {
      POST: async body => {
        const input = parse(VaultUnlockBody, body);
        await unlockVault(input.name, input.passphrase);
        resealQuickUnlock(input.name, input.passphrase);
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
    ["/api/vault/lock-all", {
      POST: async body => {
        parse(EmptyBody, body);
        await lockAll();
        return state();
      }
    }],
    ["/api/vault/remove", {
      POST: async body => {
        const input = parse(VaultNameBody, body);
        validateName(input.name);
        if (input.name === DEFAULT_VAULT_NAME) throw new BlindDropError("INVALID_INPUT");
        requireEntry(input.name);
        removeQuickUnlock(configDir, input.name);
        const settings = readSettings(configDir);
        if (Object.hasOwn(settings.vaultLockPolicies, input.name)) {
          const vaultLockPolicies = { ...settings.vaultLockPolicies };
          delete vaultLockPolicies[input.name];
          writeSettings(configDir, { vaultLockPolicies });
        }
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
        setSecretTyped(path, passphrase, input.name, input.type, input.fields, input.remove);
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
    ["/api/secret/parse-env", {
      POST: body => {
        const input = parse(ParseEnvBody, body);
        requireUnlocked(input.vault);
        return { secrets: parseEnv(input.text) };
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
    ["/api/connection/test", {
      POST: async body => {
        requireAnyUnlocked();
        const input = parse(ConnectionNameBody, body);
        validateName(input.name);
        const connections = readConnections(connectionFile);
        if (!Object.hasOwn(connections, input.name)) throw new BlindDropError("CONNECTION_NOT_FOUND");
        const connection = connections[input.name];
        // The test request is the template's concrete example; generic and
        // schematic guidance, and Modal, have none.
        const guidance = connectionGuidance(input.name, connection);
        if (guidance.recipe === null || guidance.tool !== "execute_http" || guidance.schematic) {
          throw new BlindDropError("UNSUPPORTED_OPERATION");
        }
        // A connection waiting on a locked vault answers as an agent's call
        // does (lockedVaults): every vault it needs that is not unlocked exists.
        const available = new Set(loadStoredRegistry(configDir).vaults
          .filter(entry => existsSync(entry.path)).map(entry => entry.name));
        const locked = connectionSecretRefs(connection).map(ref => ref.vault).filter(vault => !passphrases.has(vault));
        if (connection.enabled && locked.length > 0 && locked.every(vault => available.has(vault))) {
          throw new BlindDropError("VAULT_LOCKED");
        }
        // Fresh vault data through the agents' broker path, logged to Activity
        // as their requests are.
        const { broker } = createBrokerSession(unlockedList(), [input.name], TEST_TTL_SECONDS,
          { connections, logPath });
        try {
          const result = await broker.execute({ ...guidance.example, connection: input.name } as RequestInput);
          const message = result.status >= 400 ? providerMessage(result.body) : undefined;
          return message === undefined ? { status: result.status } : { status: result.status, message };
        } finally {
          broker.close();
          // A refresh token this test rotated is now only in the archive, and a
          // provider may invalidate the old one on use (GitHub does): the
          // agents' broker reloads it, letting running requests finish.
          if (connection.auth.type === "oauth2" && connection.auth.grant === "refresh_token") {
            await syncSession("drain");
          }
        }
      }
    }],
    ["/api/recipes", { GET: () => ({ recipes: RECIPES }) }],
    ["/api/oauth/start", {
      POST: body => {
        requireAnyUnlocked();
        return { oauth: startOAuth(parse(OAuthStartBody, body)) };
      }
    }],
    ["/api/oauth/status", { GET: () => ({ oauth: oauthAttempt?.view ?? null }) }],
    ["/api/oauth/cancel", {
      POST: async body => {
        const input = parse(OAuthCancelBody, body);
        const attempt = oauthAttempt;
        if (attempt !== undefined && attempt.view.id === input.id) {
          if (oauthPending(attempt)) {
            attempt.controller.abort(new BlindDropError("SESSION_CLOSED"));
            await attempt.done;
          } else {
            oauthAttempt = undefined;
          }
        }
        return { oauth: oauthAttempt?.view ?? null };
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
      POST: body => serializeOwner(async () => {
        const before = readSettings(configDir);
        const after = writeSettings(configDir, body);
        await applySessionSettings(before, after);
        return readSettings(configDir);
      })
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
        // Fresh state with no vault unlocked; the agent endpoint keeps running.
        if (passphrases.size > 0 || hasRegisteredVaults()) {
          throw new BlindDropError("VAULT_EXISTS");
        }
        return serializeOwner(async () => {
          if (passphrases.size > 0 || hasRegisteredVaults()) {
            throw new BlindDropError("VAULT_EXISTS");
          }
          const before = readSettings(configDir);
          restoreSetup(configDir, input.path);
          // The restored settings apply as a Settings change does, and the
          // restored registry and connections give agents a new locked set.
          await applySessionSettings(before, readSettings(configDir));
          await runSync();
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
        resealQuickUnlock(input.vault, input.new);
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
    lockAllCount++;
    declined.clear();
    // Attempts from before Lock All are never joined afterwards, and what a
    // Without asking attempt was answering does not become a request: the
    // agent's next ask opens that vault again.
    quickUnlocks.clear();
    unlockAsks = unlockAsks.flatMap(ask => {
      if (ask.vaults.length === 0) return silentUnlocks.size > 0 ? [] : [ask];
      const vaults = ask.vaults.filter(vault => !silentUnlocks.has(vault));
      return vaults.length > 0 ? [{ ...ask, vaults }] : [];
    });
    silentUnlocks.clear();
    releaseAll();
    await syncSession();
  }

  async function lockForEvent(
    reason: "sleep" | "screen-lock" | "idle",
    idleSeconds = 0,
  ): Promise<boolean> {
    const settings = readSettings(configDir);
    const defaults = {
      lockOnSleep: settings.lockOnSleep,
      lockOnScreenLock: settings.lockOnScreenLock,
      idleLockMinutes: settings.idleLockMinutes,
    };
    // Automatic locking does not apply to a Without asking vault: the next
    // agent call would reopen it. Unreadable choices leave every vault to its
    // policy.
    const choice = options.quickUnlock === undefined ? undefined : unlockChoices();
    const due: string[] = [];
    const now = Date.now();
    for (const name of passphrases.keys()) {
      if (choice?.(name) === "without-asking") continue;
      const policy = Object.hasOwn(settings.vaultLockPolicies, name)
        ? settings.vaultLockPolicies[name]
        : defaults;
      // After a Touch ID unlock, idle is due only once that unlock is as old too.
      const limit = policy.idleLockMinutes * 60;
      if (
        (reason === "sleep" && policy.lockOnSleep) ||
        (reason === "screen-lock" && policy.lockOnScreenLock) ||
        (reason === "idle" && limit > 0 && idleSeconds >= limit &&
          now - (touchUnlockedAt.get(name) ?? 0) >= limit * 1000)
      ) due.push(name);
    }
    if (due.length === 0) return false;
    for (const name of due) releaseVault(name);
    await syncSession();
    return true;
  }

  function hasUnlockedVaults(): boolean {
    return passphrases.size > 0;
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
  // The agent endpoint starts before any unlock; a bind failure becomes
  // `sessionError` and never fails startup.
  await syncSession();
  return {
    url: `${pageOrigin}/`,
    token,
    launchUrl: `${pageOrigin}/?t=${token}`,
    closed,
    hasUnlockedVaults,
    lockAll,
    lockForEvent,
    close,
    unlockRequest: currentUnlockRequest,
    setUnlockMode,
    // The page never prompts for an agent request: without `owner` it gets the
    // app's attempt in progress, the fallback that attempt left, or passphrase.
    quickUnlock: (name, owner = false) => owner
      ? quickUnlock(name, true)
      : quickUnlocks.get(name) ?? Promise.resolve(declined.get(name) ?? "passphrase"),
    quickUnlockRequest,
  };
}
