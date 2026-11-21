// The Mac app's per-vault Touch ID and Without asking choices, kept in
// `<config dir>/quick-unlock.json` at mode 0600 and keyed by vault name. Each
// entry holds that vault's passphrase as the app sealed it with Electron
// safeStorage, whose key the macOS Keychain keeps; this module stores the
// sealed text and never unseals it. Back Up Setup copies an explicit list of
// files that leaves this one out, and a restore deletes it, so a restored or
// copied setup starts with every vault on Passphrase.

import { readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";

import { z } from "zod";

import { BlindDropError } from "./errors.js";
import { writeOwnerFile } from "./owner-files.js";
import { validateName } from "./vault.js";

export const QUICK_UNLOCK_FILE = "quick-unlock.json";

export type QuickUnlockMode = "touch-id" | "without-asking";

export interface QuickUnlockEntry {
  mode: QuickUnlockMode;
  /** The sealed passphrase, base64. */
  sealed: string;
}

/** The vault lock-policy bound in settings.json. */
const MAX_ENTRIES = 256;
/** A 64 KiB passphrase, sealed and base64-encoded, fits well inside this. */
const MAX_SEALED_CHARS = 131_072;

const EntrySchema = z
  .object({
    mode: z.enum(["touch-id", "without-asking"]),
    sealed: z.string().min(1).max(MAX_SEALED_CHARS).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  })
  .strict();
const FileSchema = z
  .object({
    version: z.literal(1),
    vaults: z.record(z.string(), EntrySchema),
  })
  .strict();

function quickUnlockPath(configDir: string): string {
  return join(configDir, QUICK_UNLOCK_FILE);
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** Every vault's entry; none when the file does not exist. */
export function readQuickUnlock(configDir: string): Record<string, QuickUnlockEntry> {
  let text: string;
  try {
    text = readFileSync(quickUnlockPath(configDir), "utf8");
  } catch (error) {
    if (errorCode(error) === "ENOENT") return {};
    throw new BlindDropError("STORAGE_ERROR");
  }
  try {
    const { vaults } = FileSchema.parse(JSON.parse(text));
    const names = Object.keys(vaults);
    if (names.length > MAX_ENTRIES) throw new Error();
    for (const name of names) validateName(name);
    return vaults;
  } catch {
    throw new BlindDropError("STORAGE_ERROR");
  }
}

/** One vault's entry, if it has one. */
export function quickUnlockEntry(configDir: string, name: string): QuickUnlockEntry | undefined {
  const vaults = readQuickUnlock(configDir);
  return Object.hasOwn(vaults, name) ? vaults[name] : undefined;
}

/** Publishes the entries atomically, or deletes the file when none remain. */
function writeQuickUnlock(configDir: string, vaults: Record<string, QuickUnlockEntry>): void {
  if (Object.keys(vaults).length === 0) {
    try {
      unlinkSync(quickUnlockPath(configDir));
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw new BlindDropError("STORAGE_ERROR");
    }
    return;
  }
  if (Object.keys(vaults).length > MAX_ENTRIES) throw new BlindDropError("INVALID_INPUT");
  writeOwnerFile(quickUnlockPath(configDir), `${JSON.stringify({ version: 1, vaults })}\n`);
}

export function saveQuickUnlock(configDir: string, name: string, entry: QuickUnlockEntry): void {
  validateName(name);
  const parsed = EntrySchema.safeParse(entry);
  if (!parsed.success) throw new BlindDropError("INVALID_INPUT");
  writeQuickUnlock(configDir, { ...readQuickUnlock(configDir), [name]: parsed.data });
}

/**
 * Deletes one vault's entry, for the owner's Passphrase choice or the vault's
 * removal. A file that cannot be read must not block either: none of its
 * entries can be used, so it is replaced, which returns every vault to
 * Passphrase.
 */
export function removeQuickUnlock(configDir: string, name: string): void {
  let vaults: Record<string, QuickUnlockEntry>;
  try {
    vaults = readQuickUnlock(configDir);
  } catch {
    writeQuickUnlock(configDir, {});
    return;
  }
  if (!Object.hasOwn(vaults, name)) return;
  delete vaults[name];
  writeQuickUnlock(configDir, vaults);
}
