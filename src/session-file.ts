// The opt-in local endpoint file. It carries one running session's loopback
// endpoint and its session token so an agent harness can find the session the
// owner already started. It never carries vault unlock material, and it is
// withdrawn as soon as that session ends.

import { randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import process from "node:process";

import { BlindDropError } from "./errors.js";

export interface SessionFileContents {
  mcpUrl: string;
  token: string;
  expiresAt: number;
  connections: Record<string, string>;
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

/** Publishes the file through an exclusive 0600 sibling and one rename. */
export function writeSessionFile(path: string, contents: SessionFileContents): void {
  assertPath(path);
  const serialized = Buffer.from(`${JSON.stringify({
    mcpUrl: contents.mcpUrl,
    token: contents.token,
    expiresAt: contents.expiresAt,
    connections: contents.connections,
  })}\n`, "utf8");

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
    writeFileSync(descriptor, serialized);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    published = true;
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the original safe error below.
      }
    }
    if (!published) {
      try {
        unlinkSync(temporary);
      } catch {
        // The temp file may not have been created or may already be gone.
      }
    }
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    serialized.fill(0);
  }
}

/** Withdraws the file. A file that is already gone is the intended state. */
export function deleteSessionFile(path: string): void {
  assertPath(path);
  try {
    unlinkSync(path);
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw new BlindDropError("STORAGE_ERROR");
  }
}
