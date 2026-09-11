const messages = {
  INVALID_INPUT: "Invalid input.",
  VAULT_EXISTS: "The vault already exists.",
  VAULT_NOT_FOUND: "The vault does not exist.",
  VAULT_INVALID: "The vault is damaged or unsupported.",
  UNLOCK_FAILED: "Cannot unlock the vault: wrong passphrase or damaged archive.",
  SECRET_NOT_FOUND: "The secret is unavailable.",
  CONNECTION_NOT_FOUND: "The connection is unavailable.",
  ACCESS_DENIED: "This session is not authorized for that operation.",
  SESSION_EXPIRED: "The session has expired.",
  SESSION_CLOSED: "The session is closed.",
  DESTINATION_DENIED: "The destination is not permitted.",
  RESPONSE_BLOCKED: "The upstream response contains credential material.",
  RESPONSE_TOO_LARGE: "The upstream response exceeds the size limit.",
  REQUEST_TOO_LARGE: "The request exceeds the size limit.",
  UNSUPPORTED_RESPONSE: "The upstream response cannot be handled safely.",
  TIMEOUT: "The request timed out. Its upstream outcome may be unknown.",
  UPSTREAM_ERROR: "The upstream request failed. Its outcome may be unknown.",
  BUSY: "The session has reached its concurrent request limit.",
  STORAGE_ERROR: "A local storage operation failed.",
  INPUT_UNAVAILABLE: "Owner input is unavailable. Use a terminal or an inherited input descriptor.",
  INTERNAL_ERROR: "The operation failed."
} as const;

export type ErrorCode = keyof typeof messages;

export class BlindDropError extends Error {
  constructor(public readonly code: ErrorCode) {
    super(messages[code]);
    this.name = "BlindDropError";
  }
}

export function publicError(error: unknown): { code: ErrorCode; message: string } {
  const safe = error instanceof BlindDropError ? error : new BlindDropError("INTERNAL_ERROR");
  return { code: safe.code, message: safe.message };
}
