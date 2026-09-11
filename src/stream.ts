import { BlindDropError } from "./errors.js";
import type { StreamingSink } from "./types.js";

function abortError(signal: AbortSignal): BlindDropError {
  return signal.reason instanceof BlindDropError
    ? signal.reason
    : new BlindDropError("SESSION_CLOSED");
}

export function awaitAbortable<T>(
  operation: () => T | PromiseLike<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(abortError(signal));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown, value?: T): void => {
      if (settled) {
        return;
      }
      settled = true;
      signal.removeEventListener("abort", onAbort);
      if (error !== undefined) {
        reject(error);
      } else {
        resolve(value as T);
      }
    };
    const onAbort = (): void => finish(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });

    Promise.resolve()
      .then(() => {
        if (signal.aborted) {
          throw abortError(signal);
        }
        return operation();
      })
      .then(
        (value) => finish(undefined, value),
        (error: unknown) => finish(error),
      );
  });
}

function containsPattern(
  value: Buffer,
  patterns: readonly Buffer[],
): boolean {
  return patterns.some((pattern) => value.includes(pattern));
}

export async function streamFilteredResponse(
  body: AsyncIterable<Buffer>,
  sink: StreamingSink,
  patterns: readonly string[],
  signal: AbortSignal,
): Promise<void> {
  const bytePatterns = [...new Set(patterns)]
    .filter((pattern) => pattern.length > 0)
    .map((pattern) => Buffer.from(pattern, "utf8"));
  const maximumTail = Math.max(
    0,
    ...bytePatterns.map((pattern) => pattern.length - 1),
  );
  let tail = Buffer.alloc(0);

  try {
    for await (const value of body) {
      if (signal.aborted) {
        throw abortError(signal);
      }
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      const combined = tail.length === 0
        ? chunk
        : Buffer.concat([tail, chunk], tail.length + chunk.length);
      tail.fill(0);
      tail = Buffer.alloc(0);

      if (containsPattern(combined, bytePatterns)) {
        throw new BlindDropError("RESPONSE_BLOCKED");
      }

      const heldBytes = Math.min(maximumTail, combined.length);
      const releasedBytes = combined.length - heldBytes;
      if (releasedBytes > 0) {
        await awaitAbortable(
          () => sink.write(combined.subarray(0, releasedBytes)),
          signal,
        );
      }
      if (heldBytes > 0) {
        tail = Buffer.from(combined.subarray(releasedBytes));
      }
    }

    if (signal.aborted) {
      throw abortError(signal);
    }
    if (containsPattern(tail, bytePatterns)) {
      throw new BlindDropError("RESPONSE_BLOCKED");
    }
    if (tail.length > 0) {
      const finalChunk = Buffer.from(tail);
      await awaitAbortable(() => sink.write(finalChunk), signal);
    }
  } finally {
    tail.fill(0);
    for (const pattern of bytePatterns) {
      pattern.fill(0);
    }
  }
}
