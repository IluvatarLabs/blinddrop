// The only module that loads the official Modal JavaScript SDK (`modal`,
// pinned to 0.11.1, Apache-2.0). It invokes the one owner-selected deployed
// Function of a Modal connection through the SDK's documented
// fromName/spawn/get/cancel path; no other SDK method is used.
//
// Transport boundary: the SDK owns its gRPC connection to Modal's control
// plane, and may transfer large arguments or results itself through URLs that
// Modal returns (`fetch` to blob storage). None of that traffic traverses
// BlindDrop's HTTP sender or inherits its DNS pinning.

import { AsyncLocalStorage } from "node:async_hooks";

import type { FunctionCall, Logger, ModalClient, ModalClientParams } from "modal";

import { BlindDropError } from "./errors.js";
import { awaitAbortable } from "./stream.js";
import type { ModalTarget } from "./types.js";

/**
 * Modal's default service, as the SDK's default and as the one other spelling
 * nice-grpc's `createChannel` dials identically (https defaults to port 443).
 * The pinned SDK takes the service from `MODAL_SERVER_URL` or `~/.modal.toml`,
 * not from a constructor option, so the effective value is verified before
 * any RPC instead.
 */
const MODAL_SERVER_URLS: ReadonlySet<string> = new Set(["https://api.modal.com:443", "https://api.modal.com"]);
const CANCEL_TIMEOUT_MS = 5_000;

type GrpcMiddleware = NonNullable<ModalClientParams["grpcMiddleware"]>[number];

export interface ModalInvocation {
  tokenId: string;
  tokenSecret: string;
  target: ModalTarget;
  args: unknown[];
  kwargs: Record<string, unknown>;
  /** The operation's signal: session close, lock, expiry or the deadline abort it. */
  signal: AbortSignal;
  /** Epoch milliseconds; the same deadline the broker enforces. */
  deadline: number;
}

interface CallContext {
  signal: AbortSignal;
}

// One client serves concurrent invocations, so each SDK call carries its own
// signal in async context rather than in shared client state.
const callContext = new AsyncLocalStorage<CallContext>();

// The SDK installs custom middleware outermost (nice-grpc runs the last
// `use` first), and nice-grpc starts it synchronously within the SDK call, so
// it reads that call's context. Its signal then reaches every layer below,
// including the SDK's retry sleeps and the long poll inside get(). Outside a
// BlindDrop call context the options pass through untouched.
const signalMiddleware: GrpcMiddleware = async function* (call, options) {
  const current = callContext.getStore();
  if (current === undefined) {
    return yield* call.next(call.request, options);
  }
  const signals = options.signal === undefined ? [current.signal] : [current.signal, options.signal];
  return yield* call.next(call.request, { ...options, signal: AbortSignal.any(signals) });
};

// SDK logs may carry request details or remote output; none are forwarded.
const SILENT_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

function abortReason(signal: AbortSignal): BlindDropError {
  return signal.reason instanceof BlindDropError
    ? signal.reason
    : new BlindDropError("SESSION_CLOSED");
}

/**
 * One Modal client per connection for one broker session, created on first
 * use, following Modal's create-once-and-reuse client convention. A new
 * session (every owner write or unlock change) builds new clients, so
 * replaced credentials take effect there.
 */
export class ModalClients {
  private readonly clients = new Map<string, ModalClient>();

  /**
   * Submits exactly one invocation and waits for its result within the
   * deadline. BlindDrop never re-submits after a timeout, transport error,
   * cancellation or ambiguous outcome. The documented exception is the SDK's
   * own control-plane RPC retry middleware, which may resend one RPC (with one
   * idempotency key) after a transient gRPC failure; this is not exactly-once
   * execution.
   *
   * Errors are static: SDK messages, remote exceptions and output never leave.
   */
  async invoke(connectionName: string, request: ModalInvocation): Promise<unknown> {
    const { signal, deadline, target } = request;
    if (signal.aborted) throw abortReason(signal);

    // Loaded on first use: the SDK reads ~/.modal.toml when it is imported.
    let sdk: typeof import("modal");
    try {
      sdk = await import("modal");
    } catch {
      throw new BlindDropError("INTERNAL_ERROR");
    }
    // A session closed during the import creates no client.
    if (signal.aborted) throw abortReason(signal);

    const operation: CallContext = { signal };
    let handle: FunctionCall | undefined;
    let ended = false;
    let delivered = false;
    let cancelling = false;

    // Fire-and-forget under its own short signal: the reported error and
    // vault locking never wait for it, and it cannot undo remote work or
    // guarantee that cancellation wins.
    const cancelRemote = (): void => {
      if (handle === undefined || cancelling) return;
      cancelling = true;
      const call = handle;
      void callContext
        .run({ signal: AbortSignal.timeout(CANCEL_TIMEOUT_MS) }, () => call.cancel())
        .catch(() => undefined);
    };

    try {
      const client = this.client(connectionName, sdk, request);
      const fn = await awaitAbortable(
        () => callContext.run(operation, () =>
          client.functions.fromName(target.app, target.function, { environment: target.environment })),
        signal,
      );
      if (signal.aborted) throw abortReason(signal);
      // Arguments above the SDK's inline size (8 KiB for spawn) are uploaded
      // with an unabortable fetch before the spawn RPC; the race reports an
      // abort immediately, and the aborted signal then stops the spawn RPC.
      const spawning = callContext.run(operation, () => fn.spawn(request.args, request.kwargs));
      void spawning.then(
        (spawned) => {
          handle = spawned;
          // A handle that arrives after the operation ended is still cancelled.
          if (ended && !delivered) cancelRemote();
        },
        () => undefined,
      );
      const call = await awaitAbortable(() => spawning, signal);
      // A large result is downloaded with an unabortable fetch; after an abort
      // that download finishes in the background and its result is discarded.
      const value: unknown = await awaitAbortable(
        () => callContext.run(operation, () =>
          call.get({ timeoutMs: Math.max(1, deadline - Date.now()) })),
        signal,
      );
      delivered = true;
      return value;
    } catch (error) {
      if (signal.aborted) throw abortReason(signal);
      if (error instanceof BlindDropError) throw error;
      if (error instanceof sdk.TimeoutError || Date.now() >= deadline) {
        throw new BlindDropError("TIMEOUT");
      }
      // Remote exceptions, not-found, authentication and transport failures.
      throw new BlindDropError("UPSTREAM_ERROR");
    } finally {
      ended = true;
      // The Function may still be running whenever no result was delivered.
      if (!delivered) cancelRemote();
    }
  }

  /**
   * Drops this session's clients. In modal@0.11.1 `ModalClient.close()` only
   * discards the SDK's cached auth token: the SDK exposes no way to close its
   * gRPC channel, which grpc-js closes after its idle timeout (30 minutes) and
   * which does not keep the process alive. At most one such channel remains
   * per Modal connection per session. In-flight cancellations still finish.
   */
  close(): void {
    for (const client of this.clients.values()) {
      try {
        client.close();
      } catch {
        // Best-effort; the session is already closed.
      }
    }
    this.clients.clear();
  }

  private client(
    connectionName: string,
    sdk: typeof import("modal"),
    request: ModalInvocation,
  ): ModalClient {
    const cached = this.clients.get(connectionName);
    if (cached !== undefined) {
      return cached;
    }
    const client = new sdk.ModalClient({
      tokenId: request.tokenId,
      tokenSecret: request.tokenSecret,
      environment: request.target.environment,
      logger: SILENT_LOGGER,
      // Explicit, so a local MODAL_LOGLEVEL cannot change client construction.
      logLevel: "error",
      grpcMiddleware: [signalMiddleware],
    });
    // Never a local profile's service, credential or environment. The channel
    // is lazy, so this runs before any RPC; a refused client is not cached.
    const profile = client.profile;
    if (!MODAL_SERVER_URLS.has(profile.serverUrl)) {
      throw new BlindDropError("DESTINATION_DENIED");
    }
    if (
      profile.tokenId !== request.tokenId ||
      profile.tokenSecret !== request.tokenSecret ||
      profile.environment !== request.target.environment
    ) {
      throw new BlindDropError("INTERNAL_ERROR");
    }
    this.clients.set(connectionName, client);
    return client;
  }
}
