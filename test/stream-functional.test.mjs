import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { after, before, test } from "node:test";

import { Broker } from "../dist/broker.js";
import { BlindDropError } from "../dist/errors.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const certificatePath = join(testDirectory, "fixtures", "localhost-cert.pem");
const keyPath = join(testDirectory, "fixtures", "localhost-key.pem");
const CREDENTIAL = "dummy-stream-secret-X8v2L5p9";
const CAPABILITY = "dummy-session-capability-Q4m7R1t6";
const SAFE_PREFIX = "safe-stream-output-".repeat(24);

let server;
let origin;
let requestCount = 0;
let cancelClosed;
let resolveCancelClosed;
const temporaryDirectories = new Set();

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

before(async () => {
  server = createServer(
    {
      cert: readFileSync(certificatePath),
      key: readFileSync(keyPath),
    },
    async (request, response) => {
      requestCount += 1;
      response.socket?.setNoDelay(true);
      const url = new URL(request.url, "https://fixture.invalid");

      switch (url.pathname) {
        case "/binary":
          response.writeHead(200, {
            "content-type": "application/octet-stream",
            "content-encoding": "identity",
            "set-cookie": "private=discarded",
            "x-safe": "present",
          });
          response.end(Buffer.from([0x00, 0xff, 0x01, 0x80, 0x7f]));
          return;
        case "/split-reflection":
          response.writeHead(200, { "content-type": "text/plain" });
          response.write(SAFE_PREFIX);
          await delay(15);
          response.write(CREDENTIAL.slice(0, 9));
          await delay(15);
          response.end(`${CREDENTIAL.slice(9)}-not-released`);
          return;
        case "/compressed-reflection":
          response.writeHead(200, {
            "content-type": "text/plain",
            "content-encoding": "gzip",
          });
          response.end(gzipSync(`${SAFE_PREFIX}${CREDENTIAL}`));
          return;
        case "/cancel": {
          response.writeHead(200, { "content-type": "application/octet-stream" });
          response.write(Buffer.alloc(1024, 0x61));
          const interval = setInterval(() => {
            if (!response.destroyed) {
              response.write(Buffer.alloc(1024, 0x62));
            }
          }, 10);
          interval.unref();
          response.once("close", () => {
            clearInterval(interval);
            resolveCancelClosed?.();
          });
          return;
        }
        case "/truncate":
          response.writeHead(200, {
            "content-type": "application/octet-stream",
            "content-length": "4096",
          });
          response.write(Buffer.alloc(1024, 0x63));
          setTimeout(() => response.socket?.destroy(), 20).unref();
          return;
        case "/decoded-limit":
          response.writeHead(200, { "content-encoding": "gzip" });
          response.end(gzipSync("z".repeat(4096)));
          return;
        case "/reflect-capability":
          response.end(CAPABILITY);
          return;
        default:
          response.end("unexpected dispatch");
      }
    },
  );

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  origin = `https://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  for (const directory of temporaryDirectories) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function vaultFor() {
  const now = new Date().toISOString();
  return {
    version: 2,
    createdAt: now,
    updatedAt: now,
    secrets: {
      credential: {
        type: "api-key",
        fields: { value: { value: CREDENTIAL, label: "Value", masked: true, multiline: false } },
        enabled: true,
      },
    },
    connections: {
      service: {
        origin,
        auth: { type: "bearer", secret: "credential" },
        allowPrivate: true,
        enabled: true,
      },
    },
  };
}

function createBroker(streamLimits) {
  const directory = mkdtempSync(join(tmpdir(), "blinddrop-stream-"));
  temporaryDirectories.add(directory);
  return new Broker(
    vaultFor(),
    {
      id: "stream-grant",
      connections: ["service"],
      expiresAt: Date.now() + 60_000,
    },
    {
      logPath: join(directory, "events.jsonl"),
      streamLimits,
    },
  );
}

function collectingSink() {
  const state = { head: null, chunks: [] };
  return {
    state,
    sink: {
      head(status, headers) {
        state.head = { status, headers };
      },
      async write(chunk) {
        state.chunks.push(Buffer.from(chunk));
      },
    },
  };
}

function streamedBody(state) {
  return Buffer.concat(state.chunks);
}

async function rejectsWithCode(promise, code) {
  await assert.rejects(
    promise,
    (error) => error instanceof BlindDropError && error.code === code,
  );
}

test("streaming preserves binary bytes and strips response transport metadata", async () => {
  const broker = createBroker();
  const { sink, state } = collectingSink();
  try {
    await broker.executeStreaming(
      { connection: "service", method: "GET", path: "/binary" },
      sink,
    );
    assert.equal(state.head.status, 200);
    assert.equal(state.head.headers["x-safe"], "present");
    assert.equal(state.head.headers["set-cookie"], undefined);
    assert.equal(state.head.headers["content-encoding"], undefined);
    assert.equal(state.head.headers["content-length"], undefined);
    assert.deepEqual(
      streamedBody(state),
      Buffer.from([0x00, 0xff, 0x01, 0x80, 0x7f]),
    );
  } finally {
    broker.close();
  }
});

test("a credential split across upstream chunks is never released", async () => {
  const broker = createBroker();
  const { sink, state } = collectingSink();
  try {
    await rejectsWithCode(
      broker.executeStreaming(
        { connection: "service", method: "GET", path: "/split-reflection" },
        sink,
      ),
      "RESPONSE_BLOCKED",
    );
    const released = streamedBody(state).toString("utf8");
    assert.ok(released.length > 0);
    assert.ok(SAFE_PREFIX.startsWith(released));
    assert.equal(released.includes(CREDENTIAL), false);
  } finally {
    broker.close();
  }
});

test("a credential in decoded gzip bytes is blocked", async () => {
  const broker = createBroker();
  const { sink, state } = collectingSink();
  try {
    await rejectsWithCode(
      broker.executeStreaming(
        { connection: "service", method: "GET", path: "/compressed-reflection" },
        sink,
      ),
      "RESPONSE_BLOCKED",
    );
    assert.equal(streamedBody(state).includes(Buffer.from(CREDENTIAL)), false);
  } finally {
    broker.close();
  }
});

test("cancellation unblocks a pending sink write and closes upstream", async () => {
  const broker = createBroker();
  const controller = new AbortController();
  cancelClosed = new Promise((resolve) => {
    resolveCancelClosed = resolve;
  });
  let resolveWriteStarted;
  const writeStarted = new Promise((resolve) => {
    resolveWriteStarted = resolve;
  });
  const sink = {
    head() {},
    write() {
      resolveWriteStarted();
      return new Promise(() => {});
    },
  };

  try {
    const operation = broker.executeStreaming(
      { connection: "service", method: "GET", path: "/cancel" },
      sink,
      { signal: controller.signal },
    );
    await writeStarted;
    controller.abort(new BlindDropError("SESSION_CLOSED"));
    await rejectsWithCode(operation, "SESSION_CLOSED");
    await Promise.race([
      cancelClosed,
      delay(1000).then(() => {
        throw new Error("upstream response did not close after cancellation");
      }),
    ]);
  } finally {
    resolveCancelClosed = undefined;
    broker.close();
  }
});

test("a truncated upstream rejects after retaining already delivered safe bytes", async () => {
  const broker = createBroker();
  const { sink, state } = collectingSink();
  try {
    await rejectsWithCode(
      broker.executeStreaming(
        { connection: "service", method: "GET", path: "/truncate" },
        sink,
      ),
      "UPSTREAM_ERROR",
    );
    assert.equal(state.head.status, 200);
    assert.ok(streamedBody(state).length > 0);
  } finally {
    broker.close();
  }
});

test("decoded streaming bytes obey the response limit", async () => {
  const broker = createBroker({ responseBytes: 128 });
  const { sink } = collectingSink();
  try {
    await rejectsWithCode(
      broker.executeStreaming(
        { connection: "service", method: "GET", path: "/decoded-limit" },
        sink,
      ),
      "RESPONSE_TOO_LARGE",
    );
  } finally {
    broker.close();
  }
});

test("gateway capability patterns are denied after request encoding and in responses", async () => {
  const broker = createBroker();
  const dispatchesBefore = requestCount;
  try {
    await rejectsWithCode(
      broker.execute(
        {
          connection: "service",
          method: "POST",
          path: "/should-not-arrive",
          bodyBase64: Buffer.from(CAPABILITY).toString("base64"),
        },
        { extraPatterns: [CAPABILITY] },
      ),
      "ACCESS_DENIED",
    );
    await rejectsWithCode(
      broker.execute(
        {
          connection: "service",
          method: "POST",
          path: "/should-not-arrive",
          multipart: {
            fields: { value: CAPABILITY },
            files: [],
          },
        },
        { extraPatterns: [CAPABILITY] },
      ),
      "ACCESS_DENIED",
    );
    assert.equal(requestCount, dispatchesBefore);

    await rejectsWithCode(
      broker.execute(
        { connection: "service", method: "GET", path: "/reflect-capability" },
        { extraPatterns: [CAPABILITY] },
      ),
      "RESPONSE_BLOCKED",
    );
  } finally {
    broker.close();
  }
});
