import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { after, before, test } from "node:test";

import { Broker } from "../dist/broker.js";
import { BlindDropError } from "../dist/errors.js";
import {
  isAddressPermitted,
  selectValidatedAddress,
} from "../dist/netguard.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const certificatePath = join(testDirectory, "fixtures", "localhost-cert.pem");
const keyPath = join(testDirectory, "fixtures", "localhost-key.pem");

const CREDENTIALS = Object.freeze({
  bearer: "dummy-bearer-Z8k4C2q9",
  username: "dummyuserZ8k4",
  password: "dummy-pass-C2q9",
  header: "dummy-header-V7m3N1p8",
  query: "dummy query/+?&-R6t2",
});

let server;
let origin;
const records = [];
const heldResponses = [];
const temporaryDirectories = new Set();

async function requestBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

before(async () => {
  server = createServer(
    {
      cert: readFileSync(certificatePath),
      key: readFileSync(keyPath),
    },
    async (request, response) => {
      const body = await requestBody(request);
      const record = {
        method: request.method,
        url: request.url,
        headers: { ...request.headers },
        rawHeaders: [...request.rawHeaders],
        body,
      };
      records.push(record);

      const url = new URL(request.url, "https://fixture.invalid");
      switch (url.pathname) {
        case "/redirect":
          response.writeHead(302, { location: "/redirect-target" });
          response.end("redirected");
          return;
        case "/reflect-header":
          response.setHeader("x-reflected", request.headers.authorization ?? "");
          response.end("safe");
          return;
        case "/reflect-body":
          response.end(request.headers.authorization ?? request.headers["x-api-key"] ?? "");
          return;
        case "/reflect-query":
          response.end(request.url);
          return;
        case "/gzip": {
          const encoded = gzipSync("decoded response");
          response.writeHead(200, {
            "content-encoding": "gzip",
            "content-length": String(encoded.length),
          });
          response.end(encoded);
          return;
        }
        case "/deflate":
          response.writeHead(200, { "content-encoding": "deflate" });
          response.end(deflateSync("deflate response"));
          return;
        case "/brotli":
          response.writeHead(200, { "content-encoding": "br" });
          response.end(brotliCompressSync("brotli response"));
          return;
        case "/gzip-reflect": {
          const encoded = gzipSync(request.headers.authorization ?? "");
          response.writeHead(200, { "content-encoding": "gzip" });
          response.end(encoded);
          return;
        }
        case "/large":
          response.end("x".repeat(2048));
          return;
        case "/compressed-large": {
          const encoded = gzipSync("x".repeat(4096));
          response.writeHead(200, { "content-encoding": "gzip" });
          response.end(encoded);
          return;
        }
        case "/large-header":
          response.setHeader("x-large", "x".repeat(2048));
          response.end("safe");
          return;
        case "/invalid-utf8":
          response.end(Buffer.from([0xff, 0xfe, 0xfd]));
          return;
        case "/unsupported-encoding":
          response.writeHead(200, { "content-encoding": "compress" });
          response.end("encoded");
          return;
        case "/filtered-headers":
          response.setHeader("set-cookie", "session=unsafe");
          response.setHeader("strict-transport-security", "max-age=100");
          response.setHeader("alt-svc", 'h3=":443"');
          response.setHeader("x-safe", "present");
          response.end("safe");
          return;
        case "/prototype-response":
          response.setHeader("constructor", "present");
          response.end("safe");
          return;
        case "/reflect-trailer":
          response.writeHead(200, { trailer: "x-reflected" });
          response.write("safe");
          response.addTrailers({ "x-reflected": request.headers.authorization ?? "" });
          response.end();
          return;
        case "/reflect-status":
          response.writeHead(299, request.headers.authorization ?? "reflected");
          response.end("safe");
          return;
        case "/delay":
          setTimeout(() => {
            if (!response.destroyed) {
              response.end("late");
            }
          }, 150);
          return;
        case "/hold":
          heldResponses.push(response);
          return;
        default:
          response.setHeader("content-type", "application/json");
          response.end('{"ok":true}');
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
  for (const response of heldResponses.splice(0)) {
    if (!response.destroyed) {
      response.end("released");
    }
  }
  await new Promise((resolve) => server.close(resolve));
  for (const directory of temporaryDirectories) {
    rmSync(directory, { recursive: true, force: true });
  }
  temporaryDirectories.clear();
});

function secret(value, enabled = true) {
  return {
    type: "api-key",
    fields: { value: { value, label: "Value", masked: true, multiline: false } },
    enabled,
  };
}

function vaultFor(targetOrigin = origin) {
  const now = new Date().toISOString();
  return {
    version: 2,
    createdAt: now,
    updatedAt: now,
    secrets: {
      bearer: secret(CREDENTIALS.bearer),
      username: secret(CREDENTIALS.username),
      password: secret(CREDENTIALS.password),
      header: secret(CREDENTIALS.header),
      query: secret(CREDENTIALS.query),
      disabled: secret("dummy-disabled-Q1w2E3r4", false),
    },
    connections: {
      bearer: {
        origin: targetOrigin,
        auth: { type: "bearer", secret: "bearer" },
        allowPrivate: true,
        enabled: true,
      },
      basic: {
        origin: targetOrigin,
        auth: {
          type: "basic",
          usernameSecret: "username",
          passwordSecret: "password",
        },
        allowPrivate: true,
        enabled: true,
      },
      header: {
        origin: targetOrigin,
        auth: { type: "header", secret: "header", name: "X-Api-Key" },
        allowPrivate: true,
        enabled: true,
      },
      prototypeHeader: {
        origin: targetOrigin,
        auth: { type: "header", secret: "header", name: "__proto__" },
        allowPrivate: true,
        enabled: true,
      },
      query: {
        origin: targetOrigin,
        auth: { type: "query", secret: "query", name: "token" },
        allowPrivate: true,
        enabled: true,
      },
      public: {
        origin: targetOrigin,
        auth: { type: "bearer", secret: "bearer" },
        allowPrivate: false,
        enabled: true,
      },
      disabledConnection: {
        origin: targetOrigin,
        auth: { type: "bearer", secret: "bearer" },
        allowPrivate: true,
        enabled: false,
      },
      disabledSecret: {
        origin: targetOrigin,
        auth: { type: "header", secret: "disabled", name: "X-Api-Key" },
        allowPrivate: true,
        enabled: true,
      },
    },
  };
}

function createBroker({
  vault = vaultFor(),
  connections = Object.keys(vault.connections),
  expiresAt = Date.now() + 60_000,
  limits,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "blinddrop-broker-"));
  temporaryDirectories.add(directory);
  const logPath = join(directory, "events.jsonl");
  const grant = { id: "grant-fixture", connections, expiresAt };
  const broker = new Broker(vault, grant, { logPath, limits });
  return { broker, grant, logPath, vault };
}

async function rejectsCode(value, code) {
  await assert.rejects(value, (error) => {
    assert.ok(error instanceof BlindDropError);
    assert.equal(error.code, code);
    assert.equal(error.message, new BlindDropError(code).message);
    return true;
  });
}

async function waitFor(predicate) {
  const deadline = Date.now() + 1000;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error("fixture wait timed out");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("all four authentication formats override conflicting agent fields", async () => {
  const { broker } = createBroker();
  try {
    let start = records.length;
    await broker.execute({
      connection: "bearer",
      method: "POST",
      path: "/inspect",
      headers: {
        Authorization: "Bearer attacker-one",
        authorization: "Bearer attacker-two",
        Host: "attacker.invalid",
        Connection: "X-Remove",
        "X-Remove": "must-not-pass",
        "Proxy-Authorization": "Basic attacker",
        "Content-Length": "9999",
        Expect: "100-continue",
        Forwarded: "host=attacker.invalid;proto=http",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": "attacker.invalid",
        "X-Forwarded-Port": "80",
        "X-Forwarded-Proto": "http",
      },
      body: "hé",
    });
    let received = records[start];
    assert.equal(received.headers.authorization, `Bearer ${CREDENTIALS.bearer}`);
    assert.equal(received.headers.host, new URL(origin).host);
    assert.equal(received.headers["x-remove"], undefined);
    assert.equal(received.headers["proxy-authorization"], undefined);
    assert.equal(received.headers.expect, undefined);
    assert.equal(received.headers.forwarded, undefined);
    assert.equal(received.headers["x-forwarded-for"], undefined);
    assert.equal(received.headers["x-forwarded-host"], undefined);
    assert.equal(received.headers["x-forwarded-port"], undefined);
    assert.equal(received.headers["x-forwarded-proto"], undefined);
    assert.equal(received.headers["content-length"], "3");

    start = records.length;
    await broker.execute({ connection: "basic", path: "/inspect", headers: { AUTHORIZATION: "attacker" } });
    received = records[start];
    const basic = Buffer.from(`${CREDENTIALS.username}:${CREDENTIALS.password}`).toString("base64");
    assert.equal(received.headers.authorization, `Basic ${basic}`);

    start = records.length;
    await broker.execute({
      connection: "header",
      path: "/inspect",
      headers: { "X-API-KEY": "attacker", "x-api-key": "attacker-two" },
    });
    received = records[start];
    assert.equal(received.headers["x-api-key"], CREDENTIALS.header);

    start = records.length;
    await broker.execute({ connection: "prototypeHeader", path: "/inspect" });
    received = records[start];
    const prototypeHeaderIndex = received.rawHeaders.findIndex(
      (value, index) => index % 2 === 0 && value.toLowerCase() === "__proto__",
    );
    assert.notEqual(prototypeHeaderIndex, -1);
    assert.equal(received.rawHeaders[prototypeHeaderIndex + 1], CREDENTIALS.header);

    start = records.length;
    await broker.execute({
      connection: "query",
      path: "/inspect?token=attacker-one&token=attacker-two",
      query: { token: "attacker-three", safe: "visible" },
    });
    received = records[start];
    const receivedUrl = new URL(received.url, origin);
    assert.deepEqual(receivedUrl.searchParams.getAll("token"), [CREDENTIALS.query]);
    assert.equal(receivedUrl.searchParams.get("safe"), "visible");
  } finally {
    broker.close();
  }
});

test("the broker uses fixed vault and grant snapshots", async () => {
  const state = createBroker();
  try {
    state.vault.secrets.bearer.fields.value.value = "mutated-secret";
    state.vault.connections.bearer.enabled = false;
    state.grant.connections.length = 0;
    const start = records.length;
    await state.broker.execute({ connection: "bearer", path: "/inspect" });
    assert.equal(records[start].headers.authorization, `Bearer ${CREDENTIALS.bearer}`);
  } finally {
    state.broker.close();
  }
});

test("scope, expiry, disabled records, unsafe targets, and private rebinding dispatch nothing", async () => {
  const invalidBasicVault = vaultFor();
  invalidBasicVault.secrets.username.fields.value.value = "invalid:user";
  const cases = [
    {
      state: createBroker({ connections: ["header"] }),
      input: { connection: "bearer", path: "/inspect" },
      code: "ACCESS_DENIED",
    },
    {
      state: createBroker({ expiresAt: Date.now() - 1 }),
      input: { connection: "bearer", path: "/inspect" },
      code: "SESSION_EXPIRED",
    },
    {
      state: createBroker(),
      input: { connection: "disabledConnection", path: "/inspect" },
      code: "CONNECTION_NOT_FOUND",
    },
    {
      state: createBroker(),
      input: { connection: "disabledSecret", path: "/inspect" },
      code: "SECRET_NOT_FOUND",
    },
    {
      state: createBroker(),
      input: { connection: "bearer", path: "https://attacker.invalid/" },
      code: "INVALID_INPUT",
    },
    {
      state: createBroker(),
      input: { connection: "bearer", path: "//attacker.invalid/" },
      code: "INVALID_INPUT",
    },
    {
      state: createBroker(),
      input: { connection: "bearer", path: "/\\attacker.invalid/" },
      code: "INVALID_INPUT",
    },
    {
      state: createBroker(),
      input: { connection: "bearer", path: "/safe#fragment" },
      code: "INVALID_INPUT",
    },
    {
      state: createBroker(),
      input: { connection: "public", path: "/inspect" },
      code: "DESTINATION_DENIED",
    },
    {
      state: createBroker({ vault: invalidBasicVault }),
      input: { connection: "basic", path: "/inspect" },
      code: "INVALID_INPUT",
    },
  ];

  for (const { state, input, code } of cases) {
    const start = records.length;
    try {
      await rejectsCode(state.broker.execute(input), code);
      assert.equal(records.length, start);
    } finally {
      state.broker.close();
    }
  }
});

test("redirect responses are returned without a second request", async () => {
  const { broker } = createBroker();
  try {
    const start = records.length;
    const result = await broker.execute({ connection: "bearer", path: "/redirect" });
    assert.equal(result.status, 302);
    assert.equal(result.headers.location, "/redirect-target");
    assert.equal(records.length, start + 1);
    assert.equal(records[start].url, "/redirect");
  } finally {
    broker.close();
  }
});

test("direct credentials and generated wire forms are blocked in complete responses", async () => {
  const { broker } = createBroker();
  try {
    await rejectsCode(
      broker.execute({ connection: "bearer", path: "/reflect-header" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "bearer", path: "/reflect-body" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "basic", path: "/reflect-body" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "query", path: "/reflect-query" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "bearer", path: "/gzip-reflect" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "bearer", path: "/reflect-trailer" }),
      "RESPONSE_BLOCKED",
    );
    await rejectsCode(
      broker.execute({ connection: "bearer", path: "/reflect-status" }),
      "RESPONSE_BLOCKED",
    );
  } finally {
    broker.close();
  }
});

test("responses are bounded, decoded before inspection, and restricted to UTF-8", async () => {
  const decoded = createBroker({ limits: { responseBytes: 1024 } });
  try {
    const result = await decoded.broker.execute({ connection: "bearer", path: "/gzip" });
    assert.equal(result.body, "decoded response");
    assert.equal(result.headers["content-encoding"], undefined);
    assert.equal(result.headers["content-length"], undefined);
    assert.equal(
      (await decoded.broker.execute({ connection: "bearer", path: "/deflate" })).body,
      "deflate response",
    );
    assert.equal(
      (await decoded.broker.execute({ connection: "bearer", path: "/brotli" })).body,
      "brotli response",
    );
  } finally {
    decoded.broker.close();
  }

  for (const [path, code, limits] of [
    ["/large", "RESPONSE_TOO_LARGE", { responseBytes: 128 }],
    ["/compressed-large", "RESPONSE_TOO_LARGE", { responseBytes: 128 }],
    ["/large-header", "RESPONSE_TOO_LARGE", { headerBytes: 512 }],
    ["/invalid-utf8", "UNSUPPORTED_RESPONSE", undefined],
    ["/unsupported-encoding", "UNSUPPORTED_RESPONSE", undefined],
  ]) {
    const { broker } = createBroker({ limits });
    try {
      await rejectsCode(broker.execute({ connection: "bearer", path }), code);
    } finally {
      broker.close();
    }
  }
});

test("unsafe transport response headers are stripped", async () => {
  const { broker } = createBroker();
  try {
    const result = await broker.execute({ connection: "bearer", path: "/filtered-headers" });
    assert.equal(result.headers["x-safe"], "present");
    assert.equal(result.headers["set-cookie"], undefined);
    assert.equal(result.headers["strict-transport-security"], undefined);
    assert.equal(result.headers["alt-svc"], undefined);
    assert.equal(result.headers["content-length"], undefined);
    const prototypeResult = await broker.execute({
      connection: "bearer",
      path: "/prototype-response",
    });
    assert.equal(Object.hasOwn(prototypeResult.headers, "constructor"), true);
    assert.equal(prototypeResult.headers.constructor, "present");
  } finally {
    broker.close();
  }
});

test("request size, total timeout, concurrency, and close are enforced", async () => {
  const oversized = createBroker({ limits: { requestBytes: 256 } });
  try {
    const start = records.length;
    await rejectsCode(
      oversized.broker.execute({ connection: "bearer", path: "/inspect", body: "x".repeat(512) }),
      "REQUEST_TOO_LARGE",
    );
    assert.equal(records.length, start);
  } finally {
    oversized.broker.close();
  }

  const timed = createBroker({ limits: { timeoutMs: 30 } });
  try {
    await rejectsCode(
      timed.broker.execute({ connection: "bearer", path: "/delay" }),
      "TIMEOUT",
    );
  } finally {
    timed.broker.close();
  }

  const concurrent = createBroker({ limits: { concurrency: 1 } });
  try {
    const start = records.length;
    const first = concurrent.broker.execute({ connection: "bearer", path: "/hold" });
    await waitFor(() => records.length > start);
    await rejectsCode(
      concurrent.broker.execute({ connection: "bearer", path: "/inspect" }),
      "BUSY",
    );
    assert.equal(records.length, start + 1);
    heldResponses.shift().end("released");
    assert.equal((await first).body, "released");
  } finally {
    concurrent.broker.close();
  }

  const closing = createBroker();
  const start = records.length;
  const pending = closing.broker.execute({ connection: "bearer", path: "/delay" });
  await waitFor(() => records.length > start);
  closing.broker.close();
  await rejectsCode(pending, "SESSION_CLOSED");
  await rejectsCode(
    closing.broker.execute({ connection: "bearer", path: "/inspect" }),
    "SESSION_CLOSED",
  );
});

test("public destinations reject private, reserved, mapped, or mixed resolver results", () => {
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "192.0.2.1",
    "224.0.0.1",
    "::1",
    "fe80::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "2001:db8::1",
  ]) {
    assert.equal(isAddressPermitted(address, false), false, address);
  }
  assert.equal(isAddressPermitted("8.8.8.8", false), true);
  assert.equal(isAddressPermitted("2001:4860:4860::8888", false), true);
  assert.equal(isAddressPermitted("127.0.0.1", true), true);
  assert.equal(isAddressPermitted("0.0.0.0", true), false);
  assert.equal(isAddressPermitted("0.1.2.3", true), false);
  assert.equal(isAddressPermitted("::", true), false);
  assert.equal(isAddressPermitted("::ffff:0.0.0.0", true), false);
  assert.equal(isAddressPermitted("169.254.169.254", true), false);
  assert.equal(isAddressPermitted("::ffff:169.254.169.254", true), false);
  assert.equal(isAddressPermitted("fd00:ec2::254", true), false);
  assert.equal(isAddressPermitted("fd20:ce::254", true), false);
  assert.equal(isAddressPermitted("100.100.100.200", true), false);
  assert.equal(isAddressPermitted("::ffff:100.100.100.200", true), false);

  assert.throws(
    () => selectValidatedAddress(
      [
        { address: "8.8.8.8", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ],
      false,
    ),
    (error) => error instanceof BlindDropError && error.code === "DESTINATION_DENIED",
  );
  assert.deepEqual(
    selectValidatedAddress([{ address: "8.8.8.8", family: 4 }], false),
    { address: "8.8.8.8", family: 4 },
  );
});

test("errors and mode-0600 use logs exclude credentials and request values", async () => {
  const state = createBroker();
  const userMarker = "agent-private-request-marker";
  try {
    await state.broker.execute({
      connection: "bearer",
      path: "/inspect",
      query: { q: userMarker },
      headers: { "x-user-value": userMarker },
      body: userMarker,
    });
    await rejectsCode(
      state.broker.execute({ connection: "basic", path: "/reflect-body" }),
      "RESPONSE_BLOCKED",
    );

    const contents = readFileSync(state.logPath, "utf8");
    for (const forbidden of [...Object.values(CREDENTIALS), userMarker, "Basic "]) {
      assert.equal(contents.includes(forbidden), false, forbidden);
    }
    const events = contents.trim().split("\n").map((line) => JSON.parse(line));
    assert.deepEqual(
      Object.keys(events[0]).sort(),
      ["code", "connection", "grantId", "outcome", "timestamp"],
    );
    assert.equal(events[0].outcome, "success");
    assert.equal(events[1].code, "RESPONSE_BLOCKED");
    assert.equal(statSync(state.logPath).mode & 0o777, 0o600);
  } finally {
    state.broker.close();
  }

  const listener = createTcpServer();
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const address = listener.address();
  const unavailableOrigin = `https://127.0.0.1:${address.port}`;
  await new Promise((resolve) => listener.close(resolve));

  const unavailable = createBroker({ vault: vaultFor(unavailableOrigin), connections: ["bearer"] });
  try {
    await rejectsCode(
      unavailable.broker.execute({ connection: "bearer", path: "/request-secret-marker" }),
      "UPSTREAM_ERROR",
    );
  } finally {
    unavailable.broker.close();
  }
});
