// Phase 1 (v0.5.1 "blinddrop") functional tests: typed multi-field secrets,
// vault-qualified references, multiple vaults, and migration. Every test drives
// the real built runtime against a disposable HTTPS receiver with generated
// credentials, in temp vaults under a scratch HOME. No mocks, no synthetic
// assertions: each proves a reachable product behavior and fails on a real
// regression.

import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, randomBytes, scryptSync } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AuthSession } from "../dist/auth.js";
import { createBrokerSession } from "../dist/session.js";
import { sendHttps } from "../dist/transport.js";
import { createVault, loadVault, saveVault } from "../dist/vault.js";

const limits = {
  requestBytes: 1024 * 1024,
  responseBytes: 4 * 1024 * 1024,
  headerBytes: 16 * 1024,
  timeoutMs: 10_000,
  concurrency: 4,
};

// A field in the v0.5.1 shape. Masking/multiline are display metadata; the
// runtime resolves by field id regardless.
function field(value, masked = true, multiline = false) {
  return { value, label: "Field", masked, multiline };
}

function secret(type, fields, enabled = true) {
  return { type, fields, enabled };
}

async function startReceiver(t, handler) {
  const server = createServer(
    {
      key: await readFile(new URL("./fixtures/localhost-key.pem", import.meta.url)),
      cert: await readFile(new URL("./fixtures/localhost-cert.pem", import.meta.url)),
    },
    handler,
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.close();
    await once(server, "close");
  });
  return `https://127.0.0.1:${server.address().port}`;
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

// Writes a genuine pre-v0.5.1 (payload version 1) archive using the exact
// documented envelope (version byte 2, scrypt N=131072,r=8,p=1, AES-256-GCM,
// fresh salt/iv). The runtime cannot write v1 any more, so migration must be
// proven against a file built here, not one the new code produced.
async function writeV1Archive(path, payload, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  await writeFile(path, Buffer.concat([Buffer.from([2]), salt, iv, tag, ciphertext]), { mode: 0o600 });
}

// --- Compact AWS SigV4 verifier (proves the resolved secret key actually signed) ---

function awsEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function hmac(key, value) {
  return createHmac("sha256", key).update(value).digest();
}
function canonicalQuery(url) {
  return [...url.searchParams]
    .map(([n, v]) => [awsEncode(n), awsEncode(v)])
    .sort(([an, av], [bn, bv]) => (an !== bn ? (an < bn ? -1 : 1) : av === bv ? 0 : av < bv ? -1 : 1))
    .map(([n, v]) => `${n}=${v}`)
    .join("&");
}
function verifyAwsRequest(req, body, expected) {
  const authorization = req.headers.authorization ?? "";
  const match = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(authorization);
  if (!match) return false;
  const [, accessKeyId, shortDate, region, service, signedHeaderText, actualSignature] = match;
  if (accessKeyId !== expected.accessKeyId || region !== expected.region || service !== expected.service) return false;
  const signedHeaders = signedHeaderText.split(";");
  const canonicalHeaders = signedHeaders
    .map((name) => `${name}:${String(req.headers[name]).trim().replace(/\s+/g, " ")}\n`)
    .join("");
  const url = new URL(req.url, "https://receiver.invalid");
  const canonicalRequest = [req.method, url.pathname, canonicalQuery(url), canonicalHeaders, signedHeaderText, sha256(body)].join("\n");
  const longDate = req.headers["x-amz-date"];
  if (typeof longDate !== "string" || !longDate.startsWith(shortDate)) return false;
  const scope = `${shortDate}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${longDate}\n${scope}\n${sha256(canonicalRequest)}`;
  const dateKey = hmac(`AWS4${expected.secretAccessKey}`, shortDate);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, service);
  const signingKey = hmac(serviceKey, "aws4_request");
  return createHmac("sha256", signingKey).update(stringToSign).digest("hex") === actualSignature;
}

async function execute(sessionVaults, connections, input) {
  const { broker } = createBrokerSession(sessionVaults, connections, 120);
  try {
    return { broker, result: await broker.execute(input) };
  } finally {
    broker.close();
  }
}

test("multi-field secrets resolve per field into real aws-sigv4, basic, and bearer requests", { timeout: 30_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-multifield-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const creds = {
    accessKeyId: "AKID" + randomBytes(8).toString("hex").toUpperCase(),
    secretAccessKey: randomBytes(24).toString("base64"),
    region: "us-east-1",
    service: "s3",
    username: "user-" + randomBytes(4).toString("hex"),
    password: "pw-" + randomBytes(12).toString("hex"),
    token: "tok-" + randomBytes(16).toString("hex"),
  };
  const seen = { basic: undefined, bearer: undefined };

  const origin = await startReceiver(t, async (req, res) => {
    const body = await readRequestBody(req);
    if (req.url.startsWith("/aws")) {
      const ok = verifyAwsRequest(req, body, creds);
      res.writeHead(ok ? 200 : 403, { "content-type": "application/json" });
      res.end(JSON.stringify(ok ? { bucket: "ok" } : { error: "signature mismatch" }));
      return;
    }
    if (req.url === "/basic") {
      seen.basic = req.headers.authorization;
      const decoded = Buffer.from((req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString("utf8");
      const ok = decoded === `${creds.username}:${creds.password}`;
      res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
      res.end(JSON.stringify(ok ? { account: "ok" } : { error: "bad basic" }));
      return;
    }
    if (req.url === "/bearer") {
      seen.bearer = req.headers.authorization;
      const ok = req.headers.authorization === `Bearer ${creds.token}`;
      res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
      res.end(JSON.stringify(ok ? { account: "ok" } : { error: "bad bearer" }));
      return;
    }
    res.writeHead(404).end();
  });

  const path = join(dir, "vault.enc");
  const passphrase = randomBytes(24).toString("hex");
  const vault = createVault(path, passphrase);
  vault.secrets.awskeys = secret("aws", {
    aws_access_key_id: field(creds.accessKeyId, false),
    aws_secret_access_key: field(creds.secretAccessKey, true),
  });
  vault.secrets.login = secret("login", {
    username: field(creds.username, false),
    password: field(creds.password, true),
  });
  vault.secrets.apikey = secret("api-key", { token: field(creds.token, true) });
  vault.connections.s3 = {
    origin,
    auth: {
      type: "aws-sigv4",
      accessKeyIdSecret: "awskeys#aws_access_key_id",
      secretAccessKeySecret: "awskeys#aws_secret_access_key",
      region: creds.region,
      service: creds.service,
    },
    allowPrivate: true,
    enabled: true,
  };
  vault.connections.site = {
    origin,
    auth: { type: "basic", usernameSecret: "login#username", passwordSecret: "login#password" },
    allowPrivate: true,
    enabled: true,
  };
  vault.connections.api = {
    origin,
    auth: { type: "bearer", secret: "apikey#token" },
    allowPrivate: true,
    enabled: true,
  };
  saveVault(path, vault, passphrase);

  const unlock = [{ name: "default", path, passphrase }];

  const aws = await execute(unlock, ["s3"], { connection: "s3", method: "PUT", path: "/aws/object?z=2&a=b&a=a", body: "payload" });
  assert.equal(aws.result.status, 200, "aws_secret_access_key field signs a signature the receiver accepts");

  const basic = await execute(unlock, ["site"], { connection: "site", path: "/basic" });
  assert.equal(basic.result.status, 200, "username and password fields of one login secret resolve to the Basic header");
  assert.equal(seen.basic, `Basic ${Buffer.from(`${creds.username}:${creds.password}`).toString("base64")}`);

  const bearer = await execute(unlock, ["api"], { connection: "api", path: "/bearer" });
  assert.equal(bearer.result.status, 200, "token field resolves to the bearer header");
  assert.equal(seen.bearer, `Bearer ${creds.token}`);

  // Wrong field id must not resolve: a reference to a field that does not exist
  // is unusable, proving resolution is per-field, not per-secret.
  const wrong = { ...vault.connections.api, auth: { type: "bearer", secret: "apikey#nonexistent_field" } };
  vault.connections.wrong = wrong;
  saveVault(path, vault, passphrase);
  await assert.rejects(
    () => execute(unlock, ["wrong"], { connection: "wrong", path: "/bearer" }),
    (error) => error?.code === "SECRET_NOT_FOUND",
  );

  // Credential scan: no field value or passphrase in the use log.
  const log = await readFile(path + ".events.jsonl", "utf8");
  for (const v of [creds.secretAccessKey, creds.password, creds.token, passphrase]) {
    assert.equal(log.includes(v), false, "credential absent from the use log");
  }
});

test("a genuine v1 archive migrates: secrets become fields, bare references resolve, and a request authenticates", { timeout: 30_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-migrate-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const token = "legacy-" + randomBytes(16).toString("hex");
  let sawAuth;
  const origin = await startReceiver(t, async (req, res) => {
    await readRequestBody(req);
    sawAuth = req.headers.authorization;
    const ok = req.headers.authorization === `Bearer ${token}`;
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify(ok ? { account: "ok" } : { error: "unauthorized" }));
  });

  const path = join(dir, "vault.enc");
  const passphrase = randomBytes(24).toString("hex");
  const now = new Date().toISOString();
  // A pre-v0.5.1 payload: single-value secrets, a bare-name reference.
  const v1 = {
    version: 1,
    createdAt: now,
    updatedAt: now,
    secrets: { legacy: { value: token, enabled: true } },
    connections: { api: { origin, auth: { type: "bearer", secret: "legacy" }, allowPrivate: true, enabled: true } },
  };
  await writeV1Archive(path, v1, passphrase);

  const migrated = loadVault(path, passphrase);
  assert.equal(migrated.version, 2, "the payload is migrated to the current version in memory");
  assert.deepEqual(Object.keys(migrated.secrets.legacy.fields), ["value"], "the single value becomes a default-named field");
  assert.equal(migrated.secrets.legacy.fields.value.value, token);
  // The reference is rewritten to be explicit, and still targets the same value.
  assert.equal(migrated.connections.api.auth.secret, "legacy#value");

  const { broker } = createBrokerSession([{ name: "default", path, passphrase }], ["api"], 120);
  t.after(() => broker.close());
  const result = await broker.execute({ connection: "api", path: "/resource" });
  assert.equal(result.status, 200, "the migrated bearer reference authenticates a real request");
  assert.equal(sawAuth, `Bearer ${token}`);

  // A corrupt or truncated archive fails explicitly, never a silent reset.
  const archive = await readFile(path);
  const flipped = Buffer.from(archive);
  flipped[flipped.length - 1] ^= 0xff;
  const flippedPath = join(dir, "flipped.enc");
  await writeFile(flippedPath, flipped, { mode: 0o600 });
  assert.throws(() => loadVault(flippedPath, passphrase), (e) => e?.code === "UNLOCK_FAILED");
  const truncatedPath = join(dir, "truncated.enc");
  await writeFile(truncatedPath, archive.subarray(0, 45), { mode: 0o600 });
  assert.throws(() => loadVault(truncatedPath, passphrase), (e) => e?.code === "VAULT_INVALID");
});

test("a v2 payload with a bare reference still resolves to the default field (section 4 guarantee)", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-bare-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "vault.enc");
  const passphrase = randomBytes(24).toString("hex");
  const token = "bare-" + randomBytes(12).toString("hex");
  const vault = createVault(path, passphrase);
  vault.secrets.tok = secret("api-key", { value: field(token) });
  // A bare reference (no field) — the migration/back-compat form.
  vault.connections.api = { origin: "https://example.com", auth: { type: "bearer", secret: "tok" }, allowPrivate: false, enabled: true };
  saveVault(path, vault, passphrase);

  const session = new AuthSession(loadVault(path, passphrase));
  const prepared = await session.prepare(
    "api",
    loadVault(path, passphrase).connections.api,
    { url: new URL("https://example.com/x"), method: "GET", headers: { host: "example.com" } },
    sendHttps,
    AbortSignal.timeout(1000),
    limits,
  );
  session.close();
  assert.equal(prepared.request.headers.authorization, `Bearer ${token}`, "a bare reference resolves to the default field value");
});

async function buildVault(dir, name, mutate) {
  const path = join(dir, `${name}.enc`);
  const passphrase = randomBytes(24).toString("hex");
  const vault = createVault(path, passphrase);
  mutate(vault);
  saveVault(path, vault, passphrase);
  return { name, path, passphrase };
}

test("cross-vault span: a connection is usable only when both vaults are unlocked; locking one drops exactly its connections", { timeout: 30_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-span-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const credA = "a-" + randomBytes(12).toString("hex");
  const credB = "b-" + randomBytes(12).toString("hex");
  const received = [];
  const origin = await startReceiver(t, async (req, res) => {
    await readRequestBody(req);
    received.push({ a: req.headers["x-cred-a"], b: req.headers["x-cred-b"] });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ account: "ok" }));
  });

  // Vault A holds keyA plus both connections; vault B holds keyB. The span
  // connection references keyA in vault A and keyB in vault B.
  const vaultA = await buildVault(dir, "a", (v) => {
    v.secrets.keyA = secret("api-key", { value: field(credA) });
    v.connections.span = {
      origin,
      auth: {
        type: "bindings",
        bindings: [
          { in: "header", name: "X-Cred-A", secret: "a#keyA#value" },
          { in: "header", name: "X-Cred-B", secret: "b#keyB#value" },
        ],
      },
      allowPrivate: true,
      enabled: true,
    };
    v.connections.soloA = {
      origin,
      auth: { type: "bindings", bindings: [{ in: "header", name: "X-Cred-A", secret: "a#keyA#value" }] },
      allowPrivate: true,
      enabled: true,
    };
  });
  const vaultB = await buildVault(dir, "b", (v) => {
    v.secrets.keyB = secret("api-key", { value: field(credB) });
  });

  // Both unlocked: the span connection resolves both vaults and reaches the receiver with both credentials.
  {
    const { broker } = createBrokerSession([vaultA, vaultB], ["span", "soloA"], 120);
    t.after(() => broker.close());
    assert.deepEqual(broker.listConnections().map((c) => c.name).sort(), ["soloA", "span"]);
    const result = await broker.execute({ connection: "span", path: "/x" });
    assert.equal(result.status, 200);
    assert.deepEqual(received.at(-1), { a: credA, b: credB }, "both vaults' field values were resolved into one request");
    broker.close();
  }

  // Vault B locked (unlock A only): the span connection cannot be granted, but the vault-A-only connection still works.
  assert.throws(
    () => createBrokerSession([vaultA], ["span"], 120),
    (error) => error?.code === "SECRET_NOT_FOUND",
    "a connection spanning a locked vault is not grantable",
  );
  {
    const { broker } = createBrokerSession([vaultA], ["soloA"], 120);
    t.after(() => broker.close());
    assert.deepEqual(broker.listConnections().map((c) => c.name), ["soloA"], "only the vault-A connection remains in the session");
    const result = await broker.execute({ connection: "soloA", path: "/x" });
    assert.equal(result.status, 200);
    assert.equal(received.at(-1).a, credA);
    broker.close();
  }

  // If span is nonetheless granted while B is locked, listing and execution refuse it — B's value never enters the request.
  {
    const { broker } = createBrokerSession([vaultA], ["soloA"], 120);
    t.after(() => broker.close());
    await assert.rejects(
      () => broker.execute({ connection: "span", path: "/x" }),
      (error) => error?.code === "ACCESS_DENIED" || error?.code === "SECRET_NOT_FOUND",
    );
    broker.close();
  }
});

test("compartmentalization: a locked vault's values never resolve or enter the session", { timeout: 30_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-compartment-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const credA = "a-" + randomBytes(12).toString("hex");
  const credB = "b-" + randomBytes(12).toString("hex");
  const origin = await startReceiver(t, async (req, res) => {
    await readRequestBody(req);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ account: "ok" }));
  });

  const vaultA = await buildVault(dir, "a", (v) => {
    v.secrets.keyA = secret("api-key", { value: field(credA) });
    v.connections.soloA = {
      origin,
      auth: { type: "header", name: "X-Cred-A", secret: "a#keyA#value" },
      allowPrivate: true,
      enabled: true,
    };
    v.connections.needsB = {
      origin,
      auth: { type: "header", name: "X-Cred-B", secret: "b#keyB#value" },
      allowPrivate: true,
      enabled: true,
    };
  });
  await buildVault(dir, "b", (v) => {
    v.secrets.keyB = secret("api-key", { value: field(credB) });
  });

  // Unlock only vault A. The connection that needs vault B cannot be granted,
  // and vault B's value never enters the running session or its log.
  assert.throws(
    () => createBrokerSession([vaultA], ["needsB"], 120),
    (error) => error?.code === "SECRET_NOT_FOUND",
  );

  const { broker } = createBrokerSession([vaultA], ["soloA"], 120);
  t.after(() => broker.close());
  assert.deepEqual(broker.listConnections().map((c) => c.name), ["soloA"], "the locked vault's connection is not listed");
  const result = await broker.execute({ connection: "soloA", path: "/x" });
  assert.equal(result.status, 200);
  broker.close();

  const log = await readFile(vaultA.path + ".events.jsonl", "utf8");
  assert.equal(log.includes(credB), false, "the locked vault's value never appears in the session log");
  assert.equal(log.includes(credA), false, "no credential value appears in the session log");
  assert.equal(log.includes(vaultA.passphrase), false, "no passphrase appears in the session log");
});

test("OAuth refresh rotation persists the new token into the correct secret field, preserving sibling fields", { timeout: 30_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "blinddrop-v051-rotate-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const clientSecret = "cs-" + randomBytes(16).toString("hex");
  const oldRefresh = "rt-old-" + randomBytes(16).toString("hex");
  const newRefresh = "rt-new-" + randomBytes(16).toString("hex");
  let accessToken;
  let sawOldRefresh = false;

  const origin = await startReceiver(t, async (req, res) => {
    const body = (await readRequestBody(req)).toString("utf8");
    if (req.url === "/token") {
      const form = new URLSearchParams(body);
      if (form.get("grant_type") === "refresh_token" && form.get("refresh_token") === oldRefresh) {
        sawOldRefresh = true;
        accessToken = "at-" + randomBytes(16).toString("hex");
        res.writeHead(200, { "content-type": "application/json" });
        // A rotated refresh token: the runtime must persist it before use.
        res.end(JSON.stringify({ access_token: accessToken, refresh_token: newRefresh, token_type: "Bearer", expires_in: 3600 }));
        return;
      }
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }
    if (req.url === "/resource") {
      const ok = req.headers.authorization === `Bearer ${accessToken}`;
      res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
      res.end(JSON.stringify(ok ? { account: "ok" } : { error: "unauthorized" }));
      return;
    }
    res.writeHead(404).end();
  });

  const path = join(dir, "vault.enc");
  const passphrase = randomBytes(24).toString("hex");
  const vault = createVault(path, passphrase);
  // One secret carries two fields; only refresh_token must rotate.
  vault.secrets.oauthcreds = secret("oauth", {
    client_secret: field(clientSecret, true),
    refresh_token: field(oldRefresh, true),
  });
  vault.connections.api = {
    origin,
    auth: {
      type: "oauth2",
      tokenEndpoint: origin + "/token",
      grant: "refresh_token",
      clientId: "public-client",
      clientSecret: "oauthcreds#client_secret",
      refreshSecret: "oauthcreds#refresh_token",
      clientAuth: "body",
    },
    allowPrivate: true,
    enabled: true,
  };
  saveVault(path, vault, passphrase);

  const { broker } = createBrokerSession([{ name: "default", path, passphrase }], ["api"], 120);
  t.after(() => broker.close());
  const result = await broker.execute({ connection: "api", path: "/resource" });
  assert.equal(result.status, 200, "the refresh grant obtains an access token and reaches the resource");
  assert.equal(sawOldRefresh, true, "the old refresh field value was resolved and presented");
  broker.close();

  const stored = loadVault(path, passphrase);
  assert.equal(stored.secrets.oauthcreds.fields.refresh_token.value, newRefresh, "the rotated refresh token is persisted into its field");
  assert.equal(stored.secrets.oauthcreds.fields.client_secret.value, clientSecret, "the sibling client_secret field is preserved");

  const log = await readFile(path + ".events.jsonl", "utf8");
  for (const v of [clientSecret, oldRefresh, newRefresh, accessToken, passphrase]) {
    assert.equal(log.includes(v), false, "no credential or passphrase appears in the use log");
  }
});
