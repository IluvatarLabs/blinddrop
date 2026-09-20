import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/client";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { loadVault } from "../dist/vault.js";

const projectRoot = join(import.meta.dirname, "..");
const cliPath = join(projectRoot, "dist", "cli.js");
const certificatePath = join(projectRoot, "test", "fixtures", "localhost-cert.pem");
const privateKeyPath = join(projectRoot, "test", "fixtures", "localhost-key.pem");

function collectStream(stream) {
  if (stream === null) {
    return Promise.resolve("");
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    stream.on("error", reject);
  });
}

function childExit(child) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

async function stopSession(session) {
  if (session.child.exitCode === null && session.child.signalCode === null) {
    session.child.stdin.end();
    await childExit(session.child);
  }
  await session.client.close().catch(() => undefined);
}

function spawnCli(args, inheritedInputs = [], options = {}) {
  const child = spawn(process.execPath, [cliPath, ...args], {
    cwd: projectRoot,
    env: { ...process.env, ...options.env },
    stdio: [options.stdin ?? "ignore", "pipe", "pipe", ...inheritedInputs.map(() => "pipe")]
  });

  inheritedInputs.forEach((value, index) => {
    child.stdio[index + 3].end(value);
  });
  return child;
}

async function runCli(args, inheritedInputs = [], options = {}) {
  const child = spawnCli(args, inheritedInputs, options);
  const stdoutPromise = collectStream(child.stdout);
  const stderrPromise = collectStream(child.stderr);
  const [{ code, signal }, stdout, stderr] = await Promise.all([
    childExit(child),
    stdoutPromise,
    stderrPromise
  ]);
  return { code, signal, stdout, stderr };
}

async function expectCliSuccess(args, inheritedInputs, forbidden) {
  const result = await runCli(args, inheritedInputs);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.signal, null);
  for (const value of forbidden) {
    assert.equal(result.stdout.includes(value), false);
    assert.equal(result.stderr.includes(value), false);
  }
  return result;
}

async function startFixture(secret) {
  const [key, cert] = await Promise.all([
    readFile(privateKeyPath),
    readFile(certificatePath)
  ]);
  const received = [];
  const server = createServer({ key, cert }, (request, response) => {
    const entry = { url: request.url, authorization: request.headers.authorization };
    received.push(entry);

    if (request.url === "/reflect") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(secret);
      return;
    }

    if (request.headers.authorization !== `Bearer ${secret}`) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false }));
      return;
    }

    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, "object");
  return {
    origin: `https://127.0.0.1:${address.port}`,
    received,
    async close() {
      server.close();
      await once(server, "close");
    }
  };
}

async function startMcp(vaultPath, passphrase, connection, ttl = 30) {
  const child = spawnCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "serve",
      "--allow",
      connection,
      "--ttl",
      String(ttl)
    ],
    [`${passphrase}\n`],
    {
      stdin: "pipe",
      env: { NODE_EXTRA_CA_CERTS: certificatePath }
    }
  );
  const stderrPromise = collectStream(child.stderr);
  const transport = new StdioServerTransport(child.stdout, child.stdin, {
    maxBufferSize: 2 * 1024 * 1024
  });
  const client = new Client({ name: "blinddrop-functional-test", version: "1.0.0" });
  await client.connect(transport);
  return { child, client, stderrPromise };
}

function textContent(result) {
  return result.content
    .filter((item) => item.type === "text")
    .map((item) => item.text)
    .join("\n");
}

test("real owner CLI and MCP session keep credentials out of the agent interface", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "blinddrop-cli-mcp-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const vaultPath = join(directory, "vault.enc");
  const passphrase = "  disposable vault passphrase  ";
  const originalSecret = "disposable-original-token";
  const replacementSecret = "disposable-replacement-token";
  const whitespaceSecret = "  whitespace is credential data  ";
  const forbidden = [passphrase, originalSecret, replacementSecret, whitespaceSecret];
  const fixture = await startFixture(replacementSecret);
  t.after(() => fixture.close());

  await expectCliSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "init"],
    [`${passphrase}\n`],
    forbidden
  );
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "secret",
      "set",
      "whitespace-token",
      "--secret-fd",
      "4"
    ],
    [`${passphrase}\n`, `${whitespaceSecret}\n`],
    forbidden
  );
  assert.equal(loadVault(vaultPath, passphrase).secrets["whitespace-token"].fields.value.value, whitespaceSecret);
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "secret",
      "set",
      "api-token",
      "--secret-fd",
      "4"
    ],
    [`${passphrase}\n`, `${originalSecret}\n`],
    forbidden
  );

  const inheritedNameMiss = await runCli(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "disable", "toString"],
    [`${passphrase}\n`]
  );
  assert.equal(inheritedNameMiss.code, 1);
  assert.equal(inheritedNameMiss.stderr, "SECRET_NOT_FOUND: The secret is unavailable.\n");

  const inheritedReferenceMiss = await runCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "connection",
      "set",
      "missing-reference",
      "--origin",
      fixture.origin,
      "--auth",
      "bearer",
      "--secret",
      "toString",
      "--allow-private"
    ],
    [`${passphrase}\n`]
  );
  assert.equal(inheritedReferenceMiss.code, 1);
  assert.equal(inheritedReferenceMiss.stderr, "SECRET_NOT_FOUND: The secret is unavailable.\n");

  await expectCliSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "remove", "whitespace-token"],
    [`${passphrase}\n`],
    forbidden
  );
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "secret",
      "set",
      "api-token",
      "--secret-fd",
      "4"
    ],
    [`${passphrase}\n`, `${replacementSecret}\n`],
    forbidden
  );
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "connection",
      "set",
      "fixture-api",
      "--origin",
      fixture.origin,
      "--auth",
      "bearer",
      "--secret",
      "api-token",
      "--allow-private"
    ],
    [`${passphrase}\n`],
    forbidden
  );

  const referencedRemoval = await runCli(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "remove", "api-token"],
    [`${passphrase}\n`]
  );
  assert.equal(referencedRemoval.code, 1);
  assert.equal(referencedRemoval.stderr, "INVALID_INPUT: Invalid input.\n");

  const archive = await readFile(vaultPath);
  for (const value of forbidden) {
    assert.equal(archive.includes(Buffer.from(value)), false);
  }

  const listing = await expectCliSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "list"],
    [`${passphrase}\n`],
    forbidden
  );
  const ownerMetadata = JSON.parse(listing.stdout);
  assert.deepEqual(ownerMetadata.secrets, [{ name: "api-token", enabled: true }]);
  assert.deepEqual(ownerMetadata.connections, [
    {
      name: "fixture-api",
      origin: fixture.origin,
      authType: "bearer",
      allowPrivate: true,
      enabled: true
    }
  ]);

  const session = await startMcp(vaultPath, passphrase, "fixture-api");
  t.after(() => stopSession(session));
  const tools = await session.client.listTools();
  assert.deepEqual(
    tools.tools.map((tool) => tool.name).sort(),
    ["execute_http", "list_connections"]
  );
  assert.equal(JSON.stringify(tools).includes(replacementSecret), false);

  const connections = await session.client.callTool({
    name: "list_connections",
    arguments: {}
  });
  assert.equal(connections.isError, undefined);
  assert.deepEqual(connections.structuredContent, {
    connections: [{ name: "fixture-api", origin: fixture.origin, authType: "bearer" }]
  });
  assert.equal(textContent(connections).includes(replacementSecret), false);

  const authorized = await session.client.callTool({
    name: "execute_http",
    arguments: {
      connection: "fixture-api",
      method: "GET",
      path: "/ok",
      headers: { Authorization: "Bearer caller-controlled" }
    }
  });
  assert.equal(authorized.isError, undefined);
  assert.equal(authorized.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(authorized.structuredContent.body), { ok: true });
  assert.equal(fixture.received.at(-1).authorization, `Bearer ${replacementSecret}`);
  assert.equal(textContent(authorized).includes(replacementSecret), false);

  const denied = await session.client.callTool({
    name: "execute_http",
    arguments: { connection: "outside-grant", path: "/ok" }
  });
  assert.equal(denied.isError, true);
  assert.deepEqual(denied.structuredContent, {
    error: {
      code: "ACCESS_DENIED",
      message: "This session is not authorized for that operation."
    }
  });
  assert.equal(textContent(denied).includes(replacementSecret), false);

  const reflected = await session.client.callTool({
    name: "execute_http",
    arguments: { connection: "fixture-api", path: "/reflect" }
  });
  assert.equal(reflected.isError, true);
  assert.deepEqual(reflected.structuredContent, {
    error: {
      code: "RESPONSE_BLOCKED",
      message: "The upstream response contains credential material."
    }
  });
  assert.equal(textContent(reflected).includes(replacementSecret), false);

  const attackerKey = `attacker-${replacementSecret}`;
  const invalid = await session.client.callTool({
    name: "execute_http",
    arguments: { connection: "fixture-api", path: "/ok", [attackerKey]: true }
  });
  assert.equal(invalid.isError, true);
  assert.equal(textContent(invalid).includes(attackerKey), false);
  assert.equal(textContent(invalid).includes(replacementSecret), false);

  await expectCliSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "disable", "api-token"],
    [`${passphrase}\n`],
    forbidden
  );
  const activeSnapshot = await session.client.callTool({
    name: "execute_http",
    arguments: { connection: "fixture-api", path: "/after-disable" }
  });
  assert.equal(activeSnapshot.isError, undefined);
  assert.equal(activeSnapshot.structuredContent.status, 200);

  session.child.stdin.end();
  const normalExit = await childExit(session.child);
  assert.deepEqual(normalExit, { code: 0, signal: null });
  assert.equal(await session.stderrPromise, "");
  await session.client.close();

  const disabledStart = await runCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "serve",
      "--allow",
      "fixture-api",
      "--ttl",
      "30"
    ],
    [`${passphrase}\n`]
  );
  assert.equal(disabledStart.code, 1);
  assert.match(disabledStart.stderr, /^SECRET_NOT_FOUND: The secret is unavailable\.\n$/);
  for (const value of forbidden) {
    assert.equal(disabledStart.stderr.includes(value), false);
  }
});

test("MCP session process exits at its TTL and on an oversized protocol message", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "blinddrop-mcp-lifetime-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const vaultPath = join(directory, "vault.enc");
  const passphrase = "lifetime-passphrase";
  const secret = "lifetime-token";
  const fixture = await startFixture(secret);
  t.after(() => fixture.close());

  await expectCliSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "init"],
    [`${passphrase}\n`],
    [passphrase, secret]
  );
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "secret",
      "set",
      "token",
      "--secret-fd",
      "4"
    ],
    [`${passphrase}\n`, `${secret}\n`],
    [passphrase, secret]
  );
  await expectCliSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "connection",
      "set",
      "fixture",
      "--origin",
      fixture.origin,
      "--auth",
      "bearer",
      "--secret",
      "token",
      "--allow-private"
    ],
    [`${passphrase}\n`],
    [passphrase, secret]
  );

  const expiring = await startMcp(vaultPath, passphrase, "fixture", 1);
  t.after(() => stopSession(expiring));
  const expiringExit = await Promise.race([
    childExit(expiring.child),
    new Promise((_, reject) => setTimeout(() => reject(new Error("session did not expire")), 4_000))
  ]);
  assert.deepEqual(expiringExit, { code: 0, signal: null });
  assert.equal(await expiring.stderrPromise, "");
  await expiring.client.close();

  const oversized = spawnCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "serve",
      "--allow",
      "fixture",
      "--ttl",
      "30"
    ],
    [`${passphrase}\n`],
    { stdin: "pipe", env: { NODE_EXTRA_CA_CERTS: certificatePath } }
  );
  t.after(async () => {
    if (oversized.exitCode === null && oversized.signalCode === null) {
      oversized.kill("SIGTERM");
      await childExit(oversized);
    }
  });
  const oversizedStderr = collectStream(oversized.stderr);
  oversized.stdin.on("error", () => undefined);
  oversized.stdin.write(Buffer.alloc(2 * 1024 * 1024 + 1, 0x61));
  const oversizedExit = await Promise.race([
    childExit(oversized),
    new Promise((_, reject) => setTimeout(() => reject(new Error("oversized input did not close")), 4_000))
  ]);
  assert.deepEqual(oversizedExit, { code: 0, signal: null });
  assert.doesNotMatch(await oversizedStderr, /lifetime-token|lifetime-passphrase/);
});

test("Commander parse errors are static and do not echo untrusted option text", async () => {
  const attackerText = "attacker-secret-shaped-option";
  const result = await runCli([`--${attackerText}`]);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, "Invalid input.\n");
  assert.equal(result.stdout, "");
});
