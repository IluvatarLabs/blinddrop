#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:https";
import { existsSync } from "node:fs";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import process from "node:process";

import { Client } from "@modelcontextprotocol/client";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

const projectRoot = resolve(import.meta.dirname, "..");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const requiredPackagePaths = [
  "README.md",
  "FLY.md",
  "OAUTH.md",
  "CLIENTS.md",
  "CONFIGURATION.md",
  "CHANGELOG.md",
  "SECURITY.md",
  "examples/anthropic.mjs",
  "examples/request.mjs",
  "LICENSE",
  "THIRD-PARTY-NOTICES.md",
  "dist/cli.js",
  "dist/oauth-login.js",
  "dist/http.js",
  "dist/session.js",
  "dist/stream.js",
];

function collect(stream) {
  return new Promise((resolveOutput, reject) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => resolveOutput(Buffer.concat(chunks).toString("utf8")));
    stream.on("error", reject);
  });
}

function childExit(child) {
  return new Promise((resolveExit, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolveExit({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    child.once("error", reject);
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
  });
}

async function run(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: options.cwd ?? projectRoot,
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  const [exit, output, errorOutput] = await Promise.all([
    childExit(child),
    stdout,
    stderr,
  ]);
  if (exit.code !== 0 || exit.signal !== null) {
    throw new Error(
      `${basename(command)} failed (${exit.code ?? exit.signal}): ${errorOutput || output}`,
    );
  }
  return output;
}

async function runCli(
  binPath,
  args,
  inheritedInputs = [],
  env = process.env,
  cwd = dirname(binPath),
) {
  const child = spawn(binPath, args, {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe", ...inheritedInputs.map(() => "pipe")],
  });
  inheritedInputs.forEach((value, index) => {
    child.stdio[index + 3].end(value);
  });
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  const [exit, output, errorOutput] = await Promise.all([
    childExit(child),
    stdout,
    stderr,
  ]);
  assert.equal(exit.signal, null, errorOutput);
  assert.equal(exit.code, 0, errorOutput);
  return { stdout: output, stderr: errorOutput };
}

async function packageTarball(temporaryRoot) {
  const supplied = process.argv[2];
  if (supplied !== undefined) {
    const path = isAbsolute(supplied) ? supplied : resolve(process.cwd(), supplied);
    assert.equal(existsSync(path), true, `tarball does not exist: ${path}`);
    return path;
  }

  const packOutput = await run(
    npmCommand,
    ["pack", "--json", "--pack-destination", temporaryRoot],
    { cwd: projectRoot },
  );
  const result = JSON.parse(packOutput);
  assert.equal(Array.isArray(result), true);
  assert.equal(result.length, 1);
  return join(temporaryRoot, result[0].filename);
}

async function startFixture(secret, certificatePath, privateKeyPath) {
  const [cert, key] = await Promise.all([
    readFile(certificatePath),
    readFile(privateKeyPath),
  ]);
  const requests = [];
  const server = createServer({ cert, key }, (request, response) => {
    requests.push({ url: request.url, authorization: request.headers.authorization });
    if (request.url === "/reflect") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(secret);
      return;
    }
    const authenticated = request.headers.authorization === `Bearer ${secret}`;
    response.writeHead(authenticated ? 200 : 401, {
      "content-type": "application/json",
    });
    response.end(JSON.stringify({ authenticated, package: "installed" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, "object");
  return {
    origin: `https://127.0.0.1:${address.port}`,
    requests,
    async close() {
      server.close();
      await once(server, "close");
    },
  };
}

async function configureOwner(binPath, vaultPath, passphrase, secret, origin) {
  const passwordInput = `${passphrase}\n`;
  const cwd = dirname(vaultPath);
  await runCli(
    binPath,
    ["--vault", vaultPath, "--password-fd", "3", "init"],
    [passwordInput],
    process.env,
    cwd,
  );
  await runCli(
    binPath,
    [
      "--vault", vaultPath,
      "--password-fd", "3",
      "secret", "set", "package-token",
      "--secret-fd", "4",
    ],
    [passwordInput, `${secret}\n`],
    process.env,
    cwd,
  );
  await runCli(
    binPath,
    [
      "--vault", vaultPath,
      "--password-fd", "3",
      "connection", "set", "package-api",
      "--origin", origin,
      "--auth", "bearer",
      "--secret", "package-token",
      "--allow-private",
    ],
    [passwordInput],
    process.env,
    cwd,
  );
}

async function exerciseMcp(
  binPath,
  vaultPath,
  passphrase,
  certificatePath,
  forbidden,
) {
  const child = spawn(
    binPath,
    [
      "--vault", vaultPath,
      "--password-fd", "3",
      "serve",
      "--allow", "package-api",
      "--ttl", "30",
    ],
    {
      cwd: dirname(vaultPath),
      env: { ...process.env, NODE_EXTRA_CA_CERTS: certificatePath },
      stdio: ["pipe", "pipe", "pipe", "pipe"],
    },
  );
  child.stdio[3].end(`${passphrase}\n`);
  const stderrPromise = collect(child.stderr);
  const transport = new StdioServerTransport(child.stdout, child.stdin, {
    maxBufferSize: 2 * 1024 * 1024,
  });
  const client = new Client({ name: "blinddrop-package-check", version: "1.0.0" });
  try {
    await client.connect(transport);
    const authorized = await client.callTool({
      name: "execute_http",
      arguments: { connection: "package-api", path: "/identity" },
    });
    assert.equal(authorized.isError, undefined);
    assert.equal(authorized.structuredContent.status, 200);
    assert.deepEqual(JSON.parse(authorized.structuredContent.body), {
      authenticated: true,
      package: "installed",
    });

    const reflected = await client.callTool({
      name: "execute_http",
      arguments: { connection: "package-api", path: "/reflect" },
    });
    assert.equal(reflected.isError, true);
    assert.equal(reflected.structuredContent.error.code, "RESPONSE_BLOCKED");
    const visible = JSON.stringify([authorized, reflected]);
    for (const value of forbidden) {
      assert.equal(visible.includes(value), false);
    }
  } finally {
    await client.close().catch(() => undefined);
    if (child.exitCode === null && child.signalCode === null) {
      child.stdin.end();
      await childExit(child);
    }
  }
  const stderr = await stderrPromise;
  for (const value of forbidden) {
    assert.equal(stderr.includes(value), false);
  }
}

async function main() {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "blinddrop-package-"));
  let fixture;
  try {
    const tarball = await packageTarball(temporaryRoot);
    await writeFile(
      join(temporaryRoot, "package.json"),
      JSON.stringify({ private: true }),
      "utf8",
    );
    await run(
      npmCommand,
      ["install", "--omit=dev", "--no-audit", "--no-fund", tarball],
      { cwd: temporaryRoot },
    );

    const packageRoot = join(temporaryRoot, "node_modules", "blinddrop");
    for (const path of requiredPackagePaths) {
      assert.equal(existsSync(join(packageRoot, path)), true, `missing package file: ${path}`);
    }
    const topLevel = await readdir(packageRoot);
    for (const excluded of ["sources", "test", "scripts", "experiments"]) {
      assert.equal(topLevel.includes(excluded), false, `unexpected package path: ${excluded}`);
    }

    const binPath = join(
      temporaryRoot,
      "node_modules",
      ".bin",
      process.platform === "win32" ? "blinddrop.cmd" : "blinddrop",
    );
    assert.equal(existsSync(binPath), true, "npm did not install the blinddrop bin");
    const help = await run(binPath, ["--help"], { cwd: temporaryRoot });
    assert.match(help, /Usage: blinddrop/u);

    const certificatePath = join(projectRoot, "test", "fixtures", "localhost-cert.pem");
    const privateKeyPath = join(projectRoot, "test", "fixtures", "localhost-key.pem");
    const secret = `package-secret-${randomBytes(18).toString("hex")}`;
    const passphrase = `package-passphrase-${randomBytes(18).toString("hex")}`;
    const forbidden = [secret, passphrase];
    fixture = await startFixture(secret, certificatePath, privateKeyPath);

    const vaultPath = join(temporaryRoot, "vault.enc");
    await configureOwner(binPath, vaultPath, passphrase, secret, fixture.origin);
    await exerciseMcp(
      binPath,
      vaultPath,
      passphrase,
      certificatePath,
      forbidden,
    );
    assert.equal(fixture.requests.length, 2);

    const eventLog = await readFile(`${vaultPath}.events.jsonl`, "utf8");
    for (const value of forbidden) {
      assert.equal(eventLog.includes(value), false);
    }
    // Reuse actual owner/HTTP/SDK workflows against this installed executable.
    // The SDK and controller remain development consumers, not runtime dependencies.
    await run(process.execPath, [
      "--test", "--test-concurrency=1",
      join(projectRoot, "test/passwd.test.mjs"),
      join(projectRoot, "test/sdk-http.test.mjs"),
    ], {
      env: {
        ...process.env,
        NODE_EXTRA_CA_CERTS: certificatePath,
        BLINDDROP_TEST_CLI: binPath,
      },
    });
    process.stdout.write(JSON.stringify({
      package: basename(tarball),
      installedBin: true,
      authenticatedRequest: true,
      reflectionDenied: true,
      installedPassphraseHttpAndSdkWorkflows: true,
    }) + "\n");
  } finally {
    await fixture?.close();
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

await main();
