import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadVault } from "../dist/vault.js";

const projectRoot = join(import.meta.dirname, "..");
const cliPath = join(projectRoot, "dist", "cli.js");

function collectStream(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    stream.on("error", reject);
  });
}

function childExit(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

async function runCli(args, inheritedInputs = []) {
  const child = spawn(process.execPath, [cliPath, ...args], {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe", ...inheritedInputs.map(() => "pipe")],
  });
  inheritedInputs.forEach((value, index) => child.stdio[index + 3].end(value));
  const [{ code, signal }, stdout, stderr] = await Promise.all([
    childExit(child),
    collectStream(child.stdout),
    collectStream(child.stderr),
  ]);
  return { code, signal, stdout, stderr };
}

async function expectSuccess(args, inheritedInputs, forbidden) {
  const result = await runCli(args, inheritedInputs);
  assert.deepEqual({ code: result.code, signal: result.signal, stderr: result.stderr }, {
    code: 0,
    signal: null,
    stderr: "",
  });
  for (const value of forbidden) {
    assert.equal(result.stdout.includes(value), false);
    assert.equal(result.stderr.includes(value), false);
  }
  return result;
}

test("owner imports a reference-only Basic connection and disabled references deny later use", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "blinddrop-compat-owner-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const vaultPath = join(directory, "vault.enc");
  const connectionPath = join(directory, "stripe.json");
  const malformedPath = join(directory, "malformed.json");
  const passphrase = "disposable compatibility passphrase";
  const secret = "sk_test_disposable_compatibility";
  const malformedMarker = "raw-json-must-not-be-echoed";
  const forbidden = [passphrase, secret, malformedMarker];

  await expectSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "init"],
    [`${passphrase}\n`],
    forbidden,
  );
  await expectSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "secret",
      "set",
      "stripe-key",
      "--secret-fd",
      "4",
    ],
    [`${passphrase}\n`, `${secret}\n`],
    forbidden,
  );

  const definition = {
    origin: "https://API.STRIPE.com:443/",
    auth: { type: "basic", usernameSecret: "stripe-key" },
    allowPrivate: false,
    enabled: true,
  };
  await writeFile(connectionPath, JSON.stringify(definition), { mode: 0o600 });
  const imported = await expectSuccess(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "connection",
      "import",
      "stripe",
      connectionPath,
    ],
    [`${passphrase}\n`],
    forbidden,
  );
  assert.equal(imported.stdout, "Connection imported for the next session.\n");

  const listing = await expectSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "list"],
    [`${passphrase}\n`],
    forbidden,
  );
  assert.deepEqual(JSON.parse(listing.stdout), {
    secrets: [{ name: "stripe-key", enabled: true }],
    connections: [{
      name: "stripe",
      origin: "https://api.stripe.com",
      authType: "basic",
      allowPrivate: false,
      enabled: true,
    }],
  });

  const loaded = loadVault(vaultPath, passphrase);
  assert.deepEqual(loaded.connections.stripe, {
    origin: "https://api.stripe.com",
    auth: { type: "basic", usernameSecret: "stripe-key" },
    allowPrivate: false,
    enabled: true,
  });
  assert.equal((await readFile(vaultPath)).includes(Buffer.from(secret)), false);

  await writeFile(malformedPath, `{"origin":"${malformedMarker}"`, { mode: 0o600 });
  const malformed = await runCli([
    "--vault",
    vaultPath,
    "--password-fd",
    "3",
    "connection",
    "import",
    "malformed",
    malformedPath,
  ]);
  assert.equal(malformed.code, 1);
  assert.equal(malformed.stdout, "");
  assert.equal(malformed.stderr, "INVALID_INPUT: Invalid input.\n");
  assert.equal(malformed.stderr.includes(malformedMarker), false);

  await expectSuccess(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "disable", "stripe-key"],
    [`${passphrase}\n`],
    forbidden,
  );

  const disabledImport = await runCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "connection",
      "import",
      "stripe-copy",
      connectionPath,
    ],
    [`${passphrase}\n`],
  );
  assert.equal(disabledImport.code, 1);
  assert.equal(disabledImport.stderr, "SECRET_NOT_FOUND: The secret is unavailable.\n");

  const referencedRemoval = await runCli(
    ["--vault", vaultPath, "--password-fd", "3", "secret", "remove", "stripe-key"],
    [`${passphrase}\n`],
  );
  assert.equal(referencedRemoval.code, 1);
  assert.equal(referencedRemoval.stderr, "INVALID_INPUT: Invalid input.\n");

  const disabledServe = await runCli(
    [
      "--vault",
      vaultPath,
      "--password-fd",
      "3",
      "serve",
      "--allow",
      "stripe",
      "--ttl",
      "30",
    ],
    [`${passphrase}\n`],
  );
  assert.equal(disabledServe.code, 1);
  assert.equal(disabledServe.stderr, "SECRET_NOT_FOUND: The secret is unavailable.\n");
  assert.equal(loadVault(vaultPath, passphrase).connections["stripe-copy"], undefined);

  for (const result of [disabledImport, referencedRemoval, disabledServe]) {
    for (const value of forbidden) {
      assert.equal(result.stdout.includes(value), false);
      assert.equal(result.stderr.includes(value), false);
    }
  }
});
