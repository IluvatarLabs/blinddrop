import { readConnections, connectionContext } from "../dist/connection-store.js";
import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadVault } from "../dist/vault.js";
import {
  collect,
  owner,
  session,
  spawnOwner,
} from "./support/owner-session.mjs";

async function failedOwner(vault, passphrase, args, secret) {
  const run = spawnOwner(vault, passphrase, args, secret);
  run.child.stdin.end();
  const stdout = collect(run.child.stdout);
  const [exit, out, err] = await Promise.all([run.exit, stdout, run.stderr]);
  return { ...exit, stdout: out, stderr: err };
}

test("passwd preserves the archive and changes only the current copy's unlock", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "blinddrop-passwd-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const vaultPath = join(directory, "vault.enc");
  const backupPath = join(directory, "vault.backup.enc");
  const oldPassphrase = "disposable old vault passphrase";
  const newPassphrase = "disposable new vault passphrase";
  const wrongPassphrase = "disposable wrong vault passphrase";
  const discardedNewPassphrase = "disposable unused vault passphrase";
  const secret = "disposable-passwd-secret";
  const forbidden = [
    oldPassphrase,
    newPassphrase,
    wrongPassphrase,
    discardedNewPassphrase,
    secret,
  ];

  await owner(vaultPath, oldPassphrase, ["init"]);
  await owner(
    vaultPath,
    oldPassphrase,
    ["secret", "set", "api-token", "--secret-fd", "4"],
    secret,
  );
  await owner(vaultPath, oldPassphrase, [
    "connection", "set", "api",
    "--origin", "https://api.example.com",
    "--auth", "bearer",
    "--secret", "api-token",
  ]);
  await copyFile(vaultPath, backupPath);
  await copyFile(connectionContext(vaultPath).path, connectionContext(backupPath).path);

  const beforeWrongInput = await readFile(vaultPath);
  const wrong = await failedOwner(
    vaultPath,
    wrongPassphrase,
    ["passwd", "--new-password-fd", "4"],
    discardedNewPassphrase,
  );
  assert.deepEqual(
    { code: wrong.code, signal: wrong.signal, stdout: wrong.stdout, stderr: wrong.stderr },
    {
      code: 1,
      signal: null,
      stdout: "",
      stderr: "UNLOCK_FAILED: Cannot unlock the vault: wrong passphrase or damaged archive.\n",
    },
  );
  assert.deepEqual(await readFile(vaultPath), beforeWrongInput);
  assert.equal(loadVault(vaultPath, oldPassphrase).secrets["api-token"].fields.value.value, secret);

  const changed = await owner(
    vaultPath,
    oldPassphrase,
    ["passwd", "--new-password-fd", "4"],
    newPassphrase,
  );
  assert.equal(
    changed,
    "Vault passphrase changed.\n",
  );
  assert.notDeepEqual(await readFile(vaultPath), beforeWrongInput);

  const current = loadVault(vaultPath, newPassphrase);
  assert.equal(current.secrets["api-token"].fields.value.value, secret);
  assert.deepEqual(current.connections, {});
  assert.deepEqual(readConnections(connectionContext(vaultPath).path).api.auth, { type: "bearer", secret: "default#api-token#value" });

  const oldRejected = await failedOwner(
    vaultPath,
    oldPassphrase,
    ["serve", "--allow", "api", "--ttl", "30"],
  );
  assert.equal(oldRejected.code, 1);
  assert.equal(oldRejected.signal, null);
  assert.equal(oldRejected.stdout, "");
  assert.equal(
    oldRejected.stderr,
    "UNLOCK_FAILED: Cannot unlock the vault: wrong passphrase or damaged archive.\n",
  );

  const currentSession = await session(vaultPath, newPassphrase, ["api"]);
  const currentConnections = await currentSession.client.callTool({
    name: "list_connections",
    arguments: {},
  });
  assert.deepEqual(currentConnections.structuredContent.connections, [{
    name: "api",
    origin: "https://api.example.com",
    authType: "bearer",
  }]);
  const currentTraffic = await currentSession.close();

  const backupSession = await session(backupPath, oldPassphrase, ["api"]);
  const backupConnections = await backupSession.client.callTool({
    name: "list_connections",
    arguments: {},
  });
  assert.deepEqual(backupConnections.structuredContent.connections, [{
    name: "api",
    origin: "https://api.example.com",
    authType: "bearer",
  }]);
  const backupTraffic = await backupSession.close();

  const visible = JSON.stringify([
    wrong,
    changed,
    oldRejected,
    currentConnections,
    currentTraffic,
    backupConnections,
    backupTraffic,
  ]);
  for (const value of forbidden) {
    assert.equal(visible.includes(value), false);
  }
});
