import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

import {
  createVault,
  loadVault,
  saveVault,
  validateConnection,
  validateName,
} from "../dist/vault.js";

const PASSPHRASE = "dummy test passphrase";
const SECRET_VALUE = "  token:\n秘密 🔑\twith whitespace\r\n";

function workspace(t) {
  const directory = mkdtempSync(join(tmpdir(), "blinddrop-vault-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function throwsCode(code) {
  return (error) => {
    assert.equal(error?.name, "BlindDropError");
    assert.equal(error?.code, code);
    return true;
  };
}

function concurrentCreate(path, marker) {
  const moduleUrl = pathToFileURL(join(process.cwd(), "dist", "vault.js")).href;
  const source = `
    import { createVault } from ${JSON.stringify(moduleUrl)};
    const [path, marker] = process.argv.slice(1);
    try {
      createVault(path, "dummy concurrent passphrase " + marker);
      process.stdout.write(JSON.stringify({ marker, result: "created" }));
    } catch (error) {
      process.stdout.write(JSON.stringify({ marker, result: error?.code ?? "unexpected" }));
    }
  `;

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", source, path, marker], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`concurrent creator exited ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error("concurrent creator returned invalid output"));
      }
    });
  });
}

test("encrypted archive round-trips and a byte-for-byte copy restores", (t) => {
  const directory = workspace(t);
  const path = join(directory, "owner", "vault.enc");
  const restoredPath = join(directory, "restored.enc");
  const vault = createVault(path, PASSPHRASE);

  vault.secrets.API_KEY = { value: SECRET_VALUE, enabled: true };
  vault.secrets.Spacing = { value: "  \t  ", enabled: true };
  vault.connections["Work.API"] = validateConnection({
    origin: " https://EXAMPLE.com:443/ ",
    auth: { type: "bearer", secret: "API_KEY" },
    allowPrivate: false,
    enabled: true,
  });
  saveVault(path, vault, PASSPHRASE);

  const archive = readFileSync(path);
  assert.equal(archive[0], 2);
  assert.equal(archive.includes(Buffer.from(SECRET_VALUE, "utf8")), false);
  assert.equal(statSync(path).mode & 0o077, 0);
  assert.equal(statSync(dirname(path)).mode & 0o077, 0);

  const loaded = loadVault(path, PASSPHRASE);
  assert.equal(loaded.version, 1);
  assert.equal(loaded.secrets.API_KEY.value, SECRET_VALUE);
  assert.equal(loaded.secrets.Spacing.value, "  \t  ");
  assert.equal(loaded.connections["Work.API"].origin, "https://example.com");

  copyFileSync(path, restoredPath);
  assert.deepEqual(loadVault(restoredPath, PASSPHRASE), loaded);
});

test("wrong passphrase, authenticated corruption, truncation, and oversize fail explicitly", (t) => {
  const directory = workspace(t);
  const path = join(directory, "vault.enc");
  createVault(path, PASSPHRASE);
  const original = readFileSync(path);

  assert.throws(() => loadVault(path, "wrong dummy passphrase"), throwsCode("UNLOCK_FAILED"));
  assert.deepEqual(readFileSync(path), original);

  const corruptPath = join(directory, "corrupt.enc");
  const corrupt = Buffer.from(original);
  corrupt[corrupt.length - 1] ^= 0xff;
  writeFileSync(corruptPath, corrupt, { mode: 0o600 });
  assert.throws(() => loadVault(corruptPath, PASSPHRASE), throwsCode("UNLOCK_FAILED"));
  assert.deepEqual(readFileSync(corruptPath), corrupt);

  const truncatedPath = join(directory, "truncated.enc");
  writeFileSync(truncatedPath, original.subarray(0, 45), { mode: 0o600 });
  assert.throws(() => loadVault(truncatedPath, PASSPHRASE), throwsCode("VAULT_INVALID"));

  const oversizedPath = join(directory, "oversized.enc");
  writeFileSync(oversizedPath, Buffer.alloc(16 * 1024 * 1024 + 1), { mode: 0o600 });
  assert.throws(() => loadVault(oversizedPath, PASSPHRASE), throwsCode("VAULT_INVALID"));
});

test("initialization and invalid input preserve an existing archive", (t) => {
  const directory = workspace(t);
  const path = join(directory, "vault.enc");
  const vault = createVault(path, PASSPHRASE);
  vault.secrets.Current = { value: "dummy-current", enabled: true };
  saveVault(path, vault, PASSPHRASE);
  const original = readFileSync(path);

  assert.throws(() => createVault(path, "another passphrase"), throwsCode("VAULT_EXISTS"));
  assert.deepEqual(readFileSync(path), original);

  vault.secrets.Empty = { value: "", enabled: true };
  assert.throws(() => saveVault(path, vault, PASSPHRASE), throwsCode("INVALID_INPUT"));
  delete vault.secrets.Empty;
  vault.secrets.TooLarge = { value: "x".repeat(64 * 1024 + 1), enabled: true };
  assert.throws(() => saveVault(path, vault, PASSPHRASE), throwsCode("INVALID_INPUT"));
  assert.deepEqual(readFileSync(path), original);
  assert.equal(loadVault(path, PASSPHRASE).secrets.Current.value, "dummy-current");
});

test("concurrent initialization publishes exactly one complete archive", async (t) => {
  const directory = workspace(t);
  const path = join(directory, "vault.enc");
  const results = await Promise.all([
    concurrentCreate(path, "one"),
    concurrentCreate(path, "two"),
  ]);

  assert.deepEqual(
    results.map(({ result }) => result).sort(),
    ["VAULT_EXISTS", "created"],
  );
  const winner = results.find(({ result }) => result === "created");
  assert.ok(winner);
  assert.equal(
    loadVault(path, `dummy concurrent passphrase ${winner.marker}`).version,
    1,
  );
  assert.deepEqual(readdirSync(directory), ["vault.enc"]);
});

test(
  "a real replacement write failure leaves the prior valid archive and no temp file",
  { skip: process.platform === "win32" || process.getuid?.() === 0 },
  (t) => {
    const directory = workspace(t);
    const ownerDirectory = join(directory, "owner");
    const path = join(ownerDirectory, "vault.enc");
    const vault = createVault(path, PASSPHRASE);
    vault.secrets.Current = { value: "before-failure", enabled: true };
    saveVault(path, vault, PASSPHRASE);

    vault.secrets.Current.value = "after-failure";
    chmodSync(ownerDirectory, 0o500);
    try {
      assert.throws(() => saveVault(path, vault, PASSPHRASE), throwsCode("STORAGE_ERROR"));
    } finally {
      chmodSync(ownerDirectory, 0o700);
    }

    assert.equal(loadVault(path, PASSPHRASE).secrets.Current.value, "before-failure");
    assert.deepEqual(readdirSync(ownerDirectory), ["vault.enc"]);
  },
);

test("name and connection validators accept exact configuration and reject unsafe input", () => {
  assert.doesNotThrow(() => validateName("API_KEY.v2-test"));
  for (const name of ["", "-leading", "trailing-", "has space", "constructor", "PROTOTYPE", "x".repeat(65)]) {
    assert.throws(() => validateName(name), throwsCode("INVALID_INPUT"));
  }

  assert.deepEqual(
    validateConnection({
      origin: "https://Example.COM:443/",
      auth: { type: "query", secret: "API_KEY", name: "access_token[value]" },
      allowPrivate: false,
      enabled: true,
    }),
    {
      origin: "https://example.com",
      auth: { type: "query", secret: "API_KEY", name: "access_token[value]" },
      allowPrivate: false,
      enabled: true,
    },
  );

  const invalidConnections = [
    {
      origin: "http://example.com",
      auth: { type: "bearer", secret: "API_KEY" },
      allowPrivate: false,
      enabled: true,
    },
    {
      origin: "https://user@example.com",
      auth: { type: "bearer", secret: "API_KEY" },
      allowPrivate: false,
      enabled: true,
    },
    {
      origin: "https://example.com/v1",
      auth: { type: "bearer", secret: "API_KEY" },
      allowPrivate: false,
      enabled: true,
    },
    {
      origin: "https://example.com/?key=value",
      auth: { type: "bearer", secret: "API_KEY" },
      allowPrivate: false,
      enabled: true,
    },
    {
      origin: "https://*.example.com",
      auth: { type: "bearer", secret: "API_KEY" },
      allowPrivate: false,
      enabled: true,
    },
    {
      origin: "https://example.com",
      auth: { type: "header", secret: "API_KEY", name: "Content-Length" },
      allowPrivate: false,
      enabled: true,
    },
  ];

  for (const connection of invalidConnections) {
    assert.throws(() => validateConnection(connection), throwsCode("INVALID_INPUT"));
  }

  for (const name of [
    "Forwarded",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Port",
    "X-Forwarded-Proto",
  ]) {
    assert.throws(
      () => validateConnection({
        origin: "https://example.com",
        auth: { type: "header", secret: "API_KEY", name },
        allowPrivate: false,
        enabled: true,
      }),
      throwsCode("INVALID_INPUT"),
    );
  }
});

test("connection validation covers bounded compatibility authentication and TLS references", () => {
  const base = { origin: "https://example.com", allowPrivate: false, enabled: true };
  const accepted = [
    {
      ...base,
      auth: { type: "basic", usernameSecret: "stripe-key" },
    },
    {
      ...base,
      auth: { type: "basic", passwordSecret: "password" },
    },
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: [
          { in: "header", name: "X-Client-Id", secret: "client-id", prefix: "Token " },
          { in: "query", name: "access_token[value]", secret: "query-token" },
          { in: "json", name: "client_secret", secret: "body-secret" },
          { in: "path", prefix: "/bot", suffix: "/", secret: "bot-token" },
        ],
      },
    },
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://AUTH.example.com:443/oauth/token?tenant=owner",
        grant: "client_credentials",
        clientId: "public-client-id",
        clientSecret: "client-secret",
        clientAuth: "body",
        scope: "records.read records.write",
      },
    },
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://auth.example.com/token",
        grant: "refresh_token",
        clientId: "public-client-id",
        refreshSecret: "refresh-token",
        clientAuth: "none",
      },
    },
    {
      ...base,
      auth: {
        type: "jwt-bearer",
        tokenEndpoint: "https://auth.example.com/token",
        issuer: "service-account@example.com",
        subject: "delegated-user@example.com",
        scope: "records.read",
        privateKeySecret: "private-key",
        keyId: "key-id",
      },
    },
    {
      ...base,
      auth: {
        type: "aws-sigv4",
        accessKeyIdSecret: "access-key-id",
        secretAccessKeySecret: "secret-access-key",
        sessionTokenSecret: "session-token",
        region: "us-east-1",
        service: "sts",
      },
    },
    {
      ...base,
      auth: { type: "none" },
      tls: {
        certificateSecret: "client-certificate",
        privateKeySecret: "client-private-key",
        passphraseSecret: "client-key-passphrase",
      },
    },
  ];

  for (const connection of accepted) {
    assert.doesNotThrow(() => validateConnection(connection));
  }
  assert.equal(
    validateConnection(accepted[3]).auth.tokenEndpoint,
    "https://auth.example.com/oauth/token?tenant=owner",
  );

  const invalid = [
    { ...base, auth: { type: "basic" } },
    { ...base, auth: { type: "none" } },
    { ...base, auth: { type: "bindings", bindings: [] } },
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: Array.from({ length: 17 }, (_, index) => ({
          in: "query",
          name: `field-${index}`,
          secret: "token",
        })),
      },
    },
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: [
          { in: "header", name: "X-Token", secret: "one" },
          { in: "header", name: "x-token", secret: "two" },
        ],
      },
    },
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: [
          { in: "path", prefix: "/bot", secret: "one" },
          { in: "path", prefix: "/account", secret: "two" },
        ],
      },
    },
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: [
          { in: "json", name: "client_id", secret: "one" },
          { in: "form", name: "client_secret", secret: "two" },
        ],
      },
    },
    {
      ...base,
      auth: { type: "bindings", bindings: [{ in: "header", name: "Forwarded", secret: "token" }] },
    },
    ...[
      "bot",
      "/bot?x=",
      "/bot#fragment",
      "/bot\\token",
      "/bot/../token",
      "/bot/%2e%2e/token",
      `/bot${"x".repeat(1_025)}`,
    ].map(
      (prefix) => ({
        ...base,
        auth: { type: "bindings", bindings: [{ in: "path", prefix, secret: "token" }] },
      }),
    ),
    {
      ...base,
      auth: {
        type: "bindings",
        bindings: [{ in: "query", name: "token", secret: "token", prefix: "x\n" }],
      },
    },
    ...[
      "http://auth.example.com/token",
      "https://owner@auth.example.com/token",
      "https://auth.example.com/token#fragment",
      "https://auth.example.com/{tenant}/token",
      "https://*.example.com/token",
      "https://auth.example.com/to\nken",
    ].map((tokenEndpoint) => ({
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint,
        grant: "client_credentials",
        clientId: "client-id",
        clientAuth: "none",
      },
    })),
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://auth.example.com/token",
        grant: "refresh_token",
        clientId: "client-id",
        clientAuth: "none",
      },
    },
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://auth.example.com/token",
        grant: "client_credentials",
        clientId: "client-id",
        refreshSecret: "refresh-token",
        clientAuth: "none",
      },
    },
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://auth.example.com/token",
        grant: "client_credentials",
        clientId: "client-id",
        clientAuth: "basic",
      },
    },
    {
      ...base,
      auth: {
        type: "oauth2",
        tokenEndpoint: "https://auth.example.com/token",
        grant: "client_credentials",
        clientId: "client-id",
        clientSecret: "unused-client-secret",
        clientAuth: "none",
      },
    },
    {
      ...base,
      auth: { type: "bearer", secret: "token", script: "return secret" },
    },
    {
      ...base,
      auth: { type: "none" },
      tls: { certificateSecret: "certificate", privateKeySecret: "private-key", pem: "literal" },
    },
  ];

  for (const connection of invalid) {
    assert.throws(() => validateConnection(connection), throwsCode("INVALID_INPUT"));
  }
});
