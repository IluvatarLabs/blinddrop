import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { get as httpGet } from "node:http";
import { createServer as createHttpsServer, get as httpsGet } from "node:https";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadVault } from "../dist/vault.js";
import {
  ca,
  collect,
  owner,
  session,
  spawnOwner,
} from "./support/owner-session.mjs";

const projectRoot = join(import.meta.dirname, "..");
const cliPath = process.env.BLINDDROP_TEST_CLI ?? join(projectRoot, "dist", "cli.js");
const browserCheck = process.env.BLINDDROP_BROWSER_CHECK === "1";
const certificate = await readFile(ca);
const privateKey = await readFile(new URL("./fixtures/localhost-key.pem", import.meta.url));

function childExit(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function authorizationUrlFrom(child) {
  return new Promise((resolve, reject) => {
    let buffered = "";
    const onData = (chunk) => {
      buffered += Buffer.from(chunk).toString("utf8");
      const newline = buffered.indexOf("\n");
      if (newline < 0) return;
      const line = buffered.slice(0, newline);
      const prefix = "Authorization URL: ";
      if (!line.startsWith(prefix)) {
        reject(new Error("OAuth owner CLI did not emit the bounded authorization URL line"));
        return;
      }
      cleanup();
      resolve(new URL(line.slice(prefix.length)));
    };
    const onExit = () => {
      cleanup();
      reject(new Error("OAuth owner CLI exited before emitting an authorization URL"));
    };
    const cleanup = () => {
      child.stdout.removeListener("data", onData);
      child.removeListener("exit", onExit);
    };
    child.stdout.on("data", onData);
    child.once("exit", onExit);
  });
}

function startLogin(vault, passphrase, definition, browser = false) {
  const child = spawn(
    process.execPath,
    [
      cliPath,
      "--vault",
      vault,
      "--password-fd",
      "3",
      "oauth",
      "login",
      "account",
      definition,
      ...(browser ? [] : ["--no-browser"]),
    ],
    {
      cwd: projectRoot,
      stdio: ["ignore", "pipe", "pipe", "pipe"],
      env: { ...process.env, NODE_EXTRA_CA_CERTS: ca },
    },
  );
  const exit = childExit(child);
  const url = browser ? undefined : authorizationUrlFrom(child);
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  child.stdio[3].end(`${passphrase}\n`);
  return { child, exit, url, stdout, stderr };
}

function get(url) {
  const getter = url.protocol === "https:" ? httpsGet : httpGet;
  return new Promise((resolve, reject) => {
    const request = getter(url, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
  });
}

async function followAuthorization(url) {
  const authorized = await get(url);
  assert.equal(authorized.status, 302);
  assert.equal(typeof authorized.headers.location, "string");
  return get(new URL(authorized.headers.location));
}

async function requestBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function challenge(verifier) {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

async function oauthFixture(t, mode = "success") {
  let authorizationSeen;
  const authorization = new Promise(resolve => { authorizationSeen = resolve; });
  const authorizationCodes = [];
  const codeChallenges = new Map();
  const codeVerifiers = [];
  const accessTokens = [];
  const refreshTokens = [];
  const refreshInputs = [];
  const providerMarker = `provider-detail-${randomBytes(12).toString("hex")}`;
  let authorizationRequests = 0;
  let tokenRequests = 0;
  let resourceRequests = 0;
  let origin;

  const server = createHttpsServer({ cert: certificate, key: privateKey }, async (request, response) => {
    try {
      const requestUrl = new URL(request.url, origin);
      if (requestUrl.pathname === "/authorize") {
        authorizationSeen(requestUrl);
        authorizationRequests++;
        assert.equal(request.method, "GET");
        assert.equal(requestUrl.searchParams.get("client_id"), "functional-public-client");
        assert.equal(requestUrl.searchParams.get("response_type"), "code");
        assert.equal(requestUrl.searchParams.get("code_challenge_method"), "S256");
        assert.equal(requestUrl.searchParams.get("scope"), "account.read offline_access");
        assert.equal(requestUrl.searchParams.get("audience"), "functional-api");
        assert.equal(requestUrl.searchParams.get("resource"), `${origin}/account`);
        assert.equal(requestUrl.searchParams.get("access_type"), "offline");
        assert.equal(requestUrl.searchParams.get("prompt"), "consent");
        assert.deepEqual(
          [...new Set(requestUrl.searchParams.keys())].sort(),
          [
            "access_type",
            "audience",
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "prompt",
            "redirect_uri",
            "resource",
            "response_type",
            "scope",
            "state",
          ],
        );

        const code = randomBytes(24).toString("base64url");
        authorizationCodes.push(code);
        codeChallenges.set(
          code,
          mode === "wrong-verifier"
            ? randomBytes(32).toString("base64url")
            : requestUrl.searchParams.get("code_challenge"),
        );
        const callback = new URL(requestUrl.searchParams.get("redirect_uri"));
        if (mode === "redirect-mismatch") {
          callback.pathname = "/oauth/not-the-callback";
        } else if (mode === "denied") {
          callback.searchParams.set("error", "access_denied");
          callback.searchParams.set("error_description", providerMarker);
        } else {
          callback.searchParams.set("code", code);
        }
        callback.searchParams.set(
          "state",
          mode === "wrong-state" ? randomBytes(24).toString("base64url") : requestUrl.searchParams.get("state"),
        );
        callback.searchParams.set("iss", mode === "wrong-issuer" ? origin + "/other-issuer" : origin);
        response.writeHead(302, { location: callback.href, "cache-control": "no-store" });
        response.end();
        return;
      }

      if (requestUrl.pathname === "/token") {
        tokenRequests++;
        const form = new URLSearchParams((await requestBody(request)).toString("utf8"));
        assert.equal(request.method, "POST");
        assert.equal(form.get("client_id"), "functional-public-client");
        assert.equal(form.get("scope"), "account.read offline_access");
        assert.equal(form.get("audience"), "functional-api");
        assert.equal(form.get("resource"), `${origin}/account`);

        if (form.get("grant_type") === "authorization_code") {
          const code = form.get("code");
          const verifier = form.get("code_verifier");
          codeVerifiers.push(verifier);
          assert.equal(form.get("redirect_uri")?.startsWith("http://127.0.0.1:"), true);
          if (challenge(verifier) !== codeChallenges.get(code)) {
            response.writeHead(400, { "content-type": "application/json" });
            response.end(JSON.stringify({ error: "invalid_grant", error_description: providerMarker }));
            return;
          }
          const access = randomBytes(24).toString("base64url");
          const refresh = randomBytes(24).toString("base64url");
          accessTokens.push(access);
          refreshTokens.push(refresh);
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({
            access_token: access,
            token_type: "Bearer",
            expires_in: 1,
            ...(mode === "missing-refresh" ? {} : { refresh_token: refresh }),
          }));
          return;
        }

        if (form.get("grant_type") === "refresh_token") {
          const supplied = form.get("refresh_token");
          refreshInputs.push(supplied);
          if (supplied !== refreshTokens[0]) {
            response.writeHead(400, { "content-type": "application/json" });
            response.end(JSON.stringify({ error: "invalid_grant", error_description: providerMarker }));
            return;
          }
          const access = randomBytes(24).toString("base64url");
          accessTokens.push(access);
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({
            access_token: access,
            token_type: "Bearer",
            expires_in: 60,
          }));
          return;
        }
      }

      if (requestUrl.pathname === "/account") {
        resourceRequests++;
        const supplied = request.headers.authorization?.replace(/^Bearer /u, "");
        const allowed = supplied === accessTokens.at(-1);
        response.writeHead(allowed ? 200 : 401, { "content-type": "application/json" });
        response.end(JSON.stringify(allowed
          ? { account: "functional-owner-account" }
          : { error: "invalid_token" }));
        return;
      }

      response.writeHead(404).end();
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain" });
      response.end(String(error));
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  origin = `https://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.close();
    server.closeAllConnections();
    await once(server, "close");
  });
  return {
    origin,
    authorization,
    authorizationCodes,
    codeVerifiers,
    accessTokens,
    refreshTokens,
    refreshInputs,
    providerMarker,
    counts: () => ({ authorizationRequests, tokenRequests, resourceRequests }),
  };
}

function definition(origin) {
  return {
    issuer: origin,
    authorizationEndpoint: `${origin}/authorize`,
    authorizationParameters: { access_type: "offline", prompt: "consent" },
    connection: {
      origin,
      auth: {
        type: "oauth2",
        tokenEndpoint: `${origin}/token`,
        grant: "refresh_token",
        clientId: "functional-public-client",
        clientAuth: "none",
        refreshSecret: "account-refresh",
        scope: "account.read offline_access",
        audience: "functional-api",
        resource: `${origin}/account`,
      },
      allowPrivate: true,
      enabled: true,
    },
  };
}

async function initializedOwner(t, mode) {
  const directory = await mkdtemp(join(tmpdir(), `blinddrop-oauth-${mode}-`));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const vault = join(directory, "vault.enc");
  const configuration = join(directory, "oauth.json");
  const passphrase = randomBytes(24).toString("base64url");
  await owner(vault, passphrase, ["init"]);
  return { directory, vault, configuration, passphrase };
}

test("owner OAuth login uses real PKCE authorization, saves only the refresh grant, and new helpers refresh across restart", { timeout: browserCheck ? 300_000 : 60_000 }, async (t) => {
  const local = await initializedOwner(t, "success");
  const fixture = await oauthFixture(t);
  await writeFile(local.configuration, JSON.stringify(definition(fixture.origin)), { mode: 0o600 });

  const login = startLogin(local.vault, local.passphrase, local.configuration, browserCheck);
  t.after(() => { if (login.child.exitCode === null) login.child.kill(); });
  const authorizationUrl = await (browserCheck ? fixture.authorization : login.url);
  const callback = browserCheck ? undefined : await followAuthorization(authorizationUrl);
  if (callback) {
    assert.equal(callback.status, 200);
    assert.equal(callback.body, "Authorization response received. Return to BlindDrop.\n");
  }
  const [exit, stdout, stderr] = await Promise.all([login.exit, login.stdout, login.stderr]);
  assert.deepEqual({ ...exit, stderr }, { code: 0, signal: null, stderr: "" });
  assert.equal(stdout.endsWith("OAuth grant and connection saved for the next session.\n"), true);
  assert.deepEqual(fixture.counts(), { authorizationRequests: 1, tokenRequests: 1, resourceRequests: 0 });
  assert.equal(fixture.codeVerifiers.length, 1);
  assert.equal(challenge(fixture.codeVerifiers[0]), authorizationUrl.searchParams.get("code_challenge"));
  assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");

  const firstSaved = loadVault(local.vault, local.passphrase);
  assert.equal(firstSaved.secrets["account-refresh"].value, fixture.refreshTokens[0]);
  assert.equal(firstSaved.secrets["account-refresh"].enabled, true);
  assert.deepEqual(firstSaved.connections.account, definition(fixture.origin).connection);
  assert.equal((await readFile(local.vault)).includes(Buffer.from(fixture.refreshTokens[0])), false);

  const first = await session(local.vault, local.passphrase, ["account"]);
  const firstAccount = await first.execute({ connection: "account", path: "/account" });
  assert.equal(firstAccount.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(firstAccount.structuredContent.body), { account: "functional-owner-account" });
  const firstTraffic = await first.close();
  assert.equal(fixture.refreshInputs[0], fixture.refreshTokens[0]);
  const persisted = loadVault(local.vault, local.passphrase).secrets["account-refresh"].value;
  assert.equal(persisted, fixture.refreshTokens[0]);

  const second = await session(local.vault, local.passphrase, ["account"]);
  const secondAccount = await second.execute({ connection: "account", path: "/account" });
  assert.equal(secondAccount.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(secondAccount.structuredContent.body), { account: "functional-owner-account" });
  const secondTraffic = await second.close();
  assert.equal(fixture.refreshInputs[1], persisted);
  assert.deepEqual(fixture.counts(), { authorizationRequests: 1, tokenRequests: 3, resourceRequests: 2 });

  const visible = [
    stdout,
    stderr,
    callback?.body ?? "",
    JSON.stringify(firstTraffic),
    JSON.stringify(secondTraffic),
    await readFile(`${local.vault}.events.jsonl`, "utf8"),
  ].join("\n");
  for (const secret of [
    local.passphrase,
    ...fixture.authorizationCodes,
    ...fixture.codeVerifiers,
    ...fixture.accessTokens,
    ...fixture.refreshTokens,
  ]) {
    assert.equal(visible.includes(secret), false, "owner, callback, MCP and log outputs exclude credentials");
  }
});

test("owner cancellation closes the OAuth listener and leaves the encrypted archive unchanged", { timeout: 30_000 }, async (t) => {
  const local = await initializedOwner(t, "cancel");
  const fixture = await oauthFixture(t);
  await writeFile(local.configuration, JSON.stringify(definition(fixture.origin)), { mode: 0o600 });
  const before = await readFile(local.vault);
  const login = startLogin(local.vault, local.passphrase, local.configuration);
  const authorization = await login.url;
  login.child.kill("SIGTERM");
  const [exit, stdout, stderr] = await Promise.all([login.exit, login.stdout, login.stderr]);
  assert.deepEqual(exit, { code: 1, signal: null });
  assert.equal(stderr, "SESSION_CLOSED: The session is closed.\n");
  assert.equal(stdout.includes(local.passphrase), false);
  assert.equal((await readFile(local.vault)).equals(before), true);
  assert.deepEqual(fixture.counts(), { authorizationRequests: 0, tokenRequests: 0, resourceRequests: 0 });
  await assert.rejects(get(new URL(authorization.searchParams.get("redirect_uri"))), { code: "ECONNREFUSED" });
});

for (const [mode, expectedCode, expectedTokenRequests] of [
  ["wrong-state", "UPSTREAM_ERROR", 0],
  ["wrong-issuer", "UPSTREAM_ERROR", 0],
  ["redirect-mismatch", "INVALID_INPUT", 0],
  ["wrong-verifier", "UPSTREAM_ERROR", 1],
  ["denied", "UPSTREAM_ERROR", 0],
  ["missing-refresh", "UPSTREAM_ERROR", 1],
]) {
  test(`OAuth ${mode} fails statically without saving or dispatching a resource request`, { timeout: 30_000 }, async (t) => {
    const local = await initializedOwner(t, mode);
    const fixture = await oauthFixture(t, mode);
    await writeFile(local.configuration, JSON.stringify(definition(fixture.origin)), { mode: 0o600 });
    const before = await readFile(local.vault);

    const login = startLogin(local.vault, local.passphrase, local.configuration);
    const callback = await followAuthorization(await login.url);
    const [exit, stdout, stderr] = await Promise.all([login.exit, login.stdout, login.stderr]);
    assert.deepEqual(exit, { code: 1, signal: null });
    assert.equal(stderr, `${expectedCode}: ${
      expectedCode === "INVALID_INPUT"
        ? "Invalid input."
        : "The upstream request failed. Its outcome may be unknown."
    }\n`);
    assert.equal((await readFile(local.vault)).equals(before), true);
    const stored = loadVault(local.vault, local.passphrase);
    assert.equal(stored.connections.account, undefined);
    assert.equal(stored.secrets["account-refresh"], undefined);
    assert.deepEqual(fixture.counts(), {
      authorizationRequests: 1,
      tokenRequests: expectedTokenRequests,
      resourceRequests: 0,
    });
    const visible = `${stdout}\n${stderr}\n${callback.body}`;
    for (const secret of [
      local.passphrase,
      fixture.providerMarker,
      ...fixture.authorizationCodes,
      ...fixture.codeVerifiers,
      ...fixture.accessTokens,
      ...fixture.refreshTokens,
    ]) {
      assert.equal(visible.includes(secret), false);
    }
  });
}

test("OAuth configuration rejects protocol overrides and missing client-secret references before opening a callback", async (t) => {
  const local = await initializedOwner(t, "invalid-config");
  const fixture = await oauthFixture(t);
  const configured = definition(fixture.origin);
  configured.authorizationParameters.state = "owner-must-not-override-state";
  await writeFile(local.configuration, JSON.stringify(configured), { mode: 0o600 });
  let result = await ownerFailure(local, fixture);
  assert.equal(result.stderr, "INVALID_INPUT: Invalid input.\n");
  assert.deepEqual(fixture.counts(), { authorizationRequests: 0, tokenRequests: 0, resourceRequests: 0 });

  const missingReference = definition(fixture.origin);
  missingReference.connection.auth.clientAuth = "basic";
  missingReference.connection.auth.clientSecret = "missing-client-secret";
  await writeFile(local.configuration, JSON.stringify(missingReference), { mode: 0o600 });
  result = await ownerFailure(local, fixture);
  assert.equal(result.stderr, "SECRET_NOT_FOUND: The secret is unavailable.\n");
  assert.deepEqual(fixture.counts(), { authorizationRequests: 0, tokenRequests: 0, resourceRequests: 0 });

  const collidingReference = definition(fixture.origin);
  collidingReference.connection.auth.clientAuth = "basic";
  collidingReference.connection.auth.clientSecret = "account-refresh";
  await writeFile(local.configuration, JSON.stringify(collidingReference), { mode: 0o600 });
  result = await ownerFailure(local, fixture);
  assert.equal(result.stderr, "INVALID_INPUT: Invalid input.\n");
  assert.deepEqual(fixture.counts(), { authorizationRequests: 0, tokenRequests: 0, resourceRequests: 0 });
  assert.equal(loadVault(local.vault, local.passphrase).connections.account, undefined);
});

async function ownerFailure(local) {
  const run = spawnOwner(local.vault, local.passphrase, [
    "oauth", "login", "account", local.configuration, "--no-browser",
  ]);
  run.child.stdin.end();
  const [exit, stdout, stderr] = await Promise.all([
    run.exit,
    collect(run.child.stdout),
    run.stderr,
  ]);
  assert.deepEqual(exit, { code: 1, signal: null });
  assert.equal(stdout, "");
  return { stderr };
}
