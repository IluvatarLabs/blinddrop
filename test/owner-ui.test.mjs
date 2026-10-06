// v0.5.1 owner UI functional tests. Every test drives the real installed `ui`
// command as a child process with HOME pointed at a scratch directory (so the
// owner's own ~/.config/blinddrop is never touched), talks to it over its real
// loopback listener with exact control of Host/Origin/Authorization, drives the
// implicit agent session with the official MCP client, and authenticates real
// signed/keyed requests against a disposable HTTPS receiver with generated
// credentials. No mocks and no synthetic assertions: each proves a reachable
// product behavior and fails on a real regression.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

import { ca, cli, collect, owner, spawnOwner } from './support/owner-session.mjs';

const keyPath = new URL('./fixtures/localhost-key.pem', import.meta.url);
const certPath = new URL('./fixtures/localhost-cert.pem', import.meta.url);

// The page is served under exactly this policy; a relaxation would let injected
// markup reach the network or a foreign origin.
const CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'unsafe-inline'; " +
  "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; form-action 'none'; " +
  "base-uri 'none'; frame-ancestors 'none'";
const packageVersion = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;

/** Every owner API response body, plus captured agent tool results, scanned for
 *  credential material at the end of a test. */
const responses = [];

async function waitFor(produce, message, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = produce();
    if (value !== undefined) return value;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(message);
}

/** A port the kernel has just handed out and released: free when we claim it. */
async function freePort() {
  const server = createNetServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  server.close();
  await once(server, 'close');
  return port;
}

async function holdPort(requestedPort = 0) {
  const server = createNetServer(socket => socket.destroy());
  server.listen(requestedPort, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  let released = false;
  return {
    port,
    async release() {
      if (released) return;
      released = true;
      server.close();
      await once(server, 'close');
    },
  };
}

// --- Compact AWS SigV4 verifier: proves the resolved secret key actually signed
// the request the receiver accepted (identical construction to the Phase 1 core
// test, so a signing regression fails here too). ---

function awsEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
function hmac(key, value) {
  return createHmac('sha256', key).update(value).digest();
}
function canonicalQuery(url) {
  return [...url.searchParams]
    .map(([n, v]) => [awsEncode(n), awsEncode(v)])
    .sort(([an, av], [bn, bv]) => (an !== bn ? (an < bn ? -1 : 1) : av === bv ? 0 : av < bv ? -1 : 1))
    .map(([n, v]) => `${n}=${v}`)
    .join('&');
}
function verifyAwsRequest(req, body, expected) {
  const authorization = req.headers.authorization ?? '';
  const match = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(authorization);
  if (!match) return false;
  const [, accessKeyId, shortDate, region, service, signedHeaderText, actualSignature] = match;
  if (accessKeyId !== expected.accessKeyId || region !== expected.region || service !== expected.service) return false;
  const signedHeaders = signedHeaderText.split(';');
  const canonicalHeaders = signedHeaders
    .map(name => `${name}:${String(req.headers[name]).trim().replace(/\s+/g, ' ')}\n`)
    .join('');
  const url = new URL(req.url, 'https://receiver.invalid');
  const canonicalRequest = [req.method, url.pathname, canonicalQuery(url), canonicalHeaders, signedHeaderText, sha256(body)].join('\n');
  const longDate = req.headers['x-amz-date'];
  if (typeof longDate !== 'string' || !longDate.startsWith(shortDate)) return false;
  const scope = `${shortDate}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${longDate}\n${scope}\n${sha256(canonicalRequest)}`;
  const dateKey = hmac(`AWS4${expected.secretAccessKey}`, shortDate);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, service);
  const signingKey = hmac(serviceKey, 'aws4_request');
  return createHmac('sha256', signingKey).update(stringToSign).digest('hex') === actualSignature;
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

/**
 * The real installed command, with HOME pointed at a scratch directory so the
 * owner's own `~/.config/blinddrop` is never read or written. v0.5.1 makes the
 * owner UI registry-driven, so no `--vault` is passed.
 */
function startOwnerUi(home) {
  const child = spawn(process.execPath, [cli, 'ui', '--no-browser'], {
    env: { ...process.env, HOME: home, NODE_EXTRA_CA_CERTS: ca },
  });
  const stdoutChunks = [];
  child.stdout.on('data', chunk => stdoutChunks.push(Buffer.from(chunk)));
  const stdout = () => Buffer.concat(stdoutChunks).toString('utf8');
  const stderr = collect(child.stderr);
  let outcome;
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      outcome = { code, signal };
      resolve(outcome);
    });
  });
  child.stdin.end();
  return { child, exit, stdout, stderr, exited: () => outcome };
}

/** One owner UI API request with exact control over Host, Origin and Authorization. */
function api(port, method, path, options = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (options.token !== undefined) headers.authorization = `Bearer ${options.token}`;
    if (options.origin !== undefined) headers.origin = options.origin;
    if (options.host !== undefined) headers.host = options.host;
    let payload;
    if (options.body !== undefined) {
      payload = Buffer.from(JSON.stringify(options.body), 'utf8');
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(payload.length);
    }
    const request = httpRequest({ hostname: '127.0.0.1', port, path, method, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.once('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        responses.push(text);
        let json;
        try {
          json = JSON.parse(text);
        } catch {
          json = undefined;
        }
        resolve({ status: response.statusCode, headers: response.headers, text, json });
      });
    });
    request.once('error', reject);
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

function statusOf(mcpUrl, token) {
  return new Promise((resolve, reject) => {
    const url = new URL(mcpUrl);
    const request = httpRequest({
      hostname: url.hostname,
      port: Number(url.port),
      path: url.pathname,
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
    request.end();
  });
}

async function attach(mcpUrl, token) {
  const client = new Client({ name: 'blinddrop-owner-ui-consumer', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  return client;
}

/** Runs execute_http through the official MCP client and records the result for
 *  the credential scan. */
async function execute(client, args) {
  const result = await client.callTool({ name: 'execute_http', arguments: args });
  responses.push(JSON.stringify(result.structuredContent ?? result));
  return result;
}

test('the owner UI signs multi-field secret requests, keeps values on replace, and never leaks a value', { timeout: 60_000 }, async t => {
  responses.length = 0;
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-owner-ui-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const home = join(dir, 'home');
  await mkdir(home, { recursive: true });
  const configDir = join(home, '.config', 'blinddrop');
  const defaultPath = join(configDir, 'vault.enc');
  const sessionFilePath = join(configDir, 'session.json');
  const logPath = `${defaultPath}.events.jsonl`;
  const backupPath = join(dir, 'backup.enc');

  const passphrase = `disposable-ui-passphrase-${randomBytes(18).toString('hex')}`;
  const creds = {
    accessKeyId: 'AKID' + randomBytes(8).toString('hex').toUpperCase(),
    secretAccessKey: randomBytes(24).toString('base64'),
    region: 'us-east-1',
    service: 's3',
  };
  const noteValue = `note-${randomBytes(8).toString('hex')}`;
  const sessionTokens = [];
  const operations = [];

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, async (request, response) => {
    const body = await readRequestBody(request);
    const signed = verifyAwsRequest(request, body, creds);
    operations.push({ url: request.url, signed });
    if (!signed) {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end('{"error":"signature mismatch"}');
      return;
    }
    if (request.url === '/reflect') {
      // A signed request whose response echoes the secret must be blocked by the
      // broker before it reaches the agent.
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ leaked: creds.secretAccessKey }));
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"bucket":"ok"}');
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });
  const receiverOrigin = `https://127.0.0.1:${receiver.address().port}`;
  const sessionPort = await freePort();

  const ui = startOwnerUi(home);
  t.after(async () => {
    if (ui.exited() === undefined) ui.child.kill('SIGTERM');
    await ui.exit;
  });
  const readinessLine = await waitFor(() => {
    const text = ui.stdout();
    const newline = text.indexOf('\n');
    if (newline !== -1) return text.slice(0, newline);
    return ui.exited() === undefined ? undefined : null;
  }, 'the ui command printed no readiness line');
  if (readinessLine === null) {
    assert.fail(`the ui command exited before printing readiness: ${await ui.stderr}`);
  }
  const ready = JSON.parse(readinessLine);
  const port = ready.port;
  const ownerToken = ready.token;
  assert.match(ownerToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(ready.url, `http://127.0.0.1:${port}/`);

  const readSession = () => JSON.parse(readFileSync(sessionFilePath, 'utf8'));
  const state = async () => {
    const response = await api(port, 'GET', '/api/state', { token: ownerToken });
    assert.equal(response.status, 200);
    return response.json;
  };
  const list = async () => {
    const response = await api(port, 'GET', '/api/list', { token: ownerToken });
    assert.equal(response.status, 200);
    return response;
  };

  // Proof 5: the listener boundary is unchanged. No token, a foreign Host and a
  // foreign Origin each fail with a static error; the page's own origin
  // succeeds; the page carries the CSP with no CORS header of any kind.
  const anonymous = await api(port, 'GET', '/api/state');
  assert.equal(anonymous.status, 403);
  assert.equal(anonymous.json.error.code, 'ACCESS_DENIED');
  const foreignHost = await api(port, 'GET', '/api/state', { token: ownerToken, host: 'evil.example' });
  assert.equal(foreignHost.status, 403);
  assert.equal(foreignHost.json.error.code, 'ACCESS_DENIED');
  const foreignOrigin = await api(port, 'GET', '/api/state', { token: ownerToken, origin: 'http://evil.example' });
  assert.equal(foreignOrigin.status, 403);
  assert.equal(foreignOrigin.json.error.code, 'ACCESS_DENIED');
  const sameOrigin = await api(port, 'GET', '/api/state', { token: ownerToken, origin: `http://127.0.0.1:${port}` });
  assert.equal(sameOrigin.status, 200);
  const page = await api(port, 'GET', `/?t=${ownerToken}`);
  assert.equal(page.status, 200);
  assert.equal(page.headers['content-security-policy'], CONTENT_SECURITY_POLICY);
  assert.equal(page.headers['access-control-allow-origin'], undefined);
  assert.equal(page.headers['content-type'], 'text/html; charset=utf-8');
  const pageWithoutToken = await api(port, 'GET', '/');
  assert.equal(pageWithoutToken.status, 403);

  // The state works while everything is locked (the welcome/unlock screens need
  // it) and reports the always-present default vault.
  const initial = await state();
  assert.equal(initial.version, packageVersion);
  assert.equal(initial.configDir, configDir);
  assert.equal(initial.sessionFilePath, sessionFilePath);
  assert.equal(initial.logPath, logPath);
  assert.deepEqual(initial.vaults, [{ name: 'default', path: defaultPath, registered: false, exists: false, unlocked: false }]);
  assert.equal(initial.session, null);
  assert.equal(initial.sessionError, null);

  // Pin the session to a known free port so we can assert the running endpoint.
  assert.equal((await api(port, 'POST', '/api/settings', { token: ownerToken, body: { sessionPort } })).status, 200);

  // Proof 1: create the default vault; it unlocks. Nothing is eligible yet.
  const created = await api(port, 'POST', '/api/vault/create', {
    token: ownerToken, body: { name: 'default', path: defaultPath, passphrase },
  });
  assert.equal(created.status, 200);
  assert.deepEqual(created.json.vaults, [{ name: 'default', path: defaultPath, registered: true, exists: true, unlocked: true }]);
  assert.equal(created.json.session, null);
  assert.equal(created.json.sessionError, null);
  // `default` is reserved for the default path.
  const misnamed = await api(port, 'POST', '/api/vault/create', {
    token: ownerToken, body: { name: 'default', path: join(dir, 'other.enc'), passphrase },
  });
  assert.equal(misnamed.status, 400);
  assert.equal(misnamed.json.error.code, 'INVALID_INPUT');

  // A typed multi-field `aws` secret with two fields.
  const secretSet = await api(port, 'POST', '/api/secret/set', {
    token: ownerToken,
    body: {
      vault: 'default', name: 'aws', type: 'aws',
      fields: {
        aws_access_key_id: { value: creds.accessKeyId, label: 'Access key ID', masked: false, multiline: false },
        aws_secret_access_key: { value: creds.secretAccessKey, label: 'Secret access key', masked: true, multiline: false },
      },
    },
  });
  assert.equal(secretSet.status, 200);
  assert.deepEqual(secretSet.json, { ok: true });
  assert.equal((await state()).session, null, 'a secret with no connection is not eligible to serve');

  // An aws-sigv4 connection referencing the two fields by vault#secret#field.
  const connectionSet = await api(port, 'POST', '/api/connection/set', {
    token: ownerToken,
    body: {
      vault: 'default', name: 's3', origin: receiverOrigin, allowPrivate: true,
      auth: {
        type: 'aws-sigv4',
        accessKeyIdSecret: 'default#aws#aws_access_key_id',
        secretAccessKeySecret: 'default#aws#aws_secret_access_key',
        region: creds.region, service: creds.service,
      },
    },
  });
  assert.equal(connectionSet.status, 200);

  // The implicit session starts on the chosen port and publishes the file the plugin reads.
  const running = await state();
  assert.notEqual(running.session, null);
  assert.deepEqual(Object.keys(running.session.connections), ['s3']);
  assert.equal(running.session.sessionFile, sessionFilePath);
  assert.equal(running.sessionError, null);
  assert.equal(new URL(running.session.mcpUrl).port, String(sessionPort));
  assert.equal(statSync(sessionFilePath).mode & 0o777, 0o600);
  const published = readSession();
  assert.match(published.token, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(published.token, ownerToken);
  sessionTokens.push(published.token);

  // A real signed request the receiver accepts, and a reflected secret blocked.
  const agent = await attach(published.mcpUrl, published.token);
  const connections = await agent.callTool({ name: 'list_connections', arguments: {} });
  assert.deepEqual(connections.structuredContent.connections, [{
    name: 's3', origin: receiverOrigin, authType: 'aws-sigv4',
  }]);
  const probe = await execute(agent, { connection: 's3', path: '/probe' });
  assert.equal(probe.isError, undefined);
  assert.equal(probe.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(probe.structuredContent.body), { bucket: 'ok' });
  const reflected = await execute(agent, { connection: 's3', path: '/reflect' });
  assert.equal(reflected.isError, true);
  assert.equal(reflected.structuredContent.error.code, 'RESPONSE_BLOCKED');

  // Proof 5: the two tokens never authorize each other's listener.
  assert.equal(await statusOf(published.mcpUrl, ownerToken), 403);
  assert.equal((await api(port, 'GET', '/api/state', { token: published.token })).status, 403);
  await agent.close();

  // Proof 3: the list carries what the page renders and never a field value.
  const listed = await list();
  assert.equal(listed.json.vaults.length, 1);
  assert.equal(listed.json.vaults[0].name, 'default');
  const awsSecret = listed.json.vaults[0].secrets.find(s => s.name === 'aws');
  assert.equal(awsSecret.type, 'aws');
  assert.equal(awsSecret.enabled, true);
  assert.deepEqual(awsSecret.usedBy, ['s3']);
  assert.deepEqual(awsSecret.fields.map(f => f.id).sort(), ['aws_access_key_id', 'aws_secret_access_key']);
  for (const f of awsSecret.fields) {
    assert.equal(f.set, true, 'a stored field reports its value is present');
    assert.equal('value' in f, false, 'a field never carries its value');
  }
  const s3 = listed.json.connections.find(c => c.name === 's3');
  assert.equal('vault' in s3, false, 'a connection has no owning vault');
  assert.equal(s3.authType, 'aws-sigv4');
  assert.deepEqual(s3.definition.auth.accessKeyIdSecret, 'default#aws#aws_access_key_id');
  assert.deepEqual(s3.missingRefs, []);
  assert.equal(s3.inSession, true);
  // The most recent agent call on s3 was the blocked reflection.
  assert.equal(typeof s3.lastUsed, 'string');
  assert.equal(s3.lastOutcome, 'blocked');
  assert.equal(listed.text.includes(creds.accessKeyId), false);
  assert.equal(listed.text.includes(creds.secretAccessKey), false);

  // Proof 4: a replace that omits the two field values keeps them and adds a
  // custom field; a fresh signed request still authenticates, proving the
  // secret access key value survived the replace.
  const replaced = await api(port, 'POST', '/api/secret/set', {
    token: ownerToken,
    body: {
      vault: 'default', name: 'aws', type: 'aws',
      fields: {
        aws_access_key_id: { label: 'Access key ID', masked: false, multiline: false },
        aws_secret_access_key: { label: 'Secret access key', masked: true, multiline: false },
        note: { value: noteValue, label: 'Note', masked: false, multiline: false },
      },
    },
  });
  assert.equal(replaced.status, 200);
  const afterReplace = readSession();
  assert.notEqual(afterReplace.token, published.token);
  sessionTokens.push(afterReplace.token);
  const keptAgent = await attach(afterReplace.mcpUrl, afterReplace.token);
  const stillSigned = await execute(keptAgent, { connection: 's3', path: '/probe' });
  assert.equal(stillSigned.isError, undefined);
  assert.equal(stillSigned.structuredContent.status, 200, 'omitted field values were kept: the request still signs');
  await keptAgent.close();

  const withNote = await list();
  const noteFields = withNote.json.vaults[0].secrets.find(s => s.name === 'aws').fields.map(f => f.id);
  assert.deepEqual(noteFields.sort(), ['aws_access_key_id', 'aws_secret_access_key', 'note']);
  assert.equal(withNote.text.includes(noteValue), false, 'a shown field value is still never sent');

  // Proof 4: field/remove drops the custom field.
  const dropped = await api(port, 'POST', '/api/secret/field/remove', {
    token: ownerToken, body: { vault: 'default', name: 'aws', fieldId: 'note' },
  });
  assert.equal(dropped.status, 200);
  const afterDrop = await list();
  const remaining = afterDrop.json.vaults[0].secrets.find(s => s.name === 'aws').fields.map(f => f.id);
  assert.deepEqual(remaining.sort(), ['aws_access_key_id', 'aws_secret_access_key']);

  // import-env creates api-key secrets in one write; the batch is not eligible on its own.
  const env = await api(port, 'POST', '/api/secret/import-env', {
    token: ownerToken, body: { vault: 'default', secrets: { spare_one: randomBytes(8).toString('hex') } },
  });
  assert.equal(env.status, 200);
  const withEnv = await list();
  const spare = withEnv.json.vaults[0].secrets.find(s => s.name === 'spare_one');
  assert.equal(spare.type, 'api-key');
  assert.deepEqual(spare.fields.map(f => f.id), ['token']);
  assert.deepEqual(spare.usedBy, []);

  // Groups are an owner-side sidecar keyed by connection name; agents never see them.
  const grouped = await api(port, 'POST', '/api/groups', {
    token: ownerToken, body: { groups: ['cloud'], connections: { 's3': ['cloud'] } },
  });
  assert.equal(grouped.status, 200);
  assert.deepEqual(grouped.json, { groups: ['cloud'], connections: { 's3': ['cloud'] } });
  const groupRejected = await api(port, 'POST', '/api/groups', {
    token: ownerToken, body: { groups: ['cloud'], connections: { 'absent': ['cloud'] } },
  });
  assert.equal(groupRejected.status, 400);
  assert.deepEqual((await list()).json.connections.find(c => c.name === 's3').groups, ['cloud']);

  // Activity records the real use events without any credential.
  const activity = await api(port, 'GET', '/api/activity', { token: ownerToken });
  assert.equal(activity.status, 200);
  // Newest first: the post-replace probe, the blocked reflection, the first probe.
  assert.deepEqual(activity.json.events.map(e => e.outcome), ['success', 'blocked', 'success']);

  // Backup copies the encrypted bytes and never overwrites.
  const backup = await api(port, 'POST', '/api/vault/backup', {
    token: ownerToken, body: { vault: 'default', path: backupPath },
  });
  assert.equal(backup.status, 200);
  assert.deepEqual(readFileSync(backupPath), readFileSync(defaultPath));
  const overwrite = await api(port, 'POST', '/api/vault/backup', {
    token: ownerToken, body: { vault: 'default', path: backupPath },
  });
  assert.equal(overwrite.status, 409);

  // Locking the only vault ends the session and withdraws its file.
  const locked = await api(port, 'POST', '/api/vault/lock', { token: ownerToken, body: { name: 'default' } });
  assert.equal(locked.status, 200);
  assert.equal(locked.json.vaults[0].unlocked, false);
  assert.equal(locked.json.session, null);
  assert.equal(existsSync(sessionFilePath), false);

  const shutdown = await api(port, 'POST', '/api/shutdown', { token: ownerToken, body: {} });
  assert.deepEqual(shutdown.json, { ok: true });
  assert.deepEqual(await ui.exit, { code: 0, signal: null });

  // Every receiver hit carried a valid signature.
  assert.deepEqual(operations, [
    { url: '/probe', signed: true },
    { url: '/reflect', signed: true },
    { url: '/probe', signed: true },
  ]);

  // Proof 6: no field value, passphrase, or session token in any response,
  // stdout, stderr or the use log.
  const log = existsSync(logPath) ? readFileSync(logPath, 'utf8') : '';
  const transcript = `${ui.stdout()}${await ui.stderr}${responses.join('')}${log}`;
  for (const material of [passphrase, creds.accessKeyId, creds.secretAccessKey, noteValue, ...sessionTokens]) {
    assert.equal(transcript.includes(material), false);
  }
  t.diagnostic('The real ui command signed multi-field secret requests, kept omitted values on replace, blocked a reflected secret, and never returned a value or unlock material.');
});

test('two vaults: a cross-vault connection is usable only when both are unlocked', { timeout: 60_000 }, async t => {
  responses.length = 0;
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-owner-multivault-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const home = join(dir, 'home');
  await mkdir(home, { recursive: true });
  const configDir = join(home, '.config', 'blinddrop');
  const defaultPath = join(configDir, 'vault.enc');
  const vaultBPath = join(dir, 'vault-b.enc');
  const sessionFilePath = join(configDir, 'session.json');

  const passA = `disposable-a-${randomBytes(18).toString('hex')}`;
  const passB = `disposable-b-${randomBytes(18).toString('hex')}`;
  const valueA = `key-a-${randomBytes(16).toString('hex')}`;
  const valueB = `key-b-${randomBytes(16).toString('hex')}`;
  const sessionTokens = [];

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, (request, response) => {
    let ok = false;
    if (request.url === '/both') {
      ok = request.headers['x-key-a'] === valueA && request.headers['x-key-b'] === valueB;
    } else if (request.url === '/onlya') {
      ok = request.headers.authorization === `Bearer ${valueA}`;
    }
    response.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
    response.end(JSON.stringify(ok ? { ok: true } : { error: 'unauthorized' }));
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });
  const receiverOrigin = `https://127.0.0.1:${receiver.address().port}`;
  const sessionPort = await freePort();

  const ui = startOwnerUi(home);
  t.after(async () => {
    if (ui.exited() === undefined) ui.child.kill('SIGTERM');
    await ui.exit;
  });
  const ready = JSON.parse(await waitFor(() => {
    const text = ui.stdout();
    const newline = text.indexOf('\n');
    return newline === -1 ? undefined : text.slice(0, newline);
  }, 'the ui command printed no readiness line'));
  const port = ready.port;
  const ownerToken = ready.token;

  const readSession = () => JSON.parse(readFileSync(sessionFilePath, 'utf8'));
  const state = async () => (await api(port, 'GET', '/api/state', { token: ownerToken })).json;
  const list = async () => (await api(port, 'GET', '/api/list', { token: ownerToken })).json;
  const post = async (path, body) => {
    const response = await api(port, 'POST', path, { token: ownerToken, body });
    assert.equal(response.status, 200, `${path}: ${response.text}`);
    return response.json;
  };

  await post('/api/settings', { sessionPort });
  await post('/api/vault/create', { name: 'default', path: defaultPath, passphrase: passA });
  await post('/api/vault/create', { name: 'vaultb', path: vaultBPath, passphrase: passB });
  const twoVaults = await state();
  assert.deepEqual(twoVaults.vaults.map(v => [v.name, v.unlocked]), [['default', true], ['vaultb', true]]);

  await post('/api/secret/import-env', { vault: 'default', secrets: { key_a: valueA } });
  await post('/api/secret/import-env', { vault: 'vaultb', secrets: { key_b: valueB } });

  // A connection in the default vault whose bindings reference a secret in each vault.
  await post('/api/connection/set', {
    vault: 'default', name: 'both', origin: receiverOrigin, allowPrivate: true,
    auth: {
      type: 'bindings',
      bindings: [
        { in: 'header', name: 'x-key-a', secret: 'key_a' },
        { in: 'header', name: 'x-key-b', secret: 'vaultb#key_b#token' },
      ],
    },
  });
  // A first-vault-only connection.
  await post('/api/connection/set', {
    vault: 'default', name: 'onlya', origin: receiverOrigin, allowPrivate: true,
    auth: { type: 'bearer', secret: 'key_a' },
  });

  // With both vaults unlocked, both connections are in the session.
  const bothUp = await state();
  assert.notEqual(bothUp.session, null);
  assert.deepEqual(Object.keys(bothUp.session.connections).sort(), ['both', 'onlya']);
  const firstToken = readSession().token;
  sessionTokens.push(firstToken);

  const agent = await attach(readSession().mcpUrl, firstToken);
  const crossVault = await execute(agent, { connection: 'both', path: '/both' });
  assert.equal(crossVault.isError, undefined);
  assert.equal(crossVault.structuredContent.status, 200, 'both vaults resolve, so the cross-vault connection authenticates');
  const firstOnly = await execute(agent, { connection: 'onlya', path: '/onlya' });
  assert.equal(firstOnly.structuredContent.status, 200);
  await agent.close();

  // Locking the second vault drops exactly the cross-vault connection.
  await post('/api/vault/lock', { name: 'vaultb' });
  const oneUp = await state();
  assert.notEqual(oneUp.session, null);
  assert.deepEqual(Object.keys(oneUp.session.connections), ['onlya'], 'locking vaultb removes exactly `both` from the session');
  const secondToken = readSession().token;
  assert.notEqual(secondToken, firstToken, 'the session token and file rotate when a vault is locked');
  assert.deepEqual(Object.keys(readSession().connections), ['onlya']);
  sessionTokens.push(secondToken);

  // Proof 3: the locked vault's reference is now missing on the cross-vault connection.
  const afterLock = await list();
  assert.deepEqual(afterLock.vaults.map(v => v.name), ['default'], 'the locked vault is absent from the list');
  const both = afterLock.connections.find(c => c.name === 'both');
  assert.deepEqual(both.missingRefs, ['vaultb#key_b#token']);
  assert.equal(both.inSession, false);
  const onlya = afterLock.connections.find(c => c.name === 'onlya');
  assert.deepEqual(onlya.missingRefs, []);
  assert.equal(onlya.inSession, true);

  // The first-vault-only connection keeps working under the new session; the
  // dropped connection is no longer authorized to the agent.
  const survivor = await attach(readSession().mcpUrl, secondToken);
  const stillWorks = await execute(survivor, { connection: 'onlya', path: '/onlya' });
  assert.equal(stillWorks.structuredContent.status, 200, 'the first-vault-only connection keeps working');
  const granted = await survivor.callTool({ name: 'list_connections', arguments: {} });
  assert.deepEqual(granted.structuredContent.connections.map(c => c.name), ['onlya']);
  const denied = await execute(survivor, { connection: 'both', path: '/both' });
  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.error.code, 'ACCESS_DENIED', 'the cross-vault connection is no longer granted');
  await survivor.close();

  const shutdown = await api(port, 'POST', '/api/shutdown', { token: ownerToken, body: {} });
  assert.deepEqual(shutdown.json, { ok: true });
  assert.deepEqual(await ui.exit, { code: 0, signal: null });

  const transcript = `${ui.stdout()}${await ui.stderr}${responses.join('')}`;
  for (const material of [passA, passB, valueA, valueB, ...sessionTokens]) {
    assert.equal(transcript.includes(material), false);
  }
  t.diagnostic('A cross-vault connection served only while both vaults were unlocked; locking the second dropped exactly it, rotated the session token/file, and left the first-vault-only connection working.');
});

test('a held saved port advances to a working session and persists the actual port', { timeout: 60_000 }, async t => {
  responses.length = 0;
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-owner-port-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const home = join(dir, 'home');
  await mkdir(home, { recursive: true });
  const configDir = join(home, '.config', 'blinddrop');
  const defaultPath = join(configDir, 'vault.enc');
  const sessionFilePath = join(configDir, 'session.json');
  const passphrase = `disposable-port-passphrase-${randomBytes(18).toString('hex')}`;
  const apiToken = randomBytes(24).toString('hex');
  let authenticatedRequests = 0;

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, (request, response) => {
    if (request.headers.authorization === `Bearer ${apiToken}`) authenticatedRequests++;
    response.writeHead(request.headers.authorization === `Bearer ${apiToken}` ? 200 : 401, {
      'content-type': 'application/json',
    });
    response.end('{"reachable":true}');
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });

  const held = await holdPort();
  t.after(() => held.release());

  const ui = startOwnerUi(home);
  t.after(async () => {
    if (ui.exited() === undefined) ui.child.kill('SIGTERM');
    await ui.exit;
  });
  const ready = JSON.parse(await waitFor(() => {
    const text = ui.stdout();
    const newline = text.indexOf('\n');
    return newline === -1 ? undefined : text.slice(0, newline);
  }, 'the ui command printed no readiness line'));
  const port = ready.port;
  const ownerToken = ready.token;

  const initialSettings = (await api(port, 'GET', '/api/settings', { token: ownerToken })).json;
  assert.ok(initialSettings.sessionPort >= 49_152 && initialSettings.sessionPort <= 65_535);
  assert.equal(JSON.parse(readFileSync(join(configDir, 'settings.json'), 'utf8')).sessionPort, initialSettings.sessionPort);

  assert.equal((await api(port, 'POST', '/api/settings', {
    token: ownerToken, body: { sessionPort: held.port },
  })).json.sessionPort, held.port);
  assert.equal((await api(port, 'POST', '/api/vault/create', {
    token: ownerToken, body: { name: 'default', path: defaultPath, passphrase },
  })).status, 200);
  assert.equal((await api(port, 'POST', '/api/secret/import-env', {
    token: ownerToken, body: { vault: 'default', secrets: { api_token: apiToken } },
  })).status, 200);
  const imported = await api(port, 'POST', '/api/connection/set', {
    token: ownerToken,
    body: {
      vault: 'default', name: 'api', origin: `https://127.0.0.1:${receiver.address().port}`,
      allowPrivate: true,
      auth: { type: 'bearer', secret: 'api_token' },
    },
  });
  assert.equal(imported.status, 200);

  const serving = await api(port, 'GET', '/api/state', { token: ownerToken });
  assert.equal(serving.json.vaults[0].unlocked, true);
  assert.notEqual(serving.json.session, null);
  assert.equal(serving.json.sessionError, null);
  const actualPort = Number(new URL(serving.json.session.mcpUrl).port);
  assert.notEqual(actualPort, held.port);
  assert.equal((await api(port, 'GET', '/api/settings', { token: ownerToken })).json.sessionPort, actualPort);
  assert.equal(JSON.parse(readFileSync(join(configDir, 'settings.json'), 'utf8')).sessionPort, actualPort);
  assert.equal(statSync(sessionFilePath).mode & 0o777, 0o600);

  const firstSession = JSON.parse(readFileSync(sessionFilePath, 'utf8'));
  const firstAgent = await attach(firstSession.mcpUrl, firstSession.token);
  const firstRequest = await execute(firstAgent, { connection: 'api', path: '/first' });
  assert.equal(firstRequest.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(firstRequest.structuredContent.body), { reachable: true });
  await firstAgent.close();

  // A new session after locking reuses the actual saved port, rather than the held preference.
  assert.equal((await api(port, 'POST', '/api/vault/lock', { token: ownerToken, body: { name: 'default' } })).status, 200);
  const reopened = await api(port, 'POST', '/api/vault/unlock', { token: ownerToken, body: { name: 'default', passphrase } });
  assert.equal(reopened.status, 200);
  assert.equal(reopened.json.vaults[0].unlocked, true);
  assert.equal(Number(new URL(reopened.json.session.mcpUrl).port), actualPort);
  const secondSession = JSON.parse(readFileSync(sessionFilePath, 'utf8'));
  const secondAgent = await attach(secondSession.mcpUrl, secondSession.token);
  assert.equal((await execute(secondAgent, { connection: 'api', path: '/again' })).structuredContent.status, 200);
  await secondAgent.close();
  assert.equal(authenticatedRequests, 2);

  const shutdown = await api(port, 'POST', '/api/shutdown', { token: ownerToken, body: {} });
  assert.deepEqual(shutdown.json, { ok: true });
  assert.deepEqual(await ui.exit, { code: 0, signal: null });
  const transcript = `${ui.stdout()}${await ui.stderr}${responses.join('')}`;
  assert.equal(transcript.includes(passphrase), false);
  assert.equal(transcript.includes(apiToken), false);
  t.diagnostic('A held saved port advanced to a useful authenticated session, persisted its actual endpoint, and the next session reused it.');
});

test('serve publishes the same session file only in HTTP mode and withdraws it on exit', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-session-file-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const home = join(dir, 'home');
  await mkdir(home, { recursive: true });
  const vaultPath = join(dir, 'vault.enc');
  const sessionFilePath = join(dir, 'agent-session.json');
  const settingsFilePath = join(home, '.config', 'blinddrop', 'settings.json');
  const passphrase = `disposable-serve-passphrase-${randomBytes(18).toString('hex')}`;
  const providerKey = randomBytes(32).toString('hex');
  const runs = [];
  t.after(async () => {
    await Promise.all(runs.map(async run => {
      if (run.child.exitCode === null && run.child.signalCode === null) run.child.kill('SIGTERM');
      await run.exit;
    }));
  });

  const spawnInHome = args => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    try {
      const run = spawnOwner(vaultPath, passphrase, args);
      runs.push(run);
      return run;
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  };

  const startServing = async portArgs => {
    const run = spawnInHome([
      'serve', '--http', '--allow', 'api', ...portArgs, '--ttl', '30',
      '--session-file', sessionFilePath,
    ]);
    run.child.stdin.end();
    const chunks = [];
    run.child.stdout.on('data', chunk => chunks.push(Buffer.from(chunk)));
    const readiness = await waitFor(() => {
      const text = Buffer.concat(chunks).toString('utf8');
      const newline = text.indexOf('\n');
      return newline === -1 ? undefined : JSON.parse(text.slice(0, newline));
    }, 'serve --http printed no readiness line');
    const published = await waitFor(
      () => (existsSync(sessionFilePath) ? JSON.parse(readFileSync(sessionFilePath, 'utf8')) : undefined),
      'serve --http --session-file never published the session file',
    );
    assert.equal(statSync(sessionFilePath).mode & 0o777, 0o600);
    assert.deepEqual(published, {
      mcpUrl: readiness.mcpUrl,
      token: readiness.token,
      expiresAt: readiness.expiresAt,
      connections: readiness.connections,
    });
    return { run, readiness, published };
  };

  const stopServing = async run => {
    run.child.kill('SIGTERM');
    assert.equal((await run.exit).code, 0);
    assert.equal(await run.stderr, '');
    assert.equal(existsSync(sessionFilePath), false);
  };

  await owner(vaultPath, passphrase, ['init']);
  await owner(
    vaultPath,
    passphrase,
    ['secret', 'set', 'api-token', '--secret-fd', '4'],
    providerKey,
  );
  await owner(vaultPath, passphrase, [
    'connection', 'set', 'api',
    '--origin', 'https://api.example.com',
    '--auth', 'bearer',
    '--secret', 'api-token',
  ]);

  // Stdio mode has no local endpoint to publish, so the option is refused.
  const refused = spawnInHome([
    'serve', '--allow', 'api', '--ttl', '30', '--session-file', sessionFilePath,
  ]);
  refused.child.stdin.end();
  const [refusedExit, refusedStdout, refusedStderr] = await Promise.all([
    refused.exit, collect(refused.child.stdout), refused.stderr,
  ]);
  assert.deepEqual(refusedExit, { code: 1, signal: null });
  assert.equal(refusedStdout, '');
  assert.equal(refusedStderr, 'INVALID_INPUT: Invalid input.\n');
  assert.equal(existsSync(sessionFilePath), false);

  const first = await startServing([]);
  const firstPort = Number(new URL(first.readiness.mcpUrl).port);
  assert.ok(firstPort >= 49_152 && firstPort <= 65_535);
  assert.equal(JSON.parse(readFileSync(settingsFilePath, 'utf8')).sessionPort, firstPort);
  assert.equal(JSON.stringify(first.published).includes(passphrase), false);
  assert.equal(JSON.stringify(first.published).includes(providerKey), false);
  await stopServing(first.run);

  const held = await holdPort(firstPort);
  t.after(() => held.release());
  const fallback = await startServing([]);
  const fallbackPort = Number(new URL(fallback.readiness.mcpUrl).port);
  assert.notEqual(fallbackPort, firstPort);
  assert.equal(JSON.parse(readFileSync(settingsFilePath, 'utf8')).sessionPort, fallbackPort);
  await stopServing(fallback.run);
  await held.release();

  const customPort = await freePort();
  const custom = await startServing(['--port', String(customPort)]);
  assert.equal(Number(new URL(custom.readiness.mcpUrl).port), customPort);
  assert.equal(JSON.parse(readFileSync(settingsFilePath, 'utf8')).sessionPort, customPort);
  await stopServing(custom.run);

  const temporary = await startServing(['--port', '0']);
  assert.ok(Number(new URL(temporary.readiness.mcpUrl).port) > 0);
  assert.equal(JSON.parse(readFileSync(settingsFilePath, 'utf8')).sessionPort, customPort);
  await stopServing(temporary.run);
  t.diagnostic('The installed serve command chose and reused one saved random port, advanced after a collision, saved an explicit custom port, left an explicit temporary port unsaved, and withdrew each published session file.');
});
