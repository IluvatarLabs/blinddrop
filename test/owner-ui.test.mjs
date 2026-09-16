import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

import { ca, cli, collect, owner, spawnOwner } from './support/owner-session.mjs';

const keyPath = new URL('./fixtures/localhost-key.pem', import.meta.url);
const certPath = new URL('./fixtures/localhost-cert.pem', import.meta.url);

async function waitFor(produce, message, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = produce();
    if (value !== undefined) return value;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(message);
}

function startOwnerUi(vaultPath) {
  const child = spawn(process.execPath, [cli, '--vault', vaultPath, 'ui', '--no-browser'], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: ca },
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

test('the owner UI administers the vault and starts an agent session the CLI never sees', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-owner-ui-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const vaultPath = join(dir, 'vault.enc');
  const sessionFilePath = join(dir, 'session.json');
  const passphrase = `disposable-ui-passphrase-${randomBytes(18).toString('hex')}`;
  const providerKey = randomBytes(32).toString('hex');
  const operations = [];

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, (request, response) => {
    const authenticated = request.headers['x-api-key'] === providerKey &&
      request.headers.authorization === undefined;
    operations.push({ url: request.url, authenticated });
    if (!authenticated) {
      response.writeHead(401, { 'content-type': 'application/json' });
      response.end('{"error":"unauthorized"}');
      return;
    }
    if (request.url === '/identity') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"account":"functional-owner","id":731}');
      return;
    }
    if (request.url === '/reflect') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ reflected: providerKey }));
      return;
    }
    response.writeHead(404).end();
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });
  const receiverOrigin = `https://127.0.0.1:${receiver.address().port}`;

  const ui = startOwnerUi(vaultPath);
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
  assert.equal(typeof ready.port, 'number');
  assert.match(ready.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(ready.url, `http://127.0.0.1:${ready.port}/`);
  const port = ready.port;
  const ownerToken = ready.token;

  // 1. No credential at all is refused.
  const anonymous = await api(port, 'GET', '/api/state');
  assert.equal(anonymous.status, 403);
  assert.equal(anonymous.json.error.code, 'ACCESS_DENIED');

  // 2. A foreign Host header is refused even with the owner token (DNS rebinding).
  const foreignHost = await api(port, 'GET', '/api/state', { token: ownerToken, host: 'evil.example' });
  assert.equal(foreignHost.status, 403);
  assert.equal(foreignHost.json.error.code, 'ACCESS_DENIED');

  // 3. A foreign Origin is refused even with the owner token.
  const foreignOrigin = await api(port, 'GET', '/api/state', {
    token: ownerToken, origin: 'http://evil.example',
  });
  assert.equal(foreignOrigin.status, 403);
  assert.equal(foreignOrigin.json.error.code, 'ACCESS_DENIED');

  // 4. The owner token with no Origin reports an uninitialized vault.
  const initialState = await api(port, 'GET', '/api/state', { token: ownerToken });
  assert.equal(initialState.status, 200);
  assert.equal(initialState.json.vaultExists, false);
  assert.equal(initialState.json.unlocked, false);
  assert.equal(initialState.json.vaultPath, vaultPath);
  assert.equal(initialState.json.session, null);

  // 5. The page's own Origin is accepted; this is the deliberate difference from
  // the agent listener, which rejects every Origin.
  const sameOrigin = await api(port, 'GET', '/api/state', {
    token: ownerToken, origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(sameOrigin.status, 200);

  // 6. Owner administration over the API, with the secret value never read back.
  const initialized = await api(port, 'POST', '/api/init', { token: ownerToken, body: { passphrase } });
  assert.equal(initialized.status, 200);
  assert.deepEqual(initialized.json, { ok: true });

  const secretSet = await api(port, 'POST', '/api/secret/set', {
    token: ownerToken, body: { name: 'provider-key', value: providerKey },
  });
  assert.equal(secretSet.status, 200);

  const connectionSet = await api(port, 'POST', '/api/connection/set', {
    token: ownerToken,
    body: {
      name: 'receiver',
      origin: receiverOrigin,
      auth: 'header',
      field: 'x-api-key',
      secret: 'provider-key',
      allowPrivate: true,
    },
  });
  assert.equal(connectionSet.status, 200);

  const listed = await api(port, 'GET', '/api/list', { token: ownerToken });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.json.secrets, [{ name: 'provider-key', enabled: true }]);
  assert.deepEqual(listed.json.connections, [{
    name: 'receiver',
    origin: receiverOrigin,
    authType: 'header',
    allowPrivate: true,
    enabled: true,
  }]);
  assert.equal(listed.text.includes(providerKey), false);
  assert.equal(listed.text.includes(passphrase), false);

  // 7. The owner UI starts the same finite agent session the CLI serves, and
  // publishes it through the opt-in session file.
  const started = await api(port, 'POST', '/api/session/start', {
    token: ownerToken, body: { allow: ['receiver'], ttl: 60, port: 0 },
  });
  assert.equal(started.status, 200);
  assert.match(started.json.token, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(started.json.token, ownerToken);
  assert.equal(typeof started.json.mcpUrl, 'string');
  assert.equal(started.json.sessionFile, sessionFilePath);
  assert.equal(statSync(sessionFilePath).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await readFile(sessionFilePath, 'utf8')), {
    mcpUrl: started.json.mcpUrl,
    token: started.json.token,
    expiresAt: started.json.expiresAt,
    connections: started.json.connections,
  });

  const runningState = await api(port, 'GET', '/api/state', { token: ownerToken });
  assert.equal(runningState.json.unlocked, true);
  assert.equal(runningState.json.session.mcpUrl, started.json.mcpUrl);
  assert.equal(runningState.text.includes(started.json.token), false);

  const client = new Client({ name: 'blinddrop-owner-ui-consumer', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(started.json.mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${started.json.token}` } },
  });
  await client.connect(transport);
  t.after(() => client.close().catch(() => undefined));
  const connections = await client.callTool({ name: 'list_connections', arguments: {} });
  assert.deepEqual(connections.structuredContent.connections, [{
    name: 'receiver', origin: receiverOrigin, authType: 'header',
  }]);
  const identity = await client.callTool({
    name: 'execute_http', arguments: { connection: 'receiver', path: '/identity' },
  });
  assert.equal(identity.isError, undefined);
  assert.equal(identity.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(identity.structuredContent.body), {
    account: 'functional-owner', id: 731,
  });
  const reflected = await client.callTool({
    name: 'execute_http', arguments: { connection: 'receiver', path: '/reflect' },
  });
  assert.equal(reflected.isError, true);
  assert.equal(reflected.structuredContent.error.code, 'RESPONSE_BLOCKED');
  assert.deepEqual(operations, [
    { url: '/identity', authenticated: true },
    { url: '/reflect', authenticated: true },
  ]);

  // 8. The two tokens never authorize each other's listener.
  const ownerTokenAtSession = await new Promise((resolve, reject) => {
    const mcp = new URL(started.json.mcpUrl);
    const request = httpRequest({
      hostname: mcp.hostname,
      port: Number(mcp.port),
      path: mcp.pathname,
      method: 'GET',
      headers: { authorization: `Bearer ${ownerToken}` },
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
    request.end();
  });
  assert.equal(ownerTokenAtSession, 403);
  const sessionTokenAtUi = await api(port, 'GET', '/api/state', { token: started.json.token });
  assert.equal(sessionTokenAtUi.status, 403);
  assert.equal(sessionTokenAtUi.json.error.code, 'ACCESS_DENIED');

  // 9. Stopping the session withdraws the session file; shutdown ends the process
  // cleanly without ever printing owner unlock material or a provider secret.
  await client.close();
  const stopped = await api(port, 'POST', '/api/session/stop', { token: ownerToken, body: {} });
  assert.equal(stopped.status, 200);
  assert.deepEqual(stopped.json, { ok: true });
  assert.equal(existsSync(sessionFilePath), false);

  const shutdown = await api(port, 'POST', '/api/shutdown', { token: ownerToken, body: {} });
  assert.equal(shutdown.status, 200);
  assert.deepEqual(shutdown.json, { ok: true });
  const exit = await ui.exit;
  assert.deepEqual(exit, { code: 0, signal: null });

  const stderr = await ui.stderr;
  const printed = `${ui.stdout()}${stderr}`;
  assert.equal(printed.includes(passphrase), false);
  assert.equal(printed.includes(providerKey), false);
  assert.equal(printed.includes(started.json.token), false);
  t.diagnostic('The real ui command served owner administration, a browser-shaped API with loopback Host/Origin checks, an MCP session over the session file, and mutually inert owner and session tokens.');
});

test('serve publishes the same session file only in HTTP mode and withdraws it on exit', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-session-file-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const vaultPath = join(dir, 'vault.enc');
  const sessionFilePath = join(dir, 'agent-session.json');
  const passphrase = `disposable-serve-passphrase-${randomBytes(18).toString('hex')}`;
  const providerKey = randomBytes(32).toString('hex');

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
  const refused = spawnOwner(vaultPath, passphrase, [
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

  const serving = spawnOwner(vaultPath, passphrase, [
    'serve', '--http', '--allow', 'api', '--port', '0', '--ttl', '30',
    '--session-file', sessionFilePath,
  ]);
  serving.child.stdin.end();
  const servingChunks = [];
  serving.child.stdout.on('data', chunk => servingChunks.push(Buffer.from(chunk)));
  const readiness = await waitFor(() => {
    const text = Buffer.concat(servingChunks).toString('utf8');
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
  assert.equal(JSON.stringify(published).includes(passphrase), false);
  assert.equal(JSON.stringify(published).includes(providerKey), false);

  serving.child.kill('SIGTERM');
  const servingExit = await serving.exit;
  assert.equal(servingExit.code, 0);
  assert.equal(await serving.stderr, '');
  assert.equal(existsSync(sessionFilePath), false);
  t.diagnostic('The installed serve command published its own endpoint file with owner-only permissions and withdrew it when the session ended.');
});
