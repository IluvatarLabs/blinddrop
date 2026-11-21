// Owner OAuth consent through the exported owner runtime (src/ui.ts): the
// refresh grant lands in the selected vault, not another unlocked vault, and a
// vault lock before the callback writes nothing, even after that vault is
// unlocked again. The runtime runs in-process against a real HTTPS
// authorization server on loopback with generated disposable credentials.
// HOME is scoped to a temporary root during construction, so no owner Activity
// log or configuration is touched, and `work` is registered
// before anything else so the empty-registry `default` placeholder, which
// resolves HOME at call time, is never consulted. Every archive, log,
// setting and session file lives in that root.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { get as httpGet, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, get as httpsGet } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

import { startOwnerUi } from '../dist/ui.js';

const certificate = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url));
const privateKey = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url));

/** Every owner API response and agent result, scanned for credential material. */
const transcript = [];

function disposable(prefix) {
  return `${prefix}-${randomBytes(18).toString('base64url')}`;
}

function get(url) {
  const getter = url.protocol === 'https:' ? httpsGet : httpGet;
  return new Promise((resolve, reject) => {
    const request = getter(url, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.once('error', reject);
  });
}

/** The browser's part: the provider redirects to the loopback callback. */
async function followAuthorization(url) {
  const authorized = await get(url);
  assert.equal(authorized.status, 302);
  return get(new URL(authorized.headers.location));
}

/** A confidential-client authorization server and one account resource. */
async function provider(t) {
  const client = { id: disposable('client'), secret: disposable('client-secret') };
  const issued = { codes: [], access: [], refresh: [], refreshInputs: [] };
  let tokenRequests = 0;
  let origin;
  const server = createHttpsServer({ cert: certificate, key: privateKey }, async (request, response) => {
    const url = new URL(request.url, origin);
    const reply = (status, value) => {
      response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      response.end(JSON.stringify(value));
    };
    if (url.pathname === '/authorize') {
      const callback = new URL(url.searchParams.get('redirect_uri'));
      if (url.searchParams.get('client_id') === client.id) {
        const code = randomBytes(24).toString('base64url');
        issued.codes.push(code);
        callback.searchParams.set('code', code);
      } else {
        callback.searchParams.set('error', 'unauthorized_client');
      }
      callback.searchParams.set('state', url.searchParams.get('state'));
      callback.searchParams.set('iss', origin);
      response.writeHead(302, { location: callback.href, 'cache-control': 'no-store' });
      response.end();
      return;
    }
    if (url.pathname === '/token') {
      tokenRequests++;
      const chunks = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      const authenticated = form.get('client_id') === client.id && form.get('client_secret') === client.secret;
      if (authenticated && form.get('grant_type') === 'authorization_code' && issued.codes.includes(form.get('code'))) {
        const access = randomBytes(24).toString('base64url');
        const refresh = randomBytes(24).toString('base64url');
        issued.access.push(access);
        issued.refresh.push(refresh);
        reply(200, { access_token: access, token_type: 'Bearer', expires_in: 3600, refresh_token: refresh });
        return;
      }
      if (authenticated && form.get('grant_type') === 'refresh_token') {
        issued.refreshInputs.push(form.get('refresh_token'));
        if (issued.refresh.includes(form.get('refresh_token'))) {
          const access = randomBytes(24).toString('base64url');
          issued.access.push(access);
          reply(200, { access_token: access, token_type: 'Bearer', expires_in: 3600 });
          return;
        }
      }
      reply(400, { error: 'invalid_grant' });
      return;
    }
    if (url.pathname === '/account') {
      const allowed = issued.access.length > 0 && request.headers.authorization === `Bearer ${issued.access.at(-1)}`;
      reply(allowed ? 200 : 401, allowed ? { account: 'disposable-owner-account' } : { error: 'invalid_token' });
      return;
    }
    response.writeHead(404).end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `https://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.close();
    server.closeAllConnections();
  });
  return { origin, client, issued, tokenRequests: () => tokenRequests };
}

/** The exported runtime the desktop host uses, called over HTTP as the page does. */
async function ownerRuntime(t, visitAuthorizationUrl) {
  const root = await mkdtemp(join(tmpdir(), 'blinddrop-owner-oauth-'));
  let runtime;
  t.after(async () => {
    await runtime?.close();
    await rm(root, { recursive: true, force: true });
  });
  const home = join(root, 'home');
  await mkdir(home);
  const configDir = join(home, '.config', 'blinddrop');
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    runtime = await startOwnerUi({ configDir, sessionPort: 0, visitAuthorizationUrl });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
  const port = Number(new URL(runtime.url).port);
  const call = (method, path, body) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
    const headers = { authorization: `Bearer ${runtime.token}` };
    if (payload !== undefined) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(payload.length);
    }
    const request = httpRequest({ hostname: '127.0.0.1', port, path, method, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.once('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        transcript.push(text);
        if (response.statusCode === 200) resolve(JSON.parse(text));
        else reject(new Error(`${method} ${path} returned ${response.statusCode}: ${text}`));
      });
    });
    request.once('error', reject);
    request.end(payload);
  });
  return {
    configDir,
    get: path => call('GET', path),
    post: (path, body) => call('POST', path, body),
  };
}

async function settled(owner) {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const { oauth } = await owner.get('/api/oauth/status');
    if (oauth.status !== 'waiting' && oauth.status !== 'saving') return oauth;
    assert.ok(Date.now() < deadline, 'the consent attempt reached a terminal state');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

async function createVault(owner, name, passphrase) {
  await owner.post('/api/vault/create', { name, path: join(owner.configDir, `${name}.enc`), passphrase });
}

async function storeClient(owner, vault, client) {
  await owner.post('/api/secret/set', {
    vault,
    name: 'oauth-client',
    type: 'oauth',
    fields: {
      client_id: { value: client.id, label: 'Client ID', masked: false, multiline: false },
      client_secret: { value: client.secret, label: 'Client secret', masked: true, multiline: false },
    },
  });
}

function definition(origin) {
  return {
    origin,
    auth: {
      type: 'oauth2',
      tokenEndpoint: `${origin}/token`,
      grant: 'refresh_token',
      clientIdSecret: 'work#oauth-client#client_id',
      clientSecret: 'work#oauth-client#client_secret',
      clientAuth: 'body',
      refreshSecret: 'work#oauth-client#refresh_token',
      scope: 'account.read',
    },
    allowPrivate: true,
    enabled: true,
    consent: { issuer: origin, authorizationEndpoint: `${origin}/authorize` },
  };
}

function bundleFields(listed, vault) {
  const bundle = listed.vaults.find(entry => entry.name === vault).secrets.find(secret => secret.name === 'oauth-client');
  return Object.fromEntries(bundle.fields.map(field => [field.id, field.set]));
}

test('owner consent saves the grant into the selected vault and the restarted agent session uses it', { timeout: 60_000 }, async t => {
  transcript.length = 0;
  const server = await provider(t);
  const authorizationUrls = [];
  const owner = await ownerRuntime(t, async url => {
    authorizationUrls.push(new URL(url));
    assert.equal((await followAuthorization(new URL(url))).status, 200);
  });
  const workPassphrase = disposable('work-passphrase');
  const defaultPassphrase = disposable('default-passphrase');
  await createVault(owner, 'work', workPassphrase);
  await createVault(owner, 'default', defaultPassphrase);
  await storeClient(owner, 'work', server.client);
  // A same-named decoy bundle in another unlocked vault: resolving the client
  // or writing the grant against the wrong vault is observable.
  await storeClient(owner, 'default', { id: disposable('decoy-client'), secret: disposable('decoy-secret') });

  const started = await owner.post('/api/oauth/start', { vault: 'work', name: 'account', definition: definition(server.origin) });
  assert.equal(started.oauth.status, 'waiting');
  const oauth = await settled(owner);
  assert.equal(oauth.status, 'succeeded', JSON.stringify(oauth.error));
  assert.deepEqual(oauth.saved, { grant: true, connection: true, groups: false });

  const listed = await owner.get('/api/list');
  assert.deepEqual(bundleFields(listed, 'work'), { client_id: true, client_secret: true, refresh_token: true });
  assert.deepEqual(bundleFields(listed, 'default'), { client_id: true, client_secret: true });
  const account = listed.connections.find(connection => connection.name === 'account');
  assert.equal(account.definition.auth.refreshSecret, 'work#oauth-client#refresh_token');

  const published = JSON.parse(readFileSync(join(owner.configDir, 'session.json'), 'utf8'));
  const agent = new Client({ name: 'blinddrop-owner-oauth-consumer', version: '1' });
  await agent.connect(new StreamableHTTPClientTransport(new URL(published.mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${published.token}` } },
  }));
  let result;
  try {
    result = await agent.callTool({ name: 'execute_http', arguments: { connection: 'account', path: '/account' } });
  } finally {
    await agent.close();
  }
  transcript.push(JSON.stringify(result));
  assert.equal(result.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(result.structuredContent.body), { account: 'disposable-owner-account' });
  assert.deepEqual(server.issued.refreshInputs, [server.issued.refresh[0]], 'the session refreshed with the grant consent stored');

  const visible = transcript.join('\n');
  for (const material of [
    workPassphrase,
    defaultPassphrase,
    server.client.id,
    server.client.secret,
    ...server.issued.codes,
    ...server.issued.access,
    ...server.issued.refresh,
    ...authorizationUrls.flatMap(url => [url.searchParams.get('state'), url.searchParams.get('code_challenge')]),
  ]) {
    assert.equal(visible.includes(material), false, 'owner responses and agent results exclude credentials and consent values');
  }
});

test('locking the selected vault before the callback cancels consent and writes nothing after unlock', { timeout: 60_000 }, async t => {
  const server = await provider(t);
  let capture;
  const captured = new Promise(resolve => { capture = resolve; });
  const owner = await ownerRuntime(t, async url => { capture(new URL(url)); });
  const passphrase = disposable('work-passphrase');
  await createVault(owner, 'work', passphrase);
  await storeClient(owner, 'work', server.client);

  await owner.post('/api/oauth/start', { vault: 'work', name: 'account', definition: definition(server.origin) });
  const authorizationUrl = await captured;
  await owner.post('/api/vault/lock', { name: 'work' });
  const oauth = await settled(owner);
  assert.equal(oauth.status, 'cancelled');
  assert.deepEqual(oauth.saved, { grant: false, connection: false, groups: false });

  // Access resumes, then the browser finishes consent: the late callback is refused.
  await owner.post('/api/vault/unlock', { name: 'work', passphrase });
  await assert.rejects(followAuthorization(authorizationUrl), { code: 'ECONNREFUSED' });
  assert.equal(server.tokenRequests(), 0, 'no authorization code was exchanged');

  const listed = await owner.get('/api/list');
  assert.deepEqual(bundleFields(listed, 'work'), { client_id: true, client_secret: true });
  assert.equal(listed.connections.some(connection => connection.name === 'account'), false);
});
