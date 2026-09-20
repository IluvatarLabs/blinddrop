import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Broker } from '../dist/broker.js';
import { ca, owner, session } from './support/owner-session.mjs';

const cert = await readFile(ca, 'utf8');
const key = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url), 'utf8');

function fieldSecret(value) {
  return {
    type: 'api-key',
    fields: { value: { value, label: 'Value', masked: true, multiline: false } },
    enabled: true,
  };
}

async function fixture(t, handler, tls = {}) {
  const server = createServer({ cert, key, ...tls }, handler);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.close(); server.closeAllConnections(); await once(server, 'close'); });
  return `https://127.0.0.1:${server.address().port}`;
}

test('real owner CLI/MCP mTLS: accepted certificate identifies client; missing/wrong certificates never dispatch HTTP', { timeout: 60000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-mtls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const openssl = args => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=BlindDrop disposable client CA', '-keyout', 'ca.key', '-out', 'ca.crt']);
  openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=functional-client', '-keyout', 'client.key', '-out', 'client.csr']);
  await writeFile(join(dir, 'client.ext'), 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n');
  openssl(['x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-sha256', '-extfile', 'client.ext', '-out', 'client.crt']);
  const certificate = await readFile(join(dir, 'client.crt'), 'utf8');
  const privateKey = await readFile(join(dir, 'client.key'), 'utf8');
  let requests = 0;
  const origin = await fixture(t, (req, res) => {
    requests++;
    assert.equal(req.socket.authorized, true);
    res.end(JSON.stringify({ client: req.socket.getPeerCertificate().subject.CN }));
  }, { requestCert: true, rejectUnauthorized: true, ca: await readFile(join(dir, 'ca.crt')) });
  const vault = join(dir, 'vault.enc');
  const passphrase = randomBytes(24).toString('hex');
  const dummy = randomBytes(24).toString('hex');
  await owner(vault, passphrase, ['init']);
  for (const [name, value] of [['certificate', certificate], ['private-key', privateKey], ['wrong-cert', cert], ['wrong-key', key], ['dummy', dummy]]) {
    await owner(vault, passphrase, ['secret', 'set', name, '--secret-fd', '4'], value);
  }
  const definitions = {
    accepted: { auth: { type: 'none' }, tls: { certificateSecret: 'certificate', privateKeySecret: 'private-key' } },
    wrong: { auth: { type: 'none' }, tls: { certificateSecret: 'wrong-cert', privateKeySecret: 'wrong-key' } },
    missing: { auth: { type: 'bearer', secret: 'dummy' } }
  };
  for (const [name, definition] of Object.entries(definitions)) {
    const path = join(dir, name + '.json');
    await writeFile(path, JSON.stringify({ origin, allowPrivate: true, enabled: true, ...definition }));
    await owner(vault, passphrase, ['connection', 'import', name, path]);
  }
  const active = await session(vault, passphrase, Object.keys(definitions));
  let closed = false;
  t.after(async () => { if (!closed) await active.close(); });
  const accepted = await active.execute({ connection: 'accepted', path: '/identity' });
  assert.equal(accepted.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(accepted.structuredContent.body), { client: 'functional-client' });
  for (const connection of ['missing', 'wrong']) {
    const result = await active.execute({ connection, path: '/identity' });
    assert.equal(result.structuredContent.error?.code, 'UPSTREAM_ERROR');
  }
  assert.equal(requests, 1, 'TLS failures did not deliver an HTTP operation');
  const traffic = await active.close(); closed = true;
  const visible = JSON.stringify(traffic) + await readFile(vault + '.events.jsonl', 'utf8');
  for (const value of [passphrase, certificate.trim(), privateKey.trim(), key.trim(), dummy]) {
    assert.equal(visible.includes(value), false);
  }
  t.diagnostic('Actual CLI/MCP returned the TLS-authenticated client identity; missing/wrong certs failed at handshake; no private key/certificate/unlock material appeared in captured consumer traffic or logs.');
});

test('HTTPS response semantics: discarded cookie does not suppress a safe result; compressed HEAD has no body', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-http-semantics-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const secret = randomBytes(24).toString('hex');
  const origin = await fixture(t, (req, res) => {
    if (req.method === 'HEAD') { res.setHeader('Content-Encoding', 'gzip'); res.end(); return; }
    res.setHeader('Set-Cookie', 'opaque=' + secret + '; Secure; HttpOnly');
    res.end('usable response');
  });
  const now = new Date().toISOString();
  const broker = new Broker({ version: 2, createdAt: now, updatedAt: now, secrets: { token: fieldSecret(secret) },
    connections: { receiver: { origin, auth: { type: 'bearer', secret: 'token' }, allowPrivate: true, enabled: true } } },
    { id: 'http-semantics', connections: ['receiver'], expiresAt: Date.now() + 30000 }, { logPath: join(dir, 'events.jsonl') });
  t.after(() => broker.close());
  const result = await broker.execute({ connection: 'receiver', path: '/' });
  assert.equal(result.body, 'usable response');
  assert.equal(result.headers['set-cookie'], undefined);
  const head = await broker.execute({ connection: 'receiver', path: '/', method: 'HEAD' });
  assert.equal(head.status, 200); assert.equal(head.body, '');
});

test('grant expiry aborts a delayed OAuth issuer and prevents the resource operation', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-grant-expiry-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  let tokenCalls = 0, resourceCalls = 0;
  const origin = await fixture(t, async (req, res) => {
    if (req.url === '/token') {
      tokenCalls++;
      await new Promise(resolve => setTimeout(resolve, 500));
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ access_token: randomBytes(24).toString('hex'), token_type: 'Bearer', expires_in: 60 }));
    } else { resourceCalls++; res.end('should not run'); }
  });
  const now = new Date().toISOString();
  const broker = new Broker({ version: 2, createdAt: now, updatedAt: now, secrets: { refresh: fieldSecret(randomBytes(24).toString('hex')) },
    connections: { receiver: { origin, auth: { type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'refresh_token', clientId: 'public-client', clientAuth: 'none', refreshSecret: 'refresh' }, allowPrivate: true, enabled: true } } },
    { id: 'expiry', connections: ['receiver'], expiresAt: Date.now() + 150 }, { logPath: join(dir, 'events.jsonl') });
  t.after(() => broker.close());
  await assert.rejects(() => broker.execute({ connection: 'receiver', path: '/resource' }), error => error?.code === 'SESSION_EXPIRED');
  assert.equal(tokenCalls, 1); assert.equal(resourceCalls, 0);
});
