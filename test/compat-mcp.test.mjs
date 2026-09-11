import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadVault } from '../dist/vault.js';
import { owner, session } from './support/owner-session.mjs';

test('owner CLI → stdio MCP → real HTTPS: credential placements and refresh rotation survive restart', { timeout: 90000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-compat-mcp-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const vault = join(dir, 'vault.enc');
  const passphrase = randomBytes(24).toString('hex');
  const first = randomBytes(24).toString('hex');
  const second = 'value with + / = & " ' + randomBytes(24).toString('hex');
  let refresh = randomBytes(24).toString('hex');
  const forbidden = [passphrase, first, second, refresh];
  const received = [];
  const accessTokens = new Map();
  let uploaded;
  let tokenRequests = 0;
  let revoke = false;
  const fixture = createServer({
    key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)),
    cert: await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url))
  }, async (req, res) => {
    try {
      const chunks = [];
      for await (const part of req) chunks.push(part);
      const bytes = Buffer.concat(chunks);
      const body = bytes.toString('utf8');
      const url = new URL(req.url, 'https://fixture.invalid');
      received.push(url.pathname);
      if (url.pathname === '/file') {
        if (req.headers['x-first'] !== `Key ${first}`) { res.writeHead(401); res.end(); return; }
        if (req.method === 'POST') {
          const form = await new Request('https://fixture.invalid', { method: 'POST', headers: req.headers, body: bytes }).formData();
          uploaded = Buffer.from(await form.get('file').arrayBuffer());
          assert.equal(form.get('purpose'), 'functional-check');
          res.end(JSON.stringify({ id: 'disposable-file', size: uploaded.length }));
        } else if (req.method === 'PUT') {
          uploaded = Buffer.from(bytes); res.end(JSON.stringify({ id: 'disposable-file', size: uploaded.length }));
        } else if (req.method === 'DELETE') {
          uploaded = undefined; res.writeHead(204); res.end();
        } else if (uploaded) {
          res.setHeader('Content-Type', 'application/octet-stream'); res.end(uploaded);
        } else { res.writeHead(404); res.end(); }
        return;
      }
      if (url.pathname === '/token') {
        tokenRequests++;
        const form = new URLSearchParams(body);
        if (revoke || form.get('refresh_token') !== refresh || form.get('grant_type') !== 'refresh_token' ||
            form.get('client_id') !== 'functional-client' || form.get('client_secret') !== first) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        const token = randomBytes(24).toString('hex');
        refresh = randomBytes(24).toString('hex');
        forbidden.push(token, refresh);
        accessTokens.set(token, Date.now() + 2000);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: token, refresh_token: refresh, token_type: 'Bearer', expires_in: 2 }));
        return;
      }
      let valid = false;
      let family = url.pathname;
      if (family === '/header') valid = req.headers['x-first'] === `Key ${first}` && req.headers['x-second'] === first;
      if (family === '/query') valid = url.searchParams.getAll('key').length === 1 && url.searchParams.get('key') === first;
      if (family === '/basic') valid = req.headers.authorization === 'Basic ' + Buffer.from(first + ':').toString('base64');
      if (family === '/json') {
        const object = JSON.parse(body);
        valid = object.client_id === first && object.secret === second && object.operation === 'read' && Object.hasOwn(object, '__proto__') && object.__proto__ === first;
      }
      if (family === '/form') {
        const form = new URLSearchParams(body);
        valid = form.get('key') === second && form.getAll('key').length === 1 && form.get('operation') === 'read';
      }
      if (family === `/bot${first}/getMe`) { valid = true; family = '/path'; }
      if (family === '/identity') {
        const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
        valid = (accessTokens.get(token) ?? 0) > Date.now();
      }
      if (family === '/reflect') {
        res.end(req.headers.authorization ?? first);
        return;
      }
      res.writeHead(valid ? 200 : 401, { 'content-type': 'application/json' });
      res.end(JSON.stringify(valid ? { account: 'disposable-receiver', family } : { error: 'unauthorized' }));
    } catch {
      res.writeHead(400); res.end('invalid request');
    }
  });
  fixture.listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  t.after(async () => { fixture.close(); await once(fixture, 'close'); });
  const origin = `https://127.0.0.1:${fixture.address().port}`;
  await owner(vault, passphrase, ['init']);
  for (const [name, value] of [['first', first], ['second', second], ['refresh', refresh]]) {
    await owner(vault, passphrase, ['secret', 'set', name, '--secret-fd', '4'], value);
  }
  const auths = {
    header: { type: 'bindings', bindings: [
      { in: 'header', name: 'X-First', secret: 'first', prefix: 'Key ' },
      { in: 'header', name: 'X-Second', secret: 'first' }
    ] },
    query: { type: 'query', name: 'key', secret: 'first' },
    basic: { type: 'basic', usernameSecret: 'first' },
    json: { type: 'bindings', bindings: [
      { in: 'json', name: 'client_id', secret: 'first' },
      { in: 'json', name: 'secret', secret: 'second' },
      { in: 'json', name: '__proto__', secret: 'first' }
    ] },
    form: { type: 'bindings', bindings: [{ in: 'form', name: 'key', secret: 'second' }] },
    path: { type: 'bindings', bindings: [{ in: 'path', prefix: '/bot', secret: 'first' }] },
    oauth: { type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'refresh_token', clientId: 'functional-client', clientSecret: 'first', refreshSecret: 'refresh', clientAuth: 'body' }
  };
  for (const [name, auth] of Object.entries(auths)) {
    const path = join(dir, name + '.json');
    await writeFile(path, JSON.stringify({ origin, auth, allowPrivate: true, enabled: true }));
    await owner(vault, passphrase, ['connection', 'import', name, path]);
  }
  let active = await session(vault, passphrase, Object.keys(auths));
  const transcripts = [];
  t.after(async () => { if (active) await active.close(); });
  for (const input of [
    { connection: 'header', path: '/header', headers: { 'x-FiRsT': 'wrong', 'X-Second': 'wrong' } },
    { connection: 'query', path: '/query?key=wrong&key=other' },
    { connection: 'basic', path: '/basic', headers: { Authorization: 'wrong' } },
    { connection: 'json', path: '/json', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id: 'wrong', secret: 'wrong', operation: 'read' }) },
    { connection: 'form', path: '/form', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'key=wrong&key=other&operation=read' },
    { connection: 'path', path: '/getMe' },
    { connection: 'oauth', path: '/identity' }
  ]) {
    const result = await active.execute(input);
    assert.equal(result.isError, undefined, input.connection + ': ' + JSON.stringify(result));
    assert.equal(result.structuredContent.status, 200, input.connection);
    assert.equal(JSON.parse(result.structuredContent.body).account, 'disposable-receiver');
  }
  assert.equal(tokenRequests, 1);
  const file = Buffer.from([0, 1, 2, 255, 254, 128, 10]);
  const upload = await active.execute({ connection: 'header', path: '/file', method: 'POST', multipart: {
    fields: { purpose: 'functional-check' }, files: [{ name: 'file', filename: 'sample.bin', dataBase64: file.toString('base64') }]
  } });
  assert.equal(upload.structuredContent.status, 200);
  assert.equal(JSON.parse(upload.structuredContent.body).size, file.length);
  const download = await active.execute({ connection: 'header', path: '/file', responseEncoding: 'base64' });
  assert.equal(download.structuredContent.bodyEncoding, 'base64');
  assert.deepEqual(Buffer.from(download.structuredContent.body, 'base64'), file);
  const replacement = Buffer.concat([file, file]);
  const put = await active.execute({ connection: 'header', path: '/file', method: 'PUT', bodyBase64: replacement.toString('base64') });
  assert.equal(put.structuredContent.status, 200);
  const replaced = await active.execute({ connection: 'header', path: '/file', responseEncoding: 'base64' });
  assert.deepEqual(Buffer.from(replaced.structuredContent.body, 'base64'), replacement);
  const removed = await active.execute({ connection: 'header', path: '/file', method: 'DELETE' });
  assert.equal(removed.structuredContent.status, 204);
  const missing = await active.execute({ connection: 'header', path: '/file' });
  assert.equal(missing.structuredContent.status, 404);
  assert.equal(loadVault(vault, passphrase).secrets.refresh.value, refresh);
  await new Promise(resolve => setTimeout(resolve, 2100));
  const renewed = await active.execute({ connection: 'oauth', path: '/identity' });
  assert.equal(renewed.structuredContent.status, 200);
  assert.equal(tokenRequests, 2);
  assert.equal(loadVault(vault, passphrase).secrets.refresh.value, refresh);
  const reflected = await active.execute({ connection: 'oauth', path: '/reflect' });
  assert.equal(reflected.structuredContent.error?.code, 'RESPONSE_BLOCKED');
  transcripts.push(await active.close()); active = null;
  active = await session(vault, passphrase, ['oauth']);
  const restarted = await active.execute({ connection: 'oauth', path: '/identity' });
  assert.equal(restarted.structuredContent.status, 200);
  assert.equal(tokenRequests, 3);
  revoke = true;
  await new Promise(resolve => setTimeout(resolve, 2100));
  const resourceCalls = received.filter(path => path === '/identity').length;
  const revoked = await active.execute({ connection: 'oauth', path: '/identity' });
  assert.equal(revoked.isError, true);
  assert.equal(received.filter(path => path === '/identity').length, resourceCalls);
  transcripts.push(await active.close()); active = null;
  const visible = JSON.stringify(transcripts) + await readFile(vault + '.events.jsonl', 'utf8');
  for (const value of forbidden) assert.equal(visible.includes(value), false, 'credential appeared in consumer traffic/log');
  t.diagnostic('Six static placement forms authenticated; multipart create/binary read/update/delete preserved bytes; OAuth expiry/rotation/restart/revocation worked; captured MCP/stderr/use log contained no source or issued credentials.');
});
