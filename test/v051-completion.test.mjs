import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { startOwnerUi } from '../dist/ui.js';
import { createVault, loadVault } from '../dist/vault.js';
import { owner, session as cliSession } from './support/owner-session.mjs';

// Actual owner API -> session file -> official MCP client -> HTTPS receiver.
// Credentials stay in disposable vaults; the receiver returns only which account authenticated.
test('independent connection storage preserves locking, migration, activity, and CLI use', { timeout: 90_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'blinddrop-completion-'));
  const previousHome = process.env.HOME;
  process.env.HOME = root;
  const passphrase = randomBytes(24).toString('hex');
  const credentials = Object.fromEntries(['work', 'later', 'legacy', 'default'].map(n => [n, randomBytes(24).toString('hex')]));
  const legacyVaultName = `${'v'.repeat(19)}-${'a'.repeat(44)}`;
  const legacyDir = join(root, 'legacy');
  await mkdir(legacyDir);
  const vaultPaths = {
    default: join(root, 'chosen', 'personal.enc'),
    work: join(root, 'work.enc'),
    legacy: join(legacyDir, 'vault.enc'),
    available: join(root, 'available.enc'),
    temporary: join(root, 'temporary.enc'),
  };
  createVault(vaultPaths.available, passphrase);
  let ui, receiver;
  try {
    receiver = createServer({
      key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)),
      cert: await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url)),
    }, (request, response) => {
      const account = Object.entries(credentials).find(([, value]) => request.headers.authorization === `Bearer ${value}`)?.[0];
      response.writeHead(account ? 200 : 401, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ account }));
    });
    receiver.listen(0, '127.0.0.1');
    await once(receiver, 'listening');
    const origin = `https://127.0.0.1:${receiver.address().port}`;
    ui = await startOwnerUi({ sessionPort: 0 });
    const request = async (path, body, token = ui.token) => {
      const response = await fetch(new URL(path, ui.url), {
        method: body === undefined ? 'GET' : 'POST',
        headers: { Authorization: `Bearer ${token}`, Origin: new URL(ui.url).origin, 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const result = await response.json();
      return { response, result };
    };
    const api = async (path, body) => {
      const { response, result } = await request(path, body);
      assert.equal(response.status, 200, `${path}: ${JSON.stringify(result)}`);
      return result;
    };
    const denied = async (path, body, token = ui.token) => {
      const { response, result } = await request(path, body, token);
      assert.equal(response.status, 403, `${path}: ${JSON.stringify(result)}`);
      assert.equal(result.error.code, 'ACCESS_DENIED');
    };
    const execute = async name => {
      const state = await api('/api/state');
      assert.equal(state.sessionError, null);
      const file = JSON.parse(await readFile(state.sessionFilePath, 'utf8'));
      const client = new Client({ name: 'completion-proof', version: '1' });
      try {
        await client.connect(new StreamableHTTPClientTransport(new URL(file.mcpUrl), {
          requestInit: { headers: { Authorization: `Bearer ${file.token}` } },
        }));
        const result = await client.callTool({ name: 'execute_http', arguments: { connection: name, path: '/identity' } });
        assert.equal(result.isError, undefined);
        assert.equal(result.structuredContent.status, 200);
        return JSON.parse(result.structuredContent.body).account;
      } finally { await client.close(); }
    };
    const field = (value, label = 'Access token', masked = true) => ({ value, label, masked, multiline: false });
    const customFieldIds = Array.from({ length: 65 }, (_, index) => `custom_${String(index + 1).padStart(2, '0')}`);
    const customFields = Object.fromEntries(customFieldIds.map((id, index) => [
      id,
      field(index === customFieldIds.length - 1 ? credentials.later : `disposable-${index}`, `Custom ${index + 1}`),
    ]));
    const secretFields = {
      access_token: field(credentials.work),
      public_key: field('disposable-public-key', 'Public key', false),
      ...customFields,
    };
    for (const name of ['default', 'work']) await api('/api/vault/create', { name, path: vaultPaths[name], passphrase });
    assert.equal((await api('/api/state')).vaults.find(v => v.name === 'default').path, vaultPaths.default);
    await api('/api/secret/set', { vault: 'work', name: 'credential', type: 'custom', fields: secretFields });
    await api('/api/secret/set', { vault: 'work', name: 'single', type: 'api-key', fields: { access_token: field(credentials.work) } });
    const definition = { origin, auth: { type: 'bearer', secret: 'work#credential#access_token' }, allowPrivate: true, enabled: true };
    const laterDefinition = { ...definition, auth: { type: 'bearer', secret: `work#credential#${customFieldIds.at(-1)}` } };
    await api('/api/connection/import', { vault: 'default', name: 'shared', definition });
    await api('/api/connection/import', { vault: 'work', name: 'late-field', definition: laterDefinition });
    assert.equal(await execute('shared'), 'work');
    assert.equal(await execute('late-field'), 'later', 'a field beyond the old 64-field ceiling authenticates a real request');
    const createdFields = (await api('/api/list')).vaults.find(v => v.name === 'work').secrets.find(s => s.name === 'credential').fields;
    assert.equal(createdFields.length, 67);
    assert.equal(createdFields.find(item => item.id === customFieldIds.at(-1)).set, true);
    for (const name of ['default', 'work']) assert.deepEqual(loadVault(vaultPaths[name], passphrase).connections, {});
    const config = await readFile(join(root, '.config/blinddrop/connections.json'), 'utf8');
    for (const value of [...Object.values(credentials), passphrase]) assert.equal(config.includes(value), false);

    await api('/api/vault/lock', { name: 'work' });
    const bareDefinition = { ...definition, auth: { type: 'bearer', secret: 'single' } };
    await denied('/api/connection/import', { vault: 'work', name: 'bare-locked', definition: bareDefinition });
    await denied('/api/connection/import', { vault: 'work', name: 'mixed-locked', definition: {
      ...definition, auth: { type: 'basic', usernameSecret: 'single', passwordSecret: 'single#value' },
    } });
    await api('/api/connection/import', { vault: 'work', name: 'explicit-locked', definition });
    await api('/api/vault/unlock', { name: 'work', passphrase });
    await api('/api/connection/import', { vault: 'work', name: 'bare-locked', definition: bareDefinition });
    assert.equal(await execute('bare-locked'), 'work', 'an unlocked sole typed field becomes the bare reference default');
    assert.equal(await execute('explicit-locked'), 'work', 'a fully qualified reference stays editable while its vault is locked');
    await api('/api/connection/remove', { name: 'bare-locked' });
    await api('/api/connection/remove', { name: 'explicit-locked' });

    await api('/api/vault/lock', { name: 'default' });
    assert.equal(await execute('shared'), 'work', 'locking a vault without the connection secrets must not revoke it');
    assert.equal(await execute('late-field'), 'later');
    assert.equal((await api('/api/activity')).events.some(e => e.connection === 'late-field' && e.outcome === 'success'), true);
    assert.notEqual((await api('/api/list')).connections.find(c => c.name === 'late-field').lastUsed, null);
    await api('/api/groups', { groups: ['work'], connections: { shared: ['work'] } });
    await api('/api/connection/disable', { name: 'late-field' });
    await api('/api/connection/enable', { name: 'late-field' });
    await api('/api/vault/lock', { name: 'work' });

    // The owner token remains mandatory but no longer replaces vault unlock as
    // authority to read operational data or change connection configuration.
    const allLocked = await api('/api/state');
    assert.equal(allLocked.vaults.every(v => !v.unlocked), true);
    assert.equal(allLocked.session, null);
    const lockedRoutes = [
      ['/api/list'],
      ['/api/activity?limit=1'],
      ['/api/activity/clear', {}],
      ['/api/connection/set', { vault: 'work', name: 'locked-set', origin, auth: definition.auth, allowPrivate: true }],
      ['/api/connection/import', { vault: 'work', name: 'locked-import', definition }],
      ['/api/connection/enable', { name: 'late-field' }],
      ['/api/connection/disable', { name: 'late-field' }],
      ['/api/connection/remove', { name: 'shared' }],
      ['/api/groups', { groups: [], connections: {} }],
    ];
    for (const [path, body] of lockedRoutes) await denied(path, body);

    // Locked-screen operations stay usable. Opening only registers a locked
    // archive; creating a different vault unlocks that vault, not the work vault.
    assert.equal((await api('/api/settings')).appearance, 'system');
    assert.equal((await api('/api/settings', { appearance: 'dark' })).appearance, 'dark');
    assert.equal((await api('/api/vault/open', { name: 'available', path: vaultPaths.available })).vaults.find(v => v.name === 'available').unlocked, false);
    assert.equal((await api('/api/vault/create', { name: 'temporary', path: vaultPaths.temporary, passphrase })).vaults.find(v => v.name === 'temporary').unlocked, true);
    await denied('/api/secret/set', { vault: 'work', name: 'must-stay-locked', type: 'custom', fields: { value: field('not-written') } });
    await api('/api/vault/lock', { name: 'temporary' });
    await denied('/api/vault/unlock', { name: 'work', passphrase }, randomBytes(32).toString('base64url'));
    await api('/api/vault/unlock', { name: 'work', passphrase });

    const preserved = await api('/api/list');
    assert.deepEqual(preserved.connections.map(c => c.name).sort(), ['late-field', 'shared']);
    assert.equal(preserved.connections.find(c => c.name === 'late-field').definition.enabled, true);
    assert.deepEqual(preserved.connections.find(c => c.name === 'shared').groups, ['work']);
    assert.equal((await api('/api/activity')).events.some(e => e.connection === 'late-field' && e.outcome === 'success'), true,
      'the denied clear route must leave prior activity intact');

    await ui.close();
    ui = await startOwnerUi({ sessionPort: 0 });
    await api('/api/vault/unlock', { name: 'work', passphrase });
    assert.equal(await execute('shared'), 'work', 'restarted owner server only needs the secret vault');
    assert.deepEqual((await api('/api/list')).connections.find(c => c.name === 'shared').groups, ['work']);
    const editedFields = Object.fromEntries(Object.entries(secretFields).map(([id, item]) => [id, {
      label: id === 'access_token' ? 'Renamed access token' : id === customFieldIds.at(-1) ? 'Later token' : item.label,
      masked: item.masked,
      multiline: item.multiline,
    }]));
    await api('/api/secret/set', { vault: 'work', name: 'credential', type: 'custom', fields: editedFields });
    assert.equal(await execute('shared'), 'work', 'label edit retains the saved value and connection reference');
    assert.equal(await execute('late-field'), 'later', 'the stable later-field id retains its omitted value through editing');
    const edited = (await api('/api/list')).vaults.find(v => v.name === 'work').secrets.find(s => s.name === 'credential').fields;
    assert.equal(edited.length, 67);
    assert.deepEqual(edited.find(item => item.id === customFieldIds.at(-1)), {
      id: customFieldIds.at(-1), label: 'Later token', masked: true, multiline: false, set: true,
    });

    // Genuine v1 archive; a colliding connection name must preserve both records.
    const now = new Date().toISOString();
    const payload = { version: 1, createdAt: now, updatedAt: now,
      secrets: { legacy: { value: credentials.legacy, enabled: true } },
      connections: { shared: { ...definition, auth: { type: 'bearer', secret: 'legacy' } } },
    };
    const salt = randomBytes(16), iv = randomBytes(12);
    const key = scryptSync(passphrase, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    await writeFile(vaultPaths.legacy, Buffer.concat([Buffer.from([2]), salt, iv, cipher.getAuthTag(), encrypted]));
    // A restored old archive may sit beside a newer standalone CLI sidecar.
    // Both definitions survive even when their names collide before registration.
    await writeFile(`${vaultPaths.legacy}.connections.json`, JSON.stringify({ version: 1, connections: {
      shared: { ...definition, auth: { type: 'bearer', secret: 'default#legacy#value' }, enabled: false },
    } }));
    await api('/api/vault/unlock', { name: 'default', passphrase });
    await api('/api/vault/open', { name: legacyVaultName, path: vaultPaths.legacy });
    if (process.platform !== 'win32' && process.getuid?.() !== 0) {
      // Publish the independent config, then fail the real encrypted-file replacement.
      const originalArchive = await readFile(vaultPaths.legacy);
      await chmod(legacyDir, 0o500);
      try {
        const failed = await fetch(new URL('/api/vault/unlock', ui.url), {
          method: 'POST', headers: { Authorization: `Bearer ${ui.token}`, Origin: new URL(ui.url).origin, 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: legacyVaultName, passphrase }),
        });
        assert.notEqual(failed.status, 200);
        assert.deepEqual(await readFile(vaultPaths.legacy), originalArchive);
        assert.ok(loadVault(vaultPaths.legacy, passphrase).connections.shared);
        assert.equal(Object.keys(JSON.parse(await readFile(join(root, '.config/blinddrop/connections.json'), 'utf8')).connections).length, 4);
        await ui.close();
        ui = await startOwnerUi({ sessionPort: 0 });
        await api('/api/vault/unlock', { name: 'work', passphrase });
        await api('/api/vault/unlock', { name: 'default', passphrase });
      } finally { await chmod(legacyDir, 0o700); }
    }
    await api('/api/vault/unlock', { name: legacyVaultName, passphrase });
    const migrated = (await api('/api/list')).connections.find(c => c.definition.auth.secret === `${legacyVaultName}#legacy#value` && c.definition.enabled);
    assert.ok(migrated);
    assert.notEqual(migrated.name, 'shared');
    assert.match(migrated.name, /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/);
    const sidecar = (await api('/api/list')).connections.find(c => !c.definition.enabled);
    assert.ok(sidecar);
    assert.notEqual(sidecar.name, migrated.name);
    assert.equal(sidecar.definition.auth.secret, `${legacyVaultName}#legacy#value`);
    await assert.rejects(readFile(`${vaultPaths.legacy}.connections.json`), { code: 'ENOENT' });
    assert.equal(await execute(migrated.name), 'legacy', 'missing same-name default secret must not kill the session');
    await api('/api/secret/set', { vault: 'default', name: 'legacy', type: 'api-key', fields: { value: field(credentials.default) } });
    assert.equal(await execute(migrated.name), 'legacy', 'same-name default secret must never replace the imported credential');
    assert.equal(await execute('shared'), 'work');
    await api('/api/vault/lock', { name: legacyVaultName });
    await api('/api/vault/unlock', { name: legacyVaultName, passphrase });
    assert.equal((await api('/api/list')).connections.length, 4, 'reopening does not duplicate migrated connections');

    const listed = JSON.parse(await owner(vaultPaths.work, passphrase, ['list']));
    assert.ok(listed.connections.some(c => c.name === 'shared'));
    const cli = await cliSession(vaultPaths.work, passphrase, ['shared']);
    try {
      const result = await cli.execute({ connection: 'shared', path: '/identity' });
      assert.equal(result.structuredContent.status, 200);
      assert.equal(JSON.parse(result.structuredContent.body).account, 'work');
    } finally { await cli.close(); }
  } finally {
    await ui?.close();
    if (receiver) { receiver.closeAllConnections(); await new Promise(resolve => receiver.close(resolve)); }
    if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome;
    await rm(root, { recursive: true, force: true });
  }
});
