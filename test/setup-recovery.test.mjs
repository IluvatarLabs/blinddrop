import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { startOwnerUi } from '../dist/ui.js';
import { createVault } from '../dist/vault.js';

test('Lock All revokes access and a complete setup restores into fresh locked state', { timeout: 60_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'blinddrop-recovery-'));
  const originalHome = process.env.HOME;
  const sourceHome = join(root, 'source');
  const restoredHome = join(root, 'restored');
  const sourceConfig = join(sourceHome, 'custom-config');
  const restoredConfig = join(restoredHome, '.config/blinddrop');
  const backupPath = join(root, 'setup-backup');
  const passphrases = { personal: randomBytes(24).toString('hex'), work: randomBytes(24).toString('hex') };
  const credential = randomBytes(24).toString('hex');
  let ui, receiver;
  const request = async (path, body) => {
    const response = await fetch(new URL(path, ui.url), {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Authorization: `Bearer ${ui.token}`, Origin: new URL(ui.url).origin,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
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
  const execute = async () => {
    const state = await api('/api/state');
    assert.notEqual(state.session, null, JSON.stringify(state));
    const session = JSON.parse(await readFile(state.sessionFilePath, 'utf8'));
    const client = new Client({ name: 'setup-recovery-proof', version: '1' });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(session.mcpUrl), {
        requestInit: { headers: { Authorization: `Bearer ${session.token}` } },
      }));
      const result = await client.callTool({ name: 'execute_http', arguments: { connection: 'service', path: '/identity' } });
      assert.equal(result.structuredContent.status, 200);
      return JSON.parse(result.structuredContent.body).authenticated;
    } finally { await client.close(); }
  };

  try {
    receiver = createServer({
      key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)),
      cert: await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url)),
    }, (request, response) => {
      response.writeHead(request.headers.authorization === `Bearer ${credential}` ? 200 : 401,
        { 'content-type': 'application/json' });
      response.end(JSON.stringify({ authenticated: request.headers.authorization === `Bearer ${credential}` }));
    });
    receiver.listen(0, '127.0.0.1');
    await once(receiver, 'listening');
    const origin = `https://127.0.0.1:${receiver.address().port}`;

    process.env.HOME = sourceHome;
    const importedPath = join(sourceConfig, 'vault.enc');
    const eagerDefaultPath = join(sourceHome, '.config/blinddrop/vault.enc');
    createVault(importedPath, passphrases.personal);
    ui = await startOwnerUi({ sessionPort: 0, configDir: sourceConfig, vaultPath: eagerDefaultPath });
    const workPath = join(sourceHome, 'work.enc');
    const created = await api('/api/vault/create', { name: 'work', path: workPath, passphrase: passphrases.work });
    assert.deepEqual(created.vaults.map(vault => vault.name), ['work']);
    const opened = await api('/api/vault/open', { name: 'personal', path: importedPath });
    assert.deepEqual(opened.vaults.map(vault => vault.name), ['work', 'personal']);
    createVault(eagerDefaultPath, passphrases.personal);
    await api('/api/connection/import', { vault: 'work', name: 'service',
      definition: { origin, auth: { type: 'bearer', secret: 'work#service#value' }, allowPrivate: true, enabled: true },
      secrets: { service: { type: 'api-key', fields: { value: { value: credential, label: 'Token', masked: true, multiline: false } } } } });
    await api('/api/groups', { groups: ['production'], connections: { service: ['production'] } });
    await api('/api/settings', { appearance: 'dark' });
    assert.equal(await execute(), true);

    const sourceSession = (await api('/api/state')).sessionFilePath;
    await ui.lockAll();
    assert.equal(existsSync(sourceSession), false);
    assert.equal((await api('/api/state')).session, null);
    await api('/api/vault/unlock', { name: 'work', passphrase: passphrases.work });
    const backedUp = await api('/api/setup/backup', { path: backupPath });
    assert.equal(backedUp.vaults, 2);
    assert.equal(backedUp.size, (await readFile(join(backupPath, 'vaults/000.enc'))).length +
      (await readFile(join(backupPath, 'vaults/001.enc'))).length);
    assert.equal(await execute(), true, 'the paused session resumed after the complete snapshot');

    const connectionFile = join(sourceConfig, 'connections.json');
    const beforeRestore = { archive: await readFile(workPath), connections: await readFile(connectionFile) };
    const refusedRestore = await request('/api/setup/restore', { path: backupPath });
    assert.equal(refusedRestore.response.status, 409);
    assert.deepEqual(await readFile(workPath), beforeRestore.archive);
    assert.deepEqual(await readFile(connectionFile), beforeRestore.connections);
    assert.equal(await execute(), true, 'a refused restore leaves the existing connection usable');

    const missingPath = join(sourceHome, 'missing.enc');
    await api('/api/vault/create', { name: 'missing', path: missingPath, passphrase: passphrases.personal });
    await rm(missingPath);
    const partialTarget = join(root, 'must-not-exist');
    const incomplete = await request('/api/setup/backup', { path: partialTarget });
    assert.equal(incomplete.response.status, 404);
    assert.equal(incomplete.result.error.code, 'VAULT_NOT_FOUND');
    assert.equal(existsSync(partialTarget), false);
    await api('/api/vault/remove', { name: 'missing' });
    await ui.close(); ui = undefined;

    process.env.HOME = restoredHome;
    ui = await startOwnerUi({ sessionPort: 0, configDir: restoredConfig });
    assert.equal((await api('/api/state')).vaults.some(vault => vault.exists), false);
    const restored = await api('/api/setup/restore', { path: backupPath });
    assert.equal(restored.vaults.every(vault => !vault.unlocked), true);
    assert.equal(restored.session, null);
    assert.equal((await api('/api/settings')).appearance, 'dark');
    await api('/api/vault/unlock', { name: 'work', passphrase: passphrases.work });
    assert.equal((await api('/api/state')).vaults.find(vault => vault.name === 'personal').unlocked, false);
    assert.deepEqual((await api('/api/list')).connections.find(connection => connection.name === 'service').groups, ['production']);
    assert.deepEqual((await api('/api/activity')).events, []);
    assert.equal(await execute(), true, 'the restored encrypted vault and references authenticate after owner unlock');
  } finally {
    await ui?.close();
    if (receiver) { receiver.closeAllConnections(); await new Promise(resolve => receiver.close(resolve)); }
    if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
    await rm(root, { recursive: true, force: true });
  }
});
