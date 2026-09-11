import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { validateConnection } from '../dist/vault.js';
import { owner, session } from './support/owner-session.mjs';

const baseConnection = {
  origin: 'https://api.example.com',
  allowPrivate: false,
  enabled: true,
};

test('OAuth target configuration accepts one bounded provider audience and one absolute fragment-free resource', () => {
  const auth = {
    type: 'oauth2',
    tokenEndpoint: 'https://issuer.example.com/token',
    grant: 'client_credentials',
    clientId: 'public-client',
    clientAuth: 'none',
  };

  assert.doesNotThrow(() => validateConnection({
    ...baseConnection,
    auth: { ...auth, audience: 'provider defined audience', resource: 'urn:blinddrop:records' },
  }));
  assert.doesNotThrow(() => validateConnection({ ...baseConnection, auth }));

  for (const invalidTarget of [
    { audience: '' },
    { audience: 'invalid\naudience' },
    { audience: 'é'.repeat(1_025) },
    { resource: '/relative-resource' },
    { resource: 'https://resource.example.com/invalid path' },
    { resource: 'urn:blinddrop:records#fragment' },
  ]) {
    assert.throws(
      () => validateConnection({ ...baseConnection, auth: { ...auth, ...invalidTarget } }),
      error => error?.code === 'INVALID_INPUT',
    );
  }
});

test('owner-fixed OAuth scope, audience, and resource reach both grant types and cannot be overridden by an agent query', { timeout: 30_000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-oauth-targets-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const vault = join(dir, 'vault.enc');
  const passphrase = randomBytes(24).toString('hex');
  const clientSecret = randomBytes(24).toString('hex');
  const refreshToken = randomBytes(24).toString('hex');
  const suffix = randomBytes(8).toString('hex');
  const intended = {
    'client-good': {
      grant: 'client_credentials',
      scope: 'accounts:read',
      audience: `provider audience ${suffix}`,
      resource: `urn:blinddrop:accounts:${suffix}`,
      account: `machine-account-${suffix}`,
    },
    'refresh-good': {
      grant: 'refresh_token',
      scope: 'profile:read',
      audience: `https://api.example.test/${suffix}`,
      resource: `https://resource.example.test/accounts/${suffix}`,
      account: `owner-account-${suffix}`,
    },
    'client-missing': {
      grant: 'client_credentials',
      scope: 'accounts:read',
      audience: `required-audience-${suffix}`,
      resource: `urn:blinddrop:required:${suffix}`,
    },
    'refresh-wrong': {
      grant: 'refresh_token',
      scope: 'profile:read',
      audience: `required-refresh-audience-${suffix}`,
      resource: `urn:blinddrop:required-refresh:${suffix}`,
    },
  };
  const tokenRequests = [];
  const accessTokens = new Map();
  const issuedTokens = [];
  let resourceDispatches = 0;

  const fixture = createServer({
    key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)),
    cert: await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url)),
  }, async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString('utf8');
      const url = new URL(req.url, 'https://fixture.invalid');

      if (url.pathname === '/token') {
        const form = new URLSearchParams(body);
        const clientId = form.get('client_id');
        const expected = intended[clientId];
        tokenRequests.push({
          clientId,
          grant: form.getAll('grant_type'),
          scope: form.getAll('scope'),
          audience: form.getAll('audience'),
          resource: form.getAll('resource'),
        });
        const valid = expected !== undefined &&
          form.get('grant_type') === expected.grant &&
          form.get('client_secret') === clientSecret &&
          form.get('scope') === expected.scope &&
          form.get('audience') === expected.audience &&
          form.get('resource') === expected.resource &&
          (expected.grant !== 'refresh_token' || form.get('refresh_token') === refreshToken);
        if (!valid || expected.account === undefined) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_target' }));
          return;
        }

        const accessToken = randomBytes(24).toString('hex');
        issuedTokens.push(accessToken);
        accessTokens.set(accessToken, expected.account);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: accessToken, token_type: 'Bearer', expires_in: 60 }));
        return;
      }

      if (url.pathname === '/account') {
        resourceDispatches++;
        const accessToken = (req.headers.authorization ?? '').replace(/^Bearer /u, '');
        const account = accessTokens.get(accessToken);
        res.writeHead(account === undefined ? 401 : 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(account === undefined ? { error: 'unauthorized' } : {
          account,
          resourceQuery: url.searchParams.get('resource'),
          audienceQuery: url.searchParams.get('audience'),
        }));
        return;
      }

      res.writeHead(404).end();
    } catch {
      res.writeHead(400).end();
    }
  });
  fixture.listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  t.after(async () => {
    fixture.close();
    await once(fixture, 'close');
  });
  const origin = `https://127.0.0.1:${fixture.address().port}`;

  await owner(vault, passphrase, ['init']);
  await owner(vault, passphrase, ['secret', 'set', 'client-secret', '--secret-fd', '4'], clientSecret);
  await owner(vault, passphrase, ['secret', 'set', 'refresh-token', '--secret-fd', '4'], refreshToken);

  const auths = {
    'client-good': {
      type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'client_credentials',
      clientId: 'client-good', clientSecret: 'client-secret', clientAuth: 'body',
      scope: intended['client-good'].scope, audience: intended['client-good'].audience,
      resource: intended['client-good'].resource,
    },
    'refresh-good': {
      type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'refresh_token',
      clientId: 'refresh-good', clientSecret: 'client-secret', refreshSecret: 'refresh-token', clientAuth: 'body',
      scope: intended['refresh-good'].scope, audience: intended['refresh-good'].audience,
      resource: intended['refresh-good'].resource,
    },
    'client-missing': {
      type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'client_credentials',
      clientId: 'client-missing', clientSecret: 'client-secret', clientAuth: 'body',
      scope: intended['client-missing'].scope, resource: intended['client-missing'].resource,
    },
    'refresh-wrong': {
      type: 'oauth2', tokenEndpoint: origin + '/token', grant: 'refresh_token',
      clientId: 'refresh-wrong', clientSecret: 'client-secret', refreshSecret: 'refresh-token', clientAuth: 'body',
      scope: intended['refresh-wrong'].scope, audience: intended['refresh-wrong'].audience,
      resource: `urn:blinddrop:wrong:${suffix}`,
    },
  };
  for (const [name, auth] of Object.entries(auths)) {
    const path = join(dir, `${name}.json`);
    await writeFile(path, JSON.stringify({ origin, auth, allowPrivate: true, enabled: true }));
    await owner(vault, passphrase, ['connection', 'import', name, path]);
  }

  let active = await session(vault, passphrase, Object.keys(auths));
  t.after(async () => { if (active !== undefined) await active.close(); });

  const agentResource = `urn:agent:override:${suffix}`;
  const agentAudience = `agent-audience-${suffix}`;
  const clientResult = await active.execute({
    connection: 'client-good',
    path: '/account',
    query: { resource: agentResource, audience: agentAudience },
  });
  assert.equal(clientResult.isError, undefined, JSON.stringify(clientResult));
  assert.deepEqual(JSON.parse(clientResult.structuredContent.body), {
    account: intended['client-good'].account,
    resourceQuery: agentResource,
    audienceQuery: agentAudience,
  });

  const refreshResult = await active.execute({ connection: 'refresh-good', path: '/account' });
  assert.equal(refreshResult.isError, undefined, JSON.stringify(refreshResult));
  assert.equal(JSON.parse(refreshResult.structuredContent.body).account, intended['refresh-good'].account);

  for (const name of ['client-missing', 'refresh-wrong']) {
    const before = resourceDispatches;
    const denied = await active.execute({ connection: name, path: '/account' });
    assert.equal(denied.isError, true, JSON.stringify(denied));
    assert.equal(denied.structuredContent.error?.code, 'UPSTREAM_ERROR');
    assert.equal(resourceDispatches, before, `${name} dispatched a resource request`);
  }

  for (const name of ['client-good', 'refresh-good']) {
    const request = tokenRequests.find(candidate => candidate.clientId === name);
    assert.deepEqual(request, {
      clientId: name,
      grant: [intended[name].grant],
      scope: [intended[name].scope],
      audience: [intended[name].audience],
      resource: [intended[name].resource],
    });
  }
  assert.equal(
    tokenRequests.find(candidate => candidate.clientId === 'client-good').audience.includes(agentAudience),
    false,
  );
  assert.equal(
    tokenRequests.find(candidate => candidate.clientId === 'client-good').resource.includes(agentResource),
    false,
  );

  const transcript = await active.close();
  active = undefined;
  const visible = JSON.stringify(transcript) + await readFile(vault + '.events.jsonl', 'utf8');
  for (const secret of [passphrase, clientSecret, refreshToken, ...issuedTokens]) {
    assert.equal(visible.includes(secret), false, 'credential appeared in consumer traffic/log');
  }
  t.diagnostic('Both grants delivered one owner-fixed scope/audience/resource; useful account reads succeeded, missing/wrong targets stopped before resource dispatch, agent query values did not alter token requests, and captured MCP/stderr/use logs contained no credentials.');
});
