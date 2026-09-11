import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:https';
import test from 'node:test';

import { exportPKCS8, generateKeyPair, jwtVerify } from 'jose';

import { AuthSession } from '../dist/auth.js';
import { owner, session as openMcpSession } from './support/owner-session.mjs';
import { sendHttps } from '../dist/transport.js';

const limits = {
  requestBytes: 1024 * 1024,
  responseBytes: 4 * 1024 * 1024,
  headerBytes: 16 * 1024,
  timeoutMs: 10_000,
  concurrency: 4,
};

function vault(values) {
  const now = new Date().toISOString();
  return {
    version: 1,
    createdAt: now,
    updatedAt: now,
    secrets: Object.fromEntries(Object.entries(values).map(([name, value]) => [
      name,
      { value, enabled: true },
    ])),
    connections: {},
  };
}

function connection(origin, auth) {
  return { origin, auth, allowPrivate: true, enabled: true };
}

function prepared(origin, path, method = 'GET', body) {
  const url = new URL(path, origin);
  return {
    url,
    method,
    headers: body === undefined
      ? { host: url.host }
      : { host: url.host, 'content-type': 'application/json' },
    body,
  };
}

async function dispatch(result, allowPrivate = true) {
  return sendHttps({
    ...result.request,
    allowPrivate,
    tls: result.tls,
    signal: AbortSignal.timeout(limits.timeoutMs),
    limits,
  });
}

async function clientFor(t, data, configured, generatedCredentials = () => []) {
  const directory = await mkdtemp(join(tmpdir(), 'blinddrop-auth-boundary-'));
  const archive = join(directory, 'vault.enc');
  const passphrase = randomBytes(24).toString('hex');
  let client;
  t.after(async () => {
    try {
      if (client) {
        const traffic = await client.close();
        const visible = JSON.stringify(traffic) + await readFile(archive + '.events.jsonl', 'utf8');
        for (const value of [passphrase, ...Object.values(data.secrets).map(entry => entry.value), ...generatedCredentials()]) {
          if (value) assert.equal(visible.includes(value), false, 'credential absent from MCP traffic, stderr and use log');
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  await owner(archive, passphrase, ['init']);
  for (const [name, entry] of Object.entries(data.secrets)) {
    await owner(archive, passphrase, ['secret', 'set', name, '--secret-fd', '4'], entry.value);
  }
  const definition = join(directory, 'connection.json');
  await writeFile(definition, JSON.stringify(configured));
  await owner(archive, passphrase, ['connection', 'import', 'receiver', definition]);
  client = await openMcpSession(archive, passphrase, ['receiver']);
  return client;
}

async function startFixture(handler) {
  const server = createServer({
    key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)),
    cert: await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url)),
  }, handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    server,
    origin: `https://127.0.0.1:${server.address().port}`,
    async close() {
      server.close();
      await once(server, 'close');
    },
  };
}

async function readRequest(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

test('OAuth client credentials use the supplied HTTPS transport, deduplicate acquisition, expire naturally, and fail before resource dispatch', { timeout: 30_000 }, async t => {
  const clientSecret = randomBytes(24).toString('hex');
  const accessTokens = new Map();
  let tokenRequests = 0;
  let resourceRequests = 0;
  let receivedBasicPayload;
  const fixture = await startFixture(async (req, res) => {
    const body = await readRequest(req);
    if (req.url === '/token') {
      tokenRequests++;
      receivedBasicPayload = (req.headers.authorization ?? '').replace(/^Basic /, '');
      const encodedPair = Buffer.from(receivedBasicPayload, 'base64').toString('utf8');
      const colon = encodedPair.indexOf(':');
      // RFC 6749 section 2.3.1: each component is form-decoded after Basic decoding.
      const credentials = new URLSearchParams('id=' + encodedPair.slice(0, colon) + '&secret=' + encodedPair.slice(colon + 1));
      if (colon < 0 || credentials.get('id') !== 'functional-client' || credentials.get('secret') !== clientSecret) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_client' }));
        return;
      }
      const form = new URLSearchParams(body.toString('utf8'));
      assert.equal(form.get('grant_type'), 'client_credentials');
      assert.equal(form.get('scope'), 'read:identity');
      const token = randomBytes(24).toString('hex');
      accessTokens.set(token, Date.now() + 1000);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ access_token: token, token_type: 'Bearer', expires_in: 1 }));
      return;
    }
    if (req.url === '/resource') {
      resourceRequests++;
      const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
      const valid = (accessTokens.get(token) ?? 0) > Date.now();
      res.writeHead(valid ? 200 : 401, { 'content-type': 'application/json' });
      res.end(JSON.stringify(valid ? { account: 'functional-account' } : { error: 'unauthorized' }));
      return;
    }
    res.writeHead(404).end();
  });
  t.after(() => fixture.close());

  const data = vault({ client: clientSecret, wrong: 'wrong-' + clientSecret });
  const auth = {
    type: 'oauth2',
    tokenEndpoint: fixture.origin + '/token',
    grant: 'client_credentials',
    clientId: 'functional-client',
    clientSecret: 'client',
    clientAuth: 'basic',
    scope: 'read:identity',
  };
  const configured = connection(fixture.origin, auth);
  const session = new AuthSession(data);
  const signal = AbortSignal.timeout(limits.timeoutMs);

  const [first, second] = await Promise.all([
    session.prepare('oauth', configured, prepared(fixture.origin, '/resource'), sendHttps, signal, limits),
    session.prepare('oauth', configured, prepared(fixture.origin, '/resource'), sendHttps, signal, limits),
  ]);
  assert.equal(tokenRequests, 1, 'concurrent callers share one token acquisition');
  assert.equal((await dispatch(first)).status, 200);
  assert.equal((await dispatch(second)).status, 200);
  const basicPayload = receivedBasicPayload;
  assert.ok(first.patterns.includes(clientSecret), 'raw source secret is protected');
  assert.ok(first.patterns.includes(basicPayload), 'actual Basic payload is protected');
  const firstToken = first.request.headers.authorization.slice('Bearer '.length);
  assert.ok(first.patterns.includes(firstToken), 'minted access token is protected');

  await new Promise(resolve => setTimeout(resolve, 1100));
  const refreshed = await session.prepare(
    'oauth',
    configured,
    prepared(fixture.origin, '/resource'),
    sendHttps,
    AbortSignal.timeout(limits.timeoutMs),
    limits,
  );
  assert.equal(tokenRequests, 2, 'genuine expiry causes acquisition before dispatch');
  assert.equal((await dispatch(refreshed)).status, 200);

  const beforeFailure = resourceRequests;
  const invalid = connection(fixture.origin, { ...auth, clientSecret: 'wrong' });
  await assert.rejects(
    () => session.prepare(
      'invalid-oauth',
      invalid,
      prepared(fixture.origin, '/resource'),
      sendHttps,
      AbortSignal.timeout(limits.timeoutMs),
      limits,
    ),
    error => error?.code === 'UPSTREAM_ERROR' && error.message === 'The upstream request failed. Its outcome may be unknown.',
  );
  assert.equal(resourceRequests, beforeFailure, 'failed grant never dispatches the resource request');

  const jsonBinding = connection(fixture.origin, {
    type: 'bindings',
    bindings: [{ in: 'json', name: 'credential', secret: 'client' }],
  });
  await assert.rejects(
    () => session.prepare(
      'invalid-json',
      jsonBinding,
      {
        url: new URL('/resource', fixture.origin),
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: Buffer.from([0xff]),
      },
      sendHttps,
      AbortSignal.timeout(limits.timeoutMs),
      limits,
    ),
    error => error?.code === 'INVALID_INPUT',
  );
  assert.equal(resourceRequests, beforeFailure, 'invalid UTF-8 body binding never dispatches lossy bytes');

  const client = await clientFor(t, data, configured, () => [...accessTokens.keys(), receivedBasicPayload]);
  const account = await client.execute({ connection: 'receiver', path: '/resource' });
  assert.equal(account.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(account.structuredContent.body), { account: 'functional-account' });

  session.close();
  await assert.rejects(
    () => session.prepare('oauth', configured, prepared(fixture.origin, '/resource'), sendHttps, signal, limits),
    error => error?.code === 'SESSION_CLOSED',
  );
});

test('JWT bearer sends a verified short-lived RS256 assertion to the fixed token endpoint and keeps assertion and token private', { timeout: 30_000 }, async t => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const privatePem = await exportPKCS8(privateKey);
  const issuer = 'service-account@functional.invalid';
  const subject = 'delegated-user@functional.invalid';
  let fixture;
  let assertionSeen;
  let issuedToken;
  let jwtResourceRequests = 0;
  fixture = await startFixture(async (req, res) => {
    const body = await readRequest(req);
    if (req.url === '/jwt-token') {
      const form = new URLSearchParams(body.toString('utf8'));
      assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
      assert.deepEqual([...new Set(form.keys())].sort(), ['assertion', 'grant_type']);
      assertionSeen = form.get('assertion');
      let verified;
      try {
        verified = await jwtVerify(assertionSeen, publicKey, {
          issuer,
          audience: fixture.origin + '/jwt-token',
          algorithms: ['RS256'],
        });
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      assert.equal(verified.payload.sub, subject);
      assert.equal(verified.payload.scope, 'receiver.read');
      assert.ok(verified.payload.exp - verified.payload.iat <= 300);
      issuedToken = randomBytes(24).toString('hex');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ access_token: issuedToken, token_type: 'Bearer', expires_in: 60 }));
      return;
    }
    if (req.url === '/echo-assertion' || req.url === '/echo-token') {
      res.end(req.url === '/echo-assertion' ? assertionSeen : issuedToken);
      return;
    }
    if (req.url === '/jwt-resource') {
      jwtResourceRequests++;
      const ok = req.headers.authorization === `Bearer ${issuedToken}`;
      res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
      res.end(JSON.stringify(ok ? { identity: issuer } : { error: 'unauthorized' }));
      return;
    }
    res.writeHead(404).end();
  });
  t.after(() => fixture.close());

  const data = vault({ signingKey: privatePem });
  const configured = connection(fixture.origin, {
    type: 'jwt-bearer',
    tokenEndpoint: fixture.origin + '/jwt-token',
    issuer,
    subject,
    scope: 'receiver.read',
    privateKeySecret: 'signingKey',
    keyId: 'functional-key',
  });
  const session = new AuthSession(data);
  const result = await session.prepare(
    'jwt',
    configured,
    prepared(fixture.origin, '/jwt-resource'),
    sendHttps,
    AbortSignal.timeout(limits.timeoutMs),
    limits,
  );
  assert.equal((await dispatch(result)).status, 200);
  assert.ok(result.patterns.includes(privatePem));
  assert.ok(result.patterns.includes(assertionSeen));
  assert.ok(result.patterns.includes(issuedToken));
  assert.ok(result.patterns.includes(assertionSeen.split('.')[2]), 'actual assertion signature is protected');

  const wrongPair = await generateKeyPair('RS256', { extractable: true });
  data.secrets.wrongSigningKey = { value: await exportPKCS8(wrongPair.privateKey), enabled: true };
  const invalid = connection(fixture.origin, {
    ...configured.auth,
    privateKeySecret: 'wrongSigningKey',
  });
  const beforeInvalidAssertion = jwtResourceRequests;
  await assert.rejects(
    () => session.prepare(
      'invalid-jwt',
      invalid,
      prepared(fixture.origin, '/jwt-resource'),
      sendHttps,
      AbortSignal.timeout(limits.timeoutMs),
      limits,
    ),
    error => error?.code === 'UPSTREAM_ERROR',
  );
  assert.equal(jwtResourceRequests, beforeInvalidAssertion, 'invalid assertion stops before resource dispatch');
  session.close();
  const client = await clientFor(t, data, configured, () => [assertionSeen, issuedToken]);
  const identity = await client.execute({ connection: 'receiver', path: '/jwt-resource' });
  assert.equal(identity.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(identity.structuredContent.body), { identity: issuer });
  for (const path of ['/echo-assertion', '/echo-token']) {
    const reflected = await client.execute({ connection: 'receiver', path });
    assert.equal(reflected.structuredContent.error?.code, 'RESPONSE_BLOCKED');
  }
});

function awsEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, character =>
    '%' + character.charCodeAt(0).toString(16).toUpperCase());
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function hmac(key, value) {
  return createHmac('sha256', key).update(value).digest();
}

function canonicalQuery(url) {
  return [...url.searchParams]
    .map(([name, value]) => [awsEncode(name), awsEncode(value)])
    .sort(([leftName, leftValue], [rightName, rightValue]) => {
      if (leftName !== rightName) return leftName < rightName ? -1 : 1;
      if (leftValue === rightValue) return 0;
      return leftValue < rightValue ? -1 : 1;
    })
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

function verifyAwsRequest(req, body, expected) {
  const authorization = req.headers.authorization ?? '';
  const match = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(authorization);
  if (!match) return false;
  const [, accessKeyId, shortDate, region, service, signedHeaderText, actualSignature] = match;
  if (
    accessKeyId !== expected.accessKeyId ||
    region !== expected.region ||
    service !== expected.service ||
    req.headers['x-amz-security-token'] !== expected.sessionToken
  ) return false;

  const signedHeaders = signedHeaderText.split(';');
  const canonicalHeaders = signedHeaders.map(name => {
    const value = req.headers[name];
    if (typeof value !== 'string') throw new Error(`missing signed header ${name}`);
    return `${name}:${value.trim().replace(/\s+/g, ' ')}\n`;
  }).join('');
  const url = new URL(req.url, 'https://receiver.invalid');
  const canonicalRequest = [
    req.method,
    url.pathname,
    canonicalQuery(url),
    canonicalHeaders,
    signedHeaderText,
    sha256(body),
  ].join('\n');
  const longDate = req.headers['x-amz-date'];
  if (typeof longDate !== 'string' || !longDate.startsWith(shortDate)) return false;
  const scope = `${shortDate}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${longDate}\n${scope}\n${sha256(canonicalRequest)}`;
  const dateKey = hmac(`AWS4${expected.secretAccessKey}`, shortDate);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, service);
  const signingKey = hmac(serviceKey, 'aws4_request');
  const expectedSignature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  return expectedSignature === actualSignature;
}

test('AWS SigV4 signs the final S3 URL, duplicate query values, headers, and body; the receiver rejects modified bytes', { timeout: 30_000 }, async t => {
  const expected = {
    accessKeyId: 'AKID' + randomBytes(8).toString('hex').toUpperCase(),
    secretAccessKey: randomBytes(24).toString('base64'),
    sessionToken: randomBytes(24).toString('base64url'),
    region: 'us-east-1',
    service: 's3',
  };
  let acceptedPath;
  const signatures = new Set();
  const fixture = await startFixture(async (req, res) => {
    const body = await readRequest(req);
    const valid = verifyAwsRequest(req, body, expected);
    if (valid) {
      acceptedPath = req.url;
      signatures.add(req.headers.authorization.match(/Signature=([0-9a-f]+)/)[1]);
    }
    if (valid && req.url === '/echo-signature') {
      res.end(req.headers.authorization.match(/Signature=([0-9a-f]+)/)[1]);
      return;
    }
    res.writeHead(valid ? 200 : 403, { 'content-type': 'application/json' });
    res.end(JSON.stringify(valid ? { bucket: 'functional-bucket' } : { error: 'signature mismatch' }));
  });
  t.after(() => fixture.close());

  const data = vault({
    access: expected.accessKeyId,
    secret: expected.secretAccessKey,
    session: expected.sessionToken,
  });
  const configured = connection(fixture.origin, {
    type: 'aws-sigv4',
    accessKeyIdSecret: 'access',
    secretAccessKeySecret: 'secret',
    sessionTokenSecret: 'session',
    region: expected.region,
    service: expected.service,
  });
  const body = Buffer.from(JSON.stringify({ operation: 'put', value: 'functional' }));
  const session = new AuthSession(data);
  const result = await session.prepare(
    'aws',
    configured,
    prepared(fixture.origin, '/bucket/folder%2Fobject%20name?z=2&a=b&a=a', 'PUT', body),
    sendHttps,
    AbortSignal.timeout(limits.timeoutMs),
    limits,
  );
  assert.equal((await dispatch(result)).status, 200);
  assert.equal(acceptedPath, '/bucket/folder%2Fobject%20name?z=2&a=b&a=a', 'wire URL keeps encoded S3 key and duplicate query order');
  assert.ok(result.patterns.includes(expected.secretAccessKey));
  assert.ok(result.patterns.includes(expected.sessionToken));
  assert.ok(result.patterns.includes(result.request.headers.authorization));
  assert.ok(result.patterns.includes(result.request.headers.authorization.match(/Signature=([0-9a-f]+)/)[1]));

  const modifiedBody = Buffer.from(body);
  modifiedBody[modifiedBody.length - 2] ^= 1;
  const modified = {
    ...result,
    request: { ...result.request, body: modifiedBody },
  };
  assert.equal((await dispatch(modified)).status, 403, 'independent receiver rejects modified signed body');
  session.close();
  const client = await clientFor(t, data, configured, () => [...signatures]);
  const accepted = await client.execute({ connection: 'receiver', path: '/bucket/folder%2Fobject%20name?z=2&a=b&a=a', method: 'PUT', body: body.toString('utf8') });
  assert.equal(accepted.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(accepted.structuredContent.body), { bucket: 'functional-bucket' });
  const reflected = await client.execute({ connection: 'receiver', path: '/echo-signature' });
  assert.equal(reflected.structuredContent.error?.code, 'RESPONSE_BLOCKED');
});
