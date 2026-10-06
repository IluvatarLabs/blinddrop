import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

import { collect, owner, spawnOwner } from './support/owner-session.mjs';

const keyPath = new URL('./fixtures/localhost-key.pem', import.meta.url);
const certPath = new URL('./fixtures/localhost-cert.pem', import.meta.url);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function waitFor(predicate, message, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(message);
}

function firstLine(stream, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    const timeout = setTimeout(() => finish(new Error('timed out waiting for readiness JSON')), timeoutMs);
    const onData = chunk => {
      buffered += chunk.toString('utf8');
      const newline = buffered.indexOf('\n');
      if (newline !== -1) finish(undefined, buffered.slice(0, newline));
    };
    const onEnd = () => finish(new Error('session ended before readiness JSON'));
    const onError = error => finish(error);
    const finish = (error, line) => {
      clearTimeout(timeout);
      stream.off('data', onData);
      stream.off('end', onEnd);
      stream.off('error', onError);
      if (error) reject(error); else resolve(line);
    };
    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onError);
  });
}

async function startHttpSession(vault, passphrase, ttl = 30) {
  const run = spawnOwner(vault, passphrase, [
    'serve', '--http', '--allow', 'receiver', '--port', '0', '--ttl', String(ttl)
  ]);
  run.child.stdin.end();
  const line = await firstLine(run.child.stdout);
  const ready = JSON.parse(line);
  assert.equal(typeof ready.mcpUrl, 'string');
  assert.equal(typeof ready.connections?.receiver, 'string');
  assert.match(ready.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(typeof ready.expiresAt, 'number');
  return { ...run, ready };
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function stopSession(run) {
  if (run.child.exitCode === null && run.child.signalCode === null) run.child.kill('SIGTERM');
  const result = await run.exit;
  const stderr = await run.stderr;
  assert.equal(stderr.includes('disposable-'), false);
  return result;
}

function apiUrl(baseUrl, suffix) {
  return new URL(suffix, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`);
}

function rawHttp(url, lines) {
  return new Promise((resolve, reject) => {
    const socket = connect(Number(url.port), url.hostname);
    const chunks = [];
    socket.once('error', reject);
    socket.on('data', chunk => chunks.push(Buffer.from(chunk)));
    socket.once('end', () => resolve(Buffer.concat(chunks).toString('latin1')));
    socket.once('connect', () => {
      socket.end(`${lines.join('\r\n')}\r\n\r\n`);
    });
  });
}

function stalledMcpRequest(url, token) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = httpRequest(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'content-length': '128',
      },
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.once('end', () => {
        settled = true;
        resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    request.once('error', error => {
      if (!settled) reject(error);
    });
    request.write('{"jsonrpc":"2.0"');
  });
}

async function readUntilEndOrFailure(response) {
  const chunks = [];
  const reader = response.body.getReader();
  let error;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      chunks.push(Buffer.from(next.value));
    }
  } catch (caught) {
    error = caught;
  }
  return { body: Buffer.concat(chunks), error };
}

function sseOpening(text) {
  return [
    'event: message_start',
    'data: {"type":"message_start","message":{"id":"msg_fixture","type":"message","role":"assistant","model":"claude-fixture","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}',
    '',
    'event: content_block_start',
    'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
    '',
    'event: content_block_delta',
    `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } })}`,
    '',
    `: ${'safe-padding-'.repeat(16)}`,
    '',
  ].join('\n');
}

function sseClosing() {
  return [
    'event: content_block_stop',
    'data: {"type":"content_block_stop","index":0}',
    '',
    'event: message_delta',
    'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}',
    '',
    'event: message_stop',
    'data: {"type":"message_stop"}',
    '',
    '',
  ].join('\n');
}

async function configureVault(vault, passphrase, providerKey, origin) {
  await owner(vault, passphrase, ['init']);
  await owner(vault, passphrase, ['secret', 'set', 'provider-key', '--secret-fd', '4'], providerKey);
  await owner(vault, passphrase, [
    'connection', 'set', 'receiver', '--origin', origin,
    '--auth', 'header', '--field', 'x-api-key', '--secret', 'provider-key', '--allow-private'
  ]);
}

test('serve --http supports the official MCP client and a bounded ordinary HTTP base URL', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-sdk-http-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const vault = join(dir, 'vault.enc');
  const passphrase = 'disposable-http-passphrase';
  const providerKey = randomBytes(32).toString('hex');
  const binary = randomBytes(256 * 1024);
  const operations = [];
  const capabilityTokens = new Set();
  const slowClosed = deferred();
  const expiryClosed = deferred();

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, async (req, res) => {
    const bodyChunks = [];
    for await (const chunk of req) bodyChunks.push(Buffer.from(chunk));
    const body = Buffer.concat(bodyChunks);
    const serialized = `${req.url}\n${JSON.stringify(req.headers)}\n${body.toString('utf8')}`;
    const capabilitySeen = [...capabilityTokens].some(token => serialized.includes(token));
    const authenticated = req.headers['x-api-key'] === providerKey && req.headers.authorization === undefined;
    operations.push({ url: req.url, method: req.method, authenticated, capabilitySeen });
    if (!authenticated) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"error":"unauthorized"}');
      return;
    }
    if (req.url === '/identity') {
      res.setHeader('content-type', 'application/json');
      res.end('{"account":"functional-owner","id":731}');
    } else if (req.url === '/reflect') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ reflected: providerKey }));
    } else if (req.url === '/binary?tag=first&tag=second') {
      res.setHeader('content-type', 'application/octet-stream');
      res.end(binary);
    } else if (req.url === '/reflect-split') {
      res.setHeader('content-type', 'application/octet-stream');
      res.flushHeaders();
      res.write(Buffer.from(`safe-prefix:${'x'.repeat(128)}`));
      res.write(Buffer.from(providerKey.slice(0, 17)));
      setImmediate(() => res.end(Buffer.from(providerKey.slice(17))));
    } else if (req.url === '/slow') {
      res.setHeader('content-type', 'application/octet-stream');
      res.flushHeaders();
      res.write(Buffer.alloc(1_024, 0x61));
      res.once('close', () => slowClosed.resolve());
    } else if (req.url === '/slow-expiry') {
      res.setHeader('content-type', 'application/octet-stream');
      res.flushHeaders();
      res.write(Buffer.alloc(1_024, 0x62));
      res.once('close', () => expiryClosed.resolve());
    } else if (req.url === '/truncate') {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': '2048' });
      res.write(Buffer.alloc(1_024, 0x63));
      setImmediate(() => res.destroy());
    } else {
      res.writeHead(404).end();
    }
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });

  await configureVault(
    vault,
    passphrase,
    providerKey,
    `https://127.0.0.1:${receiver.address().port}`,
  );

  const serving = await startHttpSession(vault, passphrase);
  capabilityTokens.add(serving.ready.token);
  t.after(() => stopSession(serving));
  const base = serving.ready.connections.receiver;
  const gateway = new URL(serving.ready.mcpUrl);

  const client = new Client({ name: 'blinddrop-http-functional-consumer', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(serving.ready.mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${serving.ready.token}` } },
  });
  await client.connect(transport);
  t.after(() => client.close());
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), ['execute_http', 'list_connections']);
  const identity = await client.callTool({
    name: 'execute_http',
    arguments: { connection: 'receiver', path: '/identity' },
  });
  assert.equal(identity.isError, undefined);
  assert.equal(identity.structuredContent.status, 200);
  assert.match(identity.structuredContent.body, /"id":731/);
  const reflected = await client.callTool({
    name: 'execute_http',
    arguments: { connection: 'receiver', path: '/reflect' },
  });
  assert.equal(reflected.isError, true);
  assert.equal(reflected.structuredContent.error.code, 'RESPONSE_BLOCKED');

  const dispatchesBeforeDenials = operations.length;
  const deniedRequests = [
    fetch(apiUrl(base, 'identity')),
    fetch(apiUrl(base, 'identity'), { headers: { Authorization: 'Bearer wrong-token' } }),
    fetch(apiUrl(base, 'identity'), {
      headers: {
        Authorization: `Bearer ${serving.ready.token}`,
        'x-api-key': serving.ready.token,
      },
    }),
    fetch(apiUrl(base, 'identity'), {
      headers: { Authorization: `Bearer ${serving.ready.token}`, Origin: 'https://example.invalid' },
    }),
    fetch(new URL('/api/not-granted/identity', gateway), {
      headers: { Authorization: `Bearer ${serving.ready.token}` },
    }),
    fetch(apiUrl(base, 'identity'), {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${serving.ready.token}`,
        'content-type': 'text/plain',
      },
      body: serving.ready.token,
    }),
  ];
  for (const response of await Promise.all(deniedRequests)) {
    assert.ok(response.status >= 400);
    await response.arrayBuffer();
  }

  const duplicateResponse = await rawHttp(gateway, [
    'GET /api/receiver/identity HTTP/1.1',
    `Host: ${gateway.host}`,
    `Authorization: Bearer ${serving.ready.token}`,
    `Authorization: Bearer ${serving.ready.token}`,
    'Connection: close',
  ]);
  assert.match(duplicateResponse, /^HTTP\/1\.1 4\d\d/);
  const hostResponse = await rawHttp(gateway, [
    'GET /api/receiver/identity HTTP/1.1',
    'Host: example.invalid',
    `Authorization: Bearer ${serving.ready.token}`,
    'Connection: close',
  ]);
  assert.match(hostResponse, /^HTTP\/1\.1 4\d\d/);
  assert.equal(operations.length, dispatchesBeforeDenials);

  const oversizedResponse = await fetch(apiUrl(base, 'identity'), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${serving.ready.token}`,
      'content-type': 'application/octet-stream',
    },
    body: Buffer.alloc(16 * 1024 * 1024 + 1, 0x64),
  });
  assert.equal(oversizedResponse.status, 413);
  assert.deepEqual(await oversizedResponse.json(), {
    error: {
      code: 'REQUEST_TOO_LARGE',
      message: 'The request exceeds the size limit.',
    },
  });
  assert.equal(operations.length, dispatchesBeforeDenials);

  const binaryResponse = await fetch(apiUrl(base, 'binary?tag=first&tag=second'), {
    headers: { 'x-api-key': serving.ready.token },
  });
  assert.equal(binaryResponse.status, 200);
  assert.deepEqual(Buffer.from(await binaryResponse.arrayBuffer()), binary);
  const binaryOperation = operations.find(operation => operation.url === '/binary?tag=first&tag=second');
  assert.deepEqual(binaryOperation, {
    url: '/binary?tag=first&tag=second', method: 'GET', authenticated: true, capabilitySeen: false,
  });

  const splitResponse = await fetch(apiUrl(base, 'reflect-split'), {
    headers: { Authorization: `Bearer ${serving.ready.token}` },
  });
  const split = await readUntilEndOrFailure(splitResponse);
  assert.ok(split.error, 'a reflected provider credential must terminate the started response');
  assert.equal(split.body.includes(providerKey), false);

  const abortController = new AbortController();
  const slowResponse = await fetch(apiUrl(base, 'slow'), {
    headers: { Authorization: `Bearer ${serving.ready.token}` },
    signal: abortController.signal,
  });
  const slowReader = slowResponse.body.getReader();
  assert.equal((await slowReader.read()).done, false);
  abortController.abort();
  await assert.rejects(() => slowReader.read());
  await Promise.race([
    slowClosed.promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('upstream remained open after client cancellation')), 5_000)),
  ]);

  const truncatedResponse = await fetch(apiUrl(base, 'truncate'), {
    headers: { Authorization: `Bearer ${serving.ready.token}` },
  });
  const truncated = await readUntilEndOrFailure(truncatedResponse);
  assert.ok(truncated.error, 'a truncated receiver response must not complete normally');

  const expiring = await startHttpSession(vault, passphrase, 1);
  capabilityTokens.add(expiring.ready.token);
  const expiryDispatches = operations.length;
  const expiryResponse = await fetch(apiUrl(expiring.ready.connections.receiver, 'slow-expiry'), {
    headers: { Authorization: `Bearer ${expiring.ready.token}` },
  });
  const expiryReader = expiryResponse.body.getReader();
  assert.equal((await expiryReader.read()).done, false);
  const expiryExit = await expiring.exit;
  assert.equal(expiryExit.code, 0);
  await assert.rejects(() => expiryReader.read());
  await Promise.race([
    expiryClosed.promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('upstream remained open after expiry')), 5_000)),
  ]);
  assert.equal(await expiring.stderr, '');
  await assert.rejects(() => fetch(apiUrl(expiring.ready.connections.receiver, 'identity')));
  assert.equal(operations.length, expiryDispatches + 1);

  assert.ok(operations.length >= 7);
  assert.ok(operations.every(operation => operation.authenticated));
  assert.ok(operations.every(operation => !operation.capabilitySeen));
  assert.equal(JSON.stringify(operations).includes(providerKey), false);
  assert.equal(JSON.stringify(operations).includes(serving.ready.token), false);
  t.diagnostic('Official MCP HTTP, capability rejection, exact binary/query forwarding, streaming reflection, cancellation, truncation, and real session expiry all used the installed CLI path.');
});

test('run launches the official Anthropic SDK, streams before completion, preserves exit, and cleans up', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-sdk-run-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const home = join(dir, 'home');
  const settingsPath = join(home, '.config', 'blinddrop', 'settings.json');
  const vault = join(dir, 'vault.enc');
  const passphrase = 'disposable-run-passphrase';
  const providerKey = randomBytes(32).toString('hex');
  const completeSuccessfulStream = deferred();
  const cancellationClosed = deferred();
  const operations = [];

  const spawnRun = args => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    try {
      return spawnOwner(vault, passphrase, args);
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  };

  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const authenticated = req.headers['x-api-key'] === providerKey && req.headers.authorization === undefined;
    operations.push({
      url: req.url,
      authenticated,
      model: body.model,
      requestShape: req.method === 'POST' && Array.isArray(body.messages) &&
        body.max_tokens === (body.model === 'claude-fixture' ? 256 : 8),
    });
    if (!authenticated) {
      res.writeHead(401).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache' });
    res.write(sseOpening(body.model === 'claude-cancel' ? 'cancel-me' : 'hello'));
    if (body.model === 'claude-cancel') {
      res.once('close', () => cancellationClosed.resolve());
      return;
    }
    await completeSuccessfulStream.promise;
    res.end(sseClosing());
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });

  await configureVault(
    vault,
    passphrase,
    providerKey,
    `https://127.0.0.1:${receiver.address().port}`,
  );

  const run = spawnRun([
    'run', 'receiver', '--base-url-env', 'ANTHROPIC_BASE_URL',
    '--api-key-env', 'ANTHROPIC_API_KEY', '--ttl', '30', '--',
    process.execPath, 'examples/anthropic.mjs', 'claude-fixture', 'Say hello.',
  ]);
  run.child.stdin.end();
  const runOutput = [];
  run.child.stdout.on('data', chunk => runOutput.push(Buffer.from(chunk)));
  const outputText = () => Buffer.concat(runOutput).toString('utf8');
  await waitFor(() => outputText() === 'hello', 'documented SDK example did not receive the first streamed text event');
  assert.equal(outputText().includes('\n'), false, 'documented SDK example completed before the receiver completed');
  assert.equal(operations.length, 1);
  assert.deepEqual(operations[0], {
    url: '/v1/messages', authenticated: true, model: 'claude-fixture', requestShape: true,
  });
  const savedPort = JSON.parse(await readFile(settingsPath, 'utf8')).sessionPort;
  assert.ok(savedPort >= 49_152 && savedPort <= 65_535);
  completeSuccessfulStream.resolve();
  const successfulExit = await run.exit;
  const successfulStderr = await run.stderr;
  const successfulOutput = outputText();
  assert.deepEqual(successfulExit, { code: 0, signal: null });
  assert.equal(successfulStderr, '');
  assert.equal(successfulOutput, 'hello\n');
  assert.equal(successfulOutput.includes(providerKey), false);
  assert.equal(successfulOutput.includes(passphrase), false);

  const observationProgram = String.raw`
    import { createHash } from 'node:crypto';
    const hashes = [...new Set(Object.values(process.env).filter(value => typeof value === 'string')
      .map(value => createHash('sha256').update(value).digest('hex')))];
    process.stdout.write('CHILD_OBSERVATION:' + JSON.stringify({
      tokenAliasMatches: process.env.ANTHROPIC_API_KEY === process.env.BLINDDROP_TOKEN,
      prototypeNameMapped: Object.hasOwn(process.env, '__proto__') &&
        process.env.__proto__ === process.env.BLINDDROP_BASE_URL,
      environmentValueHashes: hashes
    }) + '\n');
    process.exitCode = 7;
  `;
  const exitRun = spawnRun([
    'run', 'receiver', '--base-url-env', '__proto__',
    '--api-key-env', 'ANTHROPIC_API_KEY', '--ttl', '30', '--',
    process.execPath, '--input-type=module', '--eval', observationProgram,
  ]);
  exitRun.child.stdin.end();
  const [exitResult, exitStdout, exitStderr] = await Promise.all([
    exitRun.exit, collect(exitRun.child.stdout), exitRun.stderr,
  ]);
  assert.deepEqual(exitResult, { code: 7, signal: null });
  assert.equal(exitStderr, '');
  const observation = JSON.parse(exitStdout.match(/^CHILD_OBSERVATION:(.+)$/m)?.[1]);
  assert.equal(observation.tokenAliasMatches, true);
  assert.equal(observation.prototypeNameMapped, true);
  assert.equal(observation.environmentValueHashes.includes(sha256(providerKey)), false);
  assert.equal(observation.environmentValueHashes.includes(sha256(passphrase)), false);

  const cancelProgram = String.raw`
    import Anthropic from '@anthropic-ai/sdk';
    const client = new Anthropic({ maxRetries: 0 });
    const stream = client.messages.stream({
      model: 'claude-cancel', max_tokens: 8,
      messages: [{ role: 'user', content: 'Wait.' }]
    });
    stream.on('text', text => process.stdout.write('CANCEL_FIRST:' + text + '\n'));
    process.stdout.write('CANCEL_PID:' + process.pid + '\n');
    process.stdout.write('CANCEL_BASE:' + process.env.ANTHROPIC_BASE_URL + '\n');
    await stream.finalText();
  `;
  const cancelled = spawnRun([
    'run', 'receiver', '--base-url-env', 'ANTHROPIC_BASE_URL',
    '--api-key-env', 'ANTHROPIC_API_KEY', '--ttl', '30', '--',
    process.execPath, '--input-type=module', '--eval', cancelProgram,
  ]);
  cancelled.child.stdin.end();
  const cancelledOutput = [];
  cancelled.child.stdout.on('data', chunk => cancelledOutput.push(Buffer.from(chunk)));
  const cancelledText = () => Buffer.concat(cancelledOutput).toString('utf8');
  await waitFor(() => cancelledText().includes('CANCEL_FIRST:cancel-me'), 'cancellable SDK stream did not start');
  const childPid = Number(cancelledText().match(/^CANCEL_PID:(\d+)$/m)?.[1]);
  const cancelledBase = cancelledText().match(/^CANCEL_BASE:(.+)$/m)?.[1];
  assert.ok(Number.isSafeInteger(childPid));
  assert.ok(cancelledBase);
  cancelled.child.kill('SIGTERM');
  await cancelled.exit;
  const cancelledStderr = await cancelled.stderr;
  assert.equal(cancelledStderr.includes(providerKey), false);
  assert.equal(cancelledStderr.includes(passphrase), false);
  await Promise.race([
    cancellationClosed.promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('upstream remained open after run cancellation')), 5_000)),
  ]);
  await waitFor(() => {
    try { process.kill(childPid, 0); return false; } catch (error) { return error.code === 'ESRCH'; }
  }, 'run left its SDK child process alive');
  await assert.rejects(() => fetch(apiUrl(cancelledBase, 'identity')));
  assert.equal(cancelledText().includes(providerKey), false);
  assert.equal(cancelledText().includes(passphrase), false);
  assert.equal(JSON.stringify(operations).includes(providerKey), false);
  assert.deepEqual(operations.map(operation => operation.model), ['claude-fixture', 'claude-cancel']);
  t.diagnostic('The installed CLI ran the unmodified official Anthropic SDK with ordinary baseURL/API-key environment options, streamed before completion, preserved child exit status, and cleaned up on exit and signal.');
});

test('a stalled MCP upload returns the fixed 30-second timeout before dispatch', { timeout: 45_000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'blinddrop-http-timeout-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const vault = join(dir, 'vault.enc');
  const passphrase = 'disposable-timeout-passphrase';
  const providerKey = randomBytes(32).toString('hex');
  let receiverDispatches = 0;
  const receiver = createHttpsServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, (_request, response) => {
    receiverDispatches++;
    response.end('unexpected');
  });
  receiver.listen(0, '127.0.0.1');
  await once(receiver, 'listening');
  t.after(() => {
    receiver.close();
    receiver.closeAllConnections();
  });
  await configureVault(
    vault,
    passphrase,
    providerKey,
    `https://127.0.0.1:${receiver.address().port}`,
  );
  const serving = await startHttpSession(vault, passphrase, 40);
  t.after(() => stopSession(serving));

  const started = Date.now();
  const response = await stalledMcpRequest(new URL(serving.ready.mcpUrl), serving.ready.token);
  const elapsed = Date.now() - started;
  assert.equal(response.status, 504);
  assert.deepEqual(JSON.parse(response.body), {
    error: {
      code: 'TIMEOUT',
      message: 'The request timed out. Its upstream outcome may be unknown.',
    },
  });
  assert.ok(elapsed >= 29_000, `timeout fired too early after ${elapsed} ms`);
  assert.ok(elapsed < 35_000, `timeout fired too late after ${elapsed} ms`);
  assert.equal(receiverDispatches, 0);
  t.diagnostic(`The actual MCP request-body deadline returned static 504 JSON after ${elapsed} ms without receiver dispatch.`);
});
