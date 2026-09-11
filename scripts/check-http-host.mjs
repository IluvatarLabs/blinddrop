// Actual Claude Code Streamable HTTP check using only generated local fixture credentials.
// It writes a temporary HTTP MCP configuration containing a disposable session capability.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ca, collect, owner, spawnOwner } from '../test/support/owner-session.mjs';

function firstLine(stream, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    const timeout = setTimeout(() => finish(new Error('timed out waiting for readiness JSON')), timeoutMs);
    const onData = chunk => {
      buffered += chunk.toString('utf8');
      const newline = buffered.indexOf('\n');
      if (newline !== -1) finish(undefined, buffered.slice(0, newline));
    };
    const onEnd = () => finish(new Error('BlindDrop ended before readiness JSON'));
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

const dir = await mkdtemp(join(tmpdir(), 'blinddrop-http-host-'));
const vault = join(dir, 'vault.enc');
const passphrase = 'disposable-http-host-passphrase';
const providerKey = randomBytes(32).toString('hex');
const operations = [];
const fixture = createServer({
  key: await readFile(new URL('../test/fixtures/localhost-key.pem', import.meta.url)),
  cert: await readFile(ca),
}, (req, res) => {
  const authenticated = req.headers.authorization === `Bearer ${providerKey}`;
  operations.push({ path: req.url, authenticated });
  res.setHeader('content-type', 'application/json');
  if (!authenticated) {
    res.writeHead(401);
    res.end('{"error":"unauthorized"}');
    return;
  }
  res.end(req.url === '/reflect'
    ? JSON.stringify({ echo: providerKey })
    : JSON.stringify({ account: 'functional-http-owner', id: 731 }));
});
let host;
let serving;
try {
  fixture.listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  await owner(vault, passphrase, ['init']);
  await owner(vault, passphrase, ['secret', 'set', 'token', '--secret-fd', '4'], providerKey);
  await owner(vault, passphrase, [
    'connection', 'set', 'fixture',
    '--origin', `https://127.0.0.1:${fixture.address().port}`,
    '--auth', 'bearer', '--secret', 'token', '--allow-private',
  ]);

  serving = spawnOwner(vault, passphrase, [
    'serve', '--http', '--allow', 'fixture', '--port', '0', '--ttl', '120',
  ]);
  serving.child.stdin.end();
  const ready = JSON.parse(await firstLine(serving.child.stdout));
  assert.equal(typeof ready.mcpUrl, 'string');
  assert.match(ready.token, /^[A-Za-z0-9_-]{43}$/);

  const config = join(dir, 'mcp.json');
  await writeFile(config, JSON.stringify({
    mcpServers: {
      blinddrop: {
        type: 'http',
        url: ready.mcpUrl,
        headers: { Authorization: `Bearer ${ready.token}` },
      },
    },
  }), { mode: 0o600 });

  host = spawn('claude', [
    '-p', '--setting-sources', '', '--strict-mcp-config', '--mcp-config', config,
    '--tools', '',
    '--allowedTools', 'mcp__blinddrop__list_connections', 'mcp__blinddrop__execute_http',
    '--no-session-persistence', '--output-format', 'stream-json', '--verbose',
    'Use the blinddrop MCP tools. List connections. Call execute_http for connection fixture path /identity. Then call it for /reflect. Report the account id and whether the reflection was blocked. Do not request or guess credentials.',
  ], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = collect(host.stdout);
  const stderr = collect(host.stderr);
  const exit = await new Promise((resolve, reject) => {
    host.once('error', reject);
    host.once('exit', (code, signal) => resolve({ code, signal }));
  });
  const [out, err] = await Promise.all([stdout, stderr]);
  assert.equal(exit.code, 0, err);
  assert.equal(out.includes(providerKey) || err.includes(providerKey), false);
  assert.equal(out.includes(passphrase) || err.includes(passphrase), false);
  assert.equal(out.includes(ready.token) || err.includes(ready.token), false);
  const events = out.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
  if (!operations.some(operation => operation.path === '/identity' && operation.authenticated)) {
    const diagnostic = JSON.stringify({
      host: 'Claude Code',
      transport: 'Streamable HTTP',
      mcpServers: events.find(event => event.type === 'system' && event.subtype === 'init')?.mcp_servers,
      result: events.findLast(event => event.type === 'result')?.result,
      operations,
    }).replaceAll(providerKey, '[fixture credential]')
      .replaceAll(passphrase, '[fixture unlock]')
      .replaceAll(ready.token, '[session capability]');
    process.stderr.write(`${diagnostic}\n`);
  }
  assert.ok(operations.some(operation => operation.path === '/identity' && operation.authenticated));
  assert.ok(operations.some(operation => operation.path === '/reflect' && operation.authenticated));
  assert.ok(out.includes('RESPONSE_BLOCKED'));
  assert.ok(out.includes('731'));
  const calls = events.flatMap(event => event.message?.content ?? [])
    .filter(block => block.type === 'tool_use')
    .map(block => ({ name: block.name, input: block.input }));
  assert.ok(calls.some(call => call.name === 'mcp__blinddrop__list_connections'));
  assert.ok(calls.some(call => call.name === 'mcp__blinddrop__execute_http'));

  serving.child.kill('SIGTERM');
  const servingExit = await serving.exit;
  const servingStderr = await serving.stderr;
  assert.equal(servingExit.code, 0);
  assert.equal(servingStderr, '');
  serving = undefined;

  console.log(JSON.stringify({
    date: new Date().toISOString(),
    host: 'Claude Code',
    transport: 'Streamable HTTP',
    configuration: 'temporary standard HTTP MCP URL plus disposable Bearer capability',
    operations,
    tools: [...new Set(calls.map(call => call.name))].sort(),
    account: { name: 'functional-http-owner', id: 731 },
    reflection: 'RESPONSE_BLOCKED',
    credentialScan: 'model/tool transcript and stderr passed',
    scope: 'actual CLI host; no graphical client claim',
    cleanup: 'helper stopped; temporary fixture, vault, MCP config and logs removed',
  }, null, 2));
} finally {
  if (host?.exitCode === null) host.kill('SIGTERM');
  if (serving?.child.exitCode === null) serving.child.kill('SIGTERM');
  if (serving) await serving.exit.catch(() => undefined);
  fixture.close();
  fixture.closeAllConnections();
  await rm(dir, { recursive: true, force: true });
}
