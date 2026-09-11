// Actual Claude Code host check using only generated local fixture credentials.
// Run from a terminal; enter the disposable fixture passphrase when BlindDrop prompts.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { owner, cli, ca, collect } from '../test/support/owner-session.mjs';

const dir = await mkdtemp(join(tmpdir(), 'blinddrop-agent-host-'));
const vault = join(dir, 'vault.enc');
const passphrase = 'disposable-host-check';
const secret = randomBytes(32).toString('hex');
const operations = [];
const fixture = createServer({
  key: await readFile(new URL('../test/fixtures/localhost-key.pem', import.meta.url)),
  cert: await readFile(ca)
}, (req, res) => {
  const authenticated = req.headers.authorization === 'Bearer ' + secret;
  operations.push({ path: req.url, authenticated });
  res.setHeader('Content-Type', 'application/json');
  if (!authenticated) { res.writeHead(401); res.end('{"error":"unauthorized"}'); return; }
  res.end(req.url === '/reflect' ? JSON.stringify({ echo: secret }) : JSON.stringify({ account: 'functional-agent-owner', id: 731 }));
});
let child;
try {
  fixture.listen(0, '127.0.0.1'); await once(fixture, 'listening');
  await owner(vault, passphrase, ['init']);
  await owner(vault, passphrase, ['secret', 'set', 'token', '--secret-fd', '4'], secret);
  await owner(vault, passphrase, ['connection', 'set', 'fixture', '--origin', `https://127.0.0.1:${fixture.address().port}`,
    '--auth', 'bearer', '--secret', 'token', '--allow-private']);
  const config = join(dir, 'mcp.json');
  await writeFile(config, JSON.stringify({ mcpServers: { blinddrop: { command: process.execPath,
    args: [cli, '--vault', vault, 'serve', '--allow', 'fixture', '--ttl', '120'], env: { NODE_EXTRA_CA_CERTS: ca } } } }));
  child = spawn('claude', ['-p', '--setting-sources', '', '--strict-mcp-config', '--mcp-config', config,
    '--tools', '', '--allowedTools', 'mcp__blinddrop__list_connections', 'mcp__blinddrop__execute_http',
    '--no-session-persistence', '--output-format', 'stream-json', '--verbose',
    'Use the blinddrop MCP tools. List connections. Call execute_http for connection fixture path /identity. Then call it for /reflect. Report the account id and whether the reflection was blocked. Do not request or guess credentials.'],
    { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = collect(child.stdout); const stderr = collect(child.stderr);
  const exit = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code, signal) => resolve({ code, signal })); });
  const out = await stdout, err = await stderr;
  assert.equal(exit.code, 0, err);
  assert.equal(out.includes(secret) || err.includes(secret), false);
  assert.equal(out.includes(passphrase) || err.includes(passphrase), false);
  const events = out.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
  if (!operations.some(entry => entry.path === '/identity' && entry.authenticated)) {
    const diagnostic = JSON.stringify({
      host: 'Claude Code',
      mcpServers: events.find(event => event.type === 'system' && event.subtype === 'init')?.mcp_servers,
      result: events.findLast(event => event.type === 'result')?.result,
      operations
    }).replaceAll(secret, '[fixture credential]').replaceAll(passphrase, '[fixture unlock]');
    process.stderr.write(diagnostic + '\n');
  }
  assert.ok(operations.some(entry => entry.path === '/identity' && entry.authenticated));
  assert.ok(operations.some(entry => entry.path === '/reflect' && entry.authenticated));
  assert.ok(out.includes('RESPONSE_BLOCKED'));
  assert.ok(out.includes('731'));
  const calls = events.flatMap(event => event.message?.content ?? []).filter(block => block.type === 'tool_use').map(block => ({ name: block.name, input: block.input }));
  assert.ok(calls.some(call => call.name === 'mcp__blinddrop__execute_http'));
  console.log(JSON.stringify({ date: new Date().toISOString(), host: 'Claude Code',
    operations, calls, account: { name: 'functional-agent-owner', id: 731 }, reflection: 'RESPONSE_BLOCKED',
    credentialScan: 'model/tool transcript and stderr passed', unlock: 'normal owner controlling-terminal prompt',
    cleanup: 'temporary fixture, vault, config and logs removed' }, null, 2));
} finally {
  if (child?.exitCode === null) child.kill('SIGTERM');
  fixture.close(); fixture.closeAllConnections();
  await rm(dir, { recursive: true, force: true });
}
