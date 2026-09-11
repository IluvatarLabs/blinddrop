import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/client';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../../', import.meta.url));
// Lets the same functional workflows verify an installed release artifact.
export const cli = process.env.BLINDDROP_TEST_CLI ?? fileURLToPath(new URL('../../dist/cli.js', import.meta.url));
export const ca = fileURLToPath(new URL('../fixtures/localhost-cert.pem', import.meta.url));

export function collect(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', data => chunks.push(Buffer.from(data)));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    stream.on('error', reject);
  });
}

export function spawnOwner(vault, passphrase, args, secret) {
  const child = spawn(process.execPath, [cli, '--vault', vault, '--password-fd', '3', ...args], {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe', 'pipe', ...(secret === undefined ? [] : ['pipe'])],
    env: { ...process.env, NODE_EXTRA_CA_CERTS: ca }
  });
  const inputErrors = [];
  for (const input of child.stdio.slice(3)) {
    input.on('error', error => inputErrors.push(error));
  }
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      // Early command rejection may close an unread owner pipe on Linux.
      // Preserve its exit/stderr assertions; successful commands must consume input.
      const unexpected = inputErrors.find(error => code === 0 || !['EPIPE', 'ECONNRESET'].includes(error.code));
      if (unexpected) reject(unexpected);
      else resolve({code, signal});
    });
  });
  child.stdio[3].end(passphrase + '\n');
  if (secret !== undefined) child.stdio[4].end(secret + '\n');
  return { child, exit, stderr: collect(child.stderr) };
}

export async function owner(vault, passphrase, args, secret) {
  const run = spawnOwner(vault, passphrase, args, secret);
  run.child.stdin.end();
  const stdout = collect(run.child.stdout);
  const [exit, out, err] = await Promise.all([run.exit, stdout, run.stderr]);
  assert.equal(exit.code, 0, err);
  assert.equal(err, '');
  assert.equal(out.includes(passphrase), false);
  if (secret) assert.equal(out.includes(secret), false);
  return out;
}

export async function session(vault, passphrase, names) {
  const run = spawnOwner(vault, passphrase, ['serve', ...names.flatMap(name => ['--allow', name]), '--ttl', '120']);
  const client = new Client({ name: 'blinddrop-functional-consumer', version: '1' });
  const transcript = [];
  run.child.stdout.on('data', data => transcript.push(Buffer.from(data)));
  const transport = new StdioServerTransport(run.child.stdout, run.child.stdin, { maxBufferSize: 8 * 1024 * 1024 });
  await client.connect(transport);
  return {
    client,
    async execute(args) { return client.callTool({ name: 'execute_http', arguments: args }); },
    async close() {
      run.child.stdin.end();
      const exit = await run.exit;
      await client.close();
      assert.equal(exit.code, 0);
      return { stdout: Buffer.concat(transcript).toString('utf8'), stderr: await run.stderr };
    }
  };
}
