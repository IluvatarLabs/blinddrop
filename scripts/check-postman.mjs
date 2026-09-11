// Explicit external functional check, kept out of the offline regression suite.
// Uses only Postman's published demonstration credentials, never account keys:
// https://www.postman.com/postman/postman-public-workspace/request/rg6swaa/basic-auth-success
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { owner, session } from '../test/support/owner-session.mjs';

const dir = await mkdtemp(join(tmpdir(), 'blinddrop-postman-'));
const vault = join(dir, 'vault.enc');
const passphrase = randomBytes(24).toString('hex');
const wrong = randomBytes(24).toString('hex');
let active;
try {
  await owner(vault, passphrase, ['init']);
  for (const [name, value] of [['user', 'postman'], ['pass', 'password'], ['wrong', wrong]]) {
    await owner(vault, passphrase, ['secret', 'set', name, '--secret-fd', '4'], value);
  }
  for (const [name, ref] of [['demo', 'pass'], ['invalid-demo', 'wrong']]) {
    await owner(vault, passphrase, ['connection', 'set', name, '--origin', 'https://postman-echo.com',
      '--auth', 'basic', '--username-secret', 'user', '--password-secret', ref]);
  }
  active = await session(vault, passphrase, ['demo', 'invalid-demo']);
  const good = await active.execute({ connection: 'demo', path: '/basic-auth' });
  assert.equal(good.isError, undefined, JSON.stringify(good));
  assert.equal(good.structuredContent.status, 200);
  assert.deepEqual(JSON.parse(good.structuredContent.body), { authenticated: true });
  const bad = await active.execute({ connection: 'invalid-demo', path: '/basic-auth' });
  assert.equal(bad.structuredContent.status, 401);
  const echo = await active.execute({ connection: 'demo', path: '/get' });
  assert.equal(echo.structuredContent.error?.code, 'RESPONSE_BLOCKED');
  const traffic = await active.close(); active = null;
  const visible = JSON.stringify(traffic) + await readFile(vault + '.events.jsonl', 'utf8');
  // The public username also occurs in the public hostname, so it isn't a useful
  // disclosure sentinel. Check the password, Basic wire encoding and random inputs.
  for (const value of [passphrase, wrong, 'password', Buffer.from('postman:password').toString('base64')]) {
    assert.equal(visible.includes(value), false);
  }
  console.log(JSON.stringify({ date: new Date().toISOString(), receiver: 'https://postman-echo.com',
    client: 'official MCP SDK over actual CLI stdio', authentication: 'Basic',
    authenticatedOperation: { path: '/basic-auth', status: 200, authenticated: true },
    wrongCredentialStatus: 401, reflection: 'RESPONSE_BLOCKED', credentialScan: 'passed',
    credentialSource: 'provider-published demonstration account', cleanup: 'temporary vault and logs removed' }, null, 2));
} finally {
  if (active) await active.close();
  await rm(dir, { recursive: true, force: true });
}
