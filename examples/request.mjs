// An ordinary HTTP consumer. BlindDrop supplies only a local URL/session token.
const base = process.env.BLINDDROP_BASE_URL;
const token = process.env.BLINDDROP_TOKEN;
const path = process.argv[2];
if (!base || !token || !path || !path.startsWith('/') || path.startsWith('//')) {
  throw new Error('Use: blinddrop run CONNECTION -- node request.mjs /API/PATH');
}
// Append to the connection prefix; new URL('/path', base) would discard it.
const response = await fetch(base + path.slice(1), {
  headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'User-Agent': 'blinddrop-example' },
  redirect: 'error',
});
const body = await response.text();
process.stdout.write(`HTTP ${response.status}\n${body}\n`);
if (!response.ok) process.exitCode = 1;
