# Contributing

Thank you for improving BlindDrop. Start with [README.md](README.md) for what
BlindDrop does, [CONFIGURATION.md](CONFIGURATION.md) for owner and connection
behavior, and [SECURITY.md](SECURITY.md) for the security boundary;
[AGENTS.md](AGENTS.md) holds the working rules that human contributors and
coding agents share. Behavioral changes must agree with those documents, or
change them explicitly in the same change.

## Development setup

Requirements: Node.js 22.13+ on the 22.x line or 23.5+, npm and Git.

```sh
git clone https://github.com/IluvatarLabs/blinddrop.git
cd blinddrop
npm ci
npm run build
node dist/cli.js --help
```

Never commit real credentials, vault archives, use logs, passphrases or session
tokens. `test/fixtures` holds only the generated localhost test certificate
used by the disposable HTTPS receivers.

## Before opening a pull request

```sh
npm run check
npm test
npm pack
npm run check:package -- ./blinddrop-0.4.0.tgz
```

The test suite runs the real CLI, MCP helper and official SDK clients against
disposable local HTTPS receivers with dummy credentials. The package check
installs the freshly packed tarball into a disposable directory and exercises
its owner CLI, passphrase change, MCP HTTP and streamed SDK workflows without
touching your normal installation. Inspect the tarball contents: it may contain
only `dist/`, `ui/`, `plugin/`, `examples/`, the guides listed in `package.json`,
the license and the third-party notices. The macOS app under `desktop/` has its
own manifest and build steps in its README; it is not part of the npm package.

Three explicit checks contact external services or an installed agent host and
are separate from the offline suite: `node scripts/check-postman.mjs`,
`node scripts/check-agent-host.mjs` and
`node scripts/check-http-host.mjs`. They use published demonstration accounts
or generated fixture credentials only.

## Change discipline

- Keep changes small and scoped to one concern, and explain which failure
  mode a change prevents or which workflow it enables.
- Prefer the smallest standard component, library or pattern that satisfies
  the contract over new abstractions. Reused code keeps its notices in
  [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
- A test earns its place by proving a reachable behavior or failure of the
  actual workflow; prefer functional receivers over synthetic mocks.
- Update the guides, help text and examples in the same change when behavior
  or names change. Do not describe untested behavior as supported.
- Do not add a GUI, always-on daemon, hosted control plane, provider
  catalogue, sandbox, or MITM certificate authority without an accepted change
  to the documented behavior.
- Include the real commands you ran and their observed results in the pull
  request. Do not report unrun checks as passing.

For security-sensitive reports, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.
