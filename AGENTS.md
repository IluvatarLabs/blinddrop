# AGENTS.md — BlindDrop contributor guide

`CLAUDE.md` points here so coding agents and human contributors share one set
of repository rules. Owner and client behavior is documented in
[README.md](README.md), [CONFIGURATION.md](CONFIGURATION.md) and
[CLIENTS.md](CLIENTS.md); the security boundary is in
[SECURITY.md](SECURITY.md).

## Product invariants

- Stored credentials never reach an agent through BlindDrop's tools, results,
  errors, use logs or the child environment of `run`. Agent tools expose no
  secret-read or owner-administration operation.
- Every execution interface shares one broker and one validated HTTPS sender.
  Configured authentication overrides caller input; absolute targets, other
  authorities, redirects and metadata addresses are refused.
- Owner unlock uses a hidden terminal prompt, an inherited descriptor, or the
  authenticated owner-only loopback page hosted by the browser or macOS app.
  No passphrase environment variable, plaintext cache or agent-visible unlock
  or administration route.
- Each vault is an encrypted file with its own passphrase and lock state. A
  connection enters the running session only while every vault holding its
  referenced secret fields is unlocked; locking a vault removes exactly its
  dependent connections.
- Permissions and isolation belong to the agent harness and the OS. Document
  that assumption; do not build a sandbox, harness audit or unrestricted-mode
  detector.
- Keep the GUI to the owner-only loopback page and thin macOS shell. Do not add
  an always-on daemon, hosted control plane, runtime provider catalogue or
  extension framework. Keep BlindDrop a local vault and helper.

## Working method

- Read the guides, code and call sites before changing behavior. Trace
  a change end to end: CLI or MCP input, broker, transport, response check.
- Before inventing a custom method, find the established practice and prefer
  the smallest standard component that satisfies the contract. If it fails,
  change the component before adding custom complexity.
- Tests prove the actual workflow against disposable HTTPS receivers with
  generated credentials. A test earns its place by proving a named, reachable
  failure or real behavior; never change working behavior to satisfy a test
  that proves nothing.
- Update the guides, examples and help text in the same change as a behavior
  change. Do not present proposed behavior as implemented.

## Verification and reporting

- Never claim a command passed unless it was run. Report the command, exit
  status and observed result.
- `npm run check`, `npm test`, `npm pack` and `npm run check:package` are the
  release gate. Live provider checks are recorded separately from controlled
  receivers; a recipe is not live-account proof.
- Before publishing, inspect the tarball and any app archive. Public artifacts
  must not contain credentials, vault archives, local paths or private
  material. Describe an app's architecture, signing and notarization state
  exactly as built.

## Git discipline

- Check `git status` before editing and before reporting completion.
- Do not commit or push unless the task authorizes it. Stage files by name.
- Never place real credentials, unlock material or session tokens in
  arguments, environments, fixtures, logs, tests or documentation.
