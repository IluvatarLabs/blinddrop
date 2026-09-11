# Third-party code notices

BlindDrop adapts the following MIT-licensed code. The upstream repositories and commits are recorded below. Installed dependencies retain their own licenses in their packages and exact versions in `package-lock.json`.

## 1Claw CLI

Upstream: https://github.com/1clawAI/1claw-cli
Commit: `5fa5e2c0af355f6d9530cea132668474a8c2acdf`.

Source files: `src/local-vault.ts`, `src/local-policy.ts`, and `src/secret-proxy.ts`.
Local adaptations: `src/vault.ts` retains the scrypt/AES-GCM envelope with BlindDrop's smaller validated payload and atomic filesystem writes; `src/broker.ts`, `src/auth.ts` and `src/transport.ts` retain explicit request execution and configurable authentication, adding the bounds and disclosure checks required by the MVP. Legacy cloud synchronization and vendor application features are omitted. The compatibility expansion factors the existing request transport for reuse by token exchanges; OAuth, JOSE and AWS signing are imported from their standard packages rather than copied from these reference checkouts.

```text
MIT License

Copyright (c) 2026 1Claw Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Infisical Agent Vault

Upstream: https://github.com/Infisical/agent-vault
Commit: `bd1a325d79129644487f3e5b4f18c51adbc64638`.

Source files: `internal/netguard/netguard.go` and `internal/brokercore/brokercore.go`.
Local adaptations: `src/netguard.ts` applies resolved-address validation and direct dialing using Node and ipaddr.js, with private-destination authorization per connection; `src/broker.ts` adapts canonical header stripping and the rule that configured authentication overrides caller input. No enterprise-directory code, database, control plane, MITM proxy, or generated certificate authority is included.

```text
Copyright (c) 2022 Infisical Inc.

Portions of this software are licensed as follows:

- All content that resides under any "ee/" directory of this repository, if such directories exists, are licensed under the license defined in "ee/LICENSE".
- All third party components incorporated into the Infisical Software are licensed under the original license provided by the owner of the applicable component.
- Content outside of the above mentioned directories or restrictions above is available under the "MIT Expat" license as defined below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 0.3 standard components

The HTTP MCP interface uses `@modelcontextprotocol/server` and its official
`@modelcontextprotocol/node` adapter, both MIT licensed. The existing stdio
SDK remains in use. The shared HTTPS transport uses Node HTTP/TLS, stream
pipelines and zlib decoders; no additional proxy framework or cryptography
was copied. Portable owner browser launch uses MIT-licensed `open`. The
MIT-licensed official `@anthropic-ai/sdk` is a development consumer used for
functional verification and the example; it is not a BlindDrop runtime
dependency. `cross-env` supplies the portable development test command.
Exact versions and transitive dependencies are recorded in `package-lock.json`;
installed packages retain their licenses.
