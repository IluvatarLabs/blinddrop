# BlindDrop configuration reference

## Owner setup

Run these in your own terminal. Passphrases and values are entered at hidden prompts, not as command arguments.

```sh
blinddrop init
blinddrop secret set work-key
blinddrop connection set work-api \
  --origin https://api.example.com \
  --auth bearer --secret work-key
blinddrop list
```

Replace the example origin with the API's exact HTTPS origin. `work-key` is a local secret reference; `work-api` is the connection name agents use. The archive defaults to `~/.config/blinddrop/vault.enc`; put `--vault /path/to/vault.enc` before a command to choose another archive.

| Authentication | Options to `connection set NAME --origin ORIGIN` |
|---|---|
| Bearer | `--auth bearer --secret KEY_REF` |
| Named header | `--auth header --secret KEY_REF --field X-Api-Key` |
| Named query parameter | `--auth query --secret KEY_REF --field api_key` |
| Basic | `--auth basic --username-secret USER_REF --password-secret PASS_REF` |

Create the referenced secrets before configuring Basic authentication. Omit either counterpart to send an empty username or password; at least one reference is required. For example, key-as-username APIs use `--auth basic --username-secret KEY_REF`. Values must fit the selected protocol; Basic usernames, for example, cannot contain a colon. For a private or localhost HTTPS API, add `--allow-private` to that connection. TLS verification remains enabled. An owner-managed private CA can use Node's normal CA configuration; the included test CA is solely for the disposable test server.

Local names are case-sensitive ASCII identifiers of up to 64 characters, with alphanumeric ends and alphanumeric, dot, underscore, or hyphen interiors; `constructor` and `prototype` are reserved. Query field names are separate strings that can use the API's own syntax. There is no vendor catalogue.

## Compound authentication

Store each credential with `secret set` first. Write a connection JSON file containing references, then import it:

```sh
blinddrop connection import partner-api ./partner-api.json
```

For an API accepting two credentials in JSON:

```json
{
  "origin": "https://api.example.com",
  "allowPrivate": false,
  "enabled": true,
  "auth": {
    "type": "bindings",
    "bindings": [
      { "in": "json", "name": "client_id", "secret": "client-id" },
      { "in": "json", "name": "secret", "secret": "client-secret" }
    ]
  }
}
```

The agent sends its ordinary JSON request body; BlindDrop supplies or replaces the two configured fields. JSON bindings are top-level fields. Use `in: "header"`, `"query"` or `"form"` for those placements, with optional literal `prefix`/`suffix`. A header binding with `name: "Authorization"` and `prefix: "Token "` handles that authentication convention. Up to 16 bindings are allowed; JSON and form cannot be mixed. Credential fields override conflicting caller fields.

For a token embedded before an API method path, use `{"in":"path","prefix":"/bot","secret":"bot-token"}`. An agent request for `/getMe` becomes the API's authenticated path inside BlindDrop. The origin remains fixed; the authenticated URL is never returned. There is no general-purpose templating language.

Other `auth` objects use these fields. Names ending in `Secret`, plus `clientSecret` and `refreshSecret`, refer to vault entries:

| `type` | Required fields | Optional fields / limits |
|---|---|---|
| `oauth2` | `tokenEndpoint`, `grant`, `clientId`, `clientAuth` | `grant` is `client_credentials` or `refresh_token`; the latter needs `refreshSecret`. `clientAuth` is `basic`, `body` or `none`; Basic/body need `clientSecret`. Optional `scope`, `audience`, `resource`. Obtain the initial refresh grant with `oauth login` ([guide](OAUTH.md)), or provision it through the owner secret input. |
| `jwt-bearer` | `tokenEndpoint`, `issuer`, `scope`, `privateKeySecret` | Optional `subject`, `keyId`. RS256 assertion exchanged for a Bearer token; not a direct GitHub App JWT workflow. |
| `aws-sigv4` | `accessKeyIdSecret`, `secretAccessKeySecret`, `region`, `service` | Optional `sessionTokenSecret` for temporary AWS credentials. |
| `none` | No auth fields | Requires TLS client credentials below. |

For example, an OAuth refresh configuration is:

```json
{
  "type": "oauth2",
  "tokenEndpoint": "https://oauth2.googleapis.com/token",
  "grant": "refresh_token",
  "clientId": "YOUR_PUBLIC_CLIENT_ID",
  "clientAuth": "body",
  "clientSecret": "oauth-client-secret",
  "refreshSecret": "oauth-refresh-token"
}
```

This is a configuration example, not a claim that this checkout was tested against a Google account. Token endpoints are owner-configured HTTPS URLs. Token responses stay internal; rotating refresh tokens are saved into the encrypted archive before use. Failed exchanges or storage failures do not return tokens or replay the API operation. Access tokens are cached until the returned `expires_in` elapses; if omitted, they remain cached for the session. A resource 401 is returned without automatic refresh-and-replay. Restart the session to discard that cache.

For mutual TLS, add a top-level `tls` object to the connection:

```json
{
  "certificateSecret": "client-certificate-pem",
  "privateKeySecret": "client-private-key-pem"
}
```

An encrypted private key can add `passphraseSecret`. Store PEM contents using the normal protected owner input; a trusted launcher can supply a multiline value through the inherited secret descriptor. TLS composes with the selected HTTP authentication. BlindDrop uses Node's certificate validation and does not install a MITM CA.

## Owner GUI

`blinddrop ui` starts an owner-only page on a loopback port and opens it in your default browser; `--no-browser` prints the URL instead and `--port` fixes the port. The page manages the same archive as the commands above: create or unlock the vault, add or disable secrets and connections, import a compound definition, change the passphrase, and start or stop an agent session with chosen connections, a lifetime and a port. The page's URL carries a one-time owner token; every request needs it, the listener accepts only its own origin, and the token is never given to an agent. The passphrase you type is held in the `ui` process's memory only, as `serve` holds it. Quit from the page or press Ctrl-C in the terminal to stop; closing the tab alone leaves the process running.

A session started from the page defaults to port 8787 and, unless you untick the option, writes `~/.config/blinddrop/session.json` at mode 0600 with the MCP URL, session token, expiry and connection base URLs. The BlindDrop Claude Code plugin reads that file to connect automatically; the file is deleted when the session ends. The CLI writes the same file only with `serve --http --session-file PATH`.

The macOS app in `desktop/` hosts the same server and page in its own window; quitting the app ends every session. Linux and Windows use the browser page.

## Agent session

Configure a terminal-launched stdio MCP client to use the installed executable. Replace the example path with the result of `command -v blinddrop`:

```json
{
  "mcpServers": {
    "blinddrop": {
      "command": "/absolute/path/to/.local/bin/blinddrop",
      "args": [
        "serve", "--allow", "work-api", "--ttl", "3600"
      ]
    }
  }
}
```

With a terminal-launched client, the helper prompts the owner on the controlling terminal, keeping MCP stdin/stdout for protocol messages. Unlock once per helper session. Repeat `--allow` for more connections; no wildcard grant is provided. The default lifetime is one hour, with a range of 1–86400 seconds. The helper exits on expiry, client input closure, SIGINT, or SIGTERM.

A headless host without a controlling terminal must supply owner input through inherited descriptors. Global `--password-fd 3` reads the passphrase from descriptor 3; `secret set ... --secret-fd 4` can similarly read a value. The trusted launcher must create and pass those descriptors: adding their numbers to MCP JSON alone does not create the input. Input is bounded UTF-8, read to EOF, with one trailing newline removed; descriptors close after use. No passphrase environment variable or plaintext cache is provided. Alternatively, start `serve --http` in your terminal and attach the headless host using the temporary session token ([HTTP setup](CLIENTS.md#attach-an-independently-launched-mcp-host)). The owner GUI is an owner-side page, not a host unlock dialog: use it to start a session and copy the URL and token for a headless host, or leave the session file on so the Claude Code plugin attaches automatically.

The server exposes exactly two tools: `list_connections` for permitted metadata and `execute_http` for requests. Example request:

```json
{
  "connection": "work-api",
  "method": "GET",
  "path": "/v1/items",
  "query": { "limit": "10" },
  "headers": { "Accept": "application/json" }
}
```

Choose one request representation: `body` for UTF-8 text, `bodyBase64` for bytes, or `multipart` for form uploads. A file part is `{ "name": "file", "filename": "sample.bin", "contentType": "application/octet-stream", "dataBase64": "AAEC/w==" }` inside `multipart.files`; optional `multipart.fields` contains ordinary string fields. BlindDrop generates the multipart Content-Type and boundary.

Results contain `status`, `headers`, and a UTF-8 `body` by default. Set `responseEncoding: "base64"` to receive binary bytes as base64 with `bodyEncoding: "base64"`. This still checks the decoded response for credential material before returning it. Base64 and MCP JSON add size overhead; the request/response byte limits below apply to the HTTP data. Broker errors contain static `error.code` and `error.message` fields with MCP `isError: true`. Agent tools cannot read secrets or perform owner administration.

## Replace, disable, and back up

Stop the active helper before changing credentials or connections, then start a new session. A running session keeps its opened snapshot; editing the archive does not revoke that process.

```sh
blinddrop secret set work-key
blinddrop secret disable work-key
blinddrop connection disable work-api
blinddrop passwd
```

`secret set` replaces and enables a secret; `connection set` replaces and enables a connection. `connection import` uses the definition's explicit `enabled` value. `secret remove NAME` removes an unreferenced secret and rejects removal while a connection references it. `list` shows metadata only.

`passwd` unlocks with the old passphrase, prompts for and confirms the new one, then atomically re-encrypts the archive. A trusted launcher can supply `--password-fd 3 passwd --new-password-fd 4`. Existing helpers must be stopped first; backups retain their original passphrase.

Back up or move the encrypted archive by copying it. Restore the copy at a selected `--vault` path and unlock with the same passphrase. There is no passphrase-recovery bypass. Use events are appended to `<vault-path>.events.jsonl`, containing timestamp, grant identifier, known connection name, outcome, and error code. Request bodies, query values, and credentials are excluded. It is a local diagnostic log, not an audit ledger or automatically rotated archive. A log append failure produces a static warning while preserving the request's actual result.

## Limits

The expanded scope covers the HTTPS mechanisms above, JSON/form/text/XML, REST/GraphQL payloads, multipart and binary. Browser session automation, device authorization, other signing/challenge protocols, native database/SSH protocols, WebSocket and gRPC remain outside it. Ordinary HTTP/SSE streaming is available through the SDK endpoint. Default responses must be valid UTF-8; explicit base64 mode preserves binary bytes. Identity, gzip, deflate and Brotli content encodings are handled; unsupported encodings fail explicitly.

Buffered MCP requests are capped at 1 MiB including target, headers, and body; headers at 16 KiB; responses at 4 MiB before and after decompression. Up to four requests run concurrently, each with a 30-second total timeout. MCP input is capped at 2 MiB. SDK requests are capped at 16 MiB, responses at 64 MiB before and after decompression, with a ten-minute total timeout and the same four-operation cap. The CLI does not expose limit tuning. MCP returns redirects without following them; the SDK endpoint rejects redirects so the client stays within its connection. BlindDrop never retries ambiguous failures.

A complete bounded MCP response is checked for used secret values and constructed credential representations before release. The SDK endpoint inspects incremental bytes while withholding enough tail to detect split credentials. A late failure truncates delivery; already delivered safe bytes remain visible. This is explicitly different from buffered all-or-nothing delivery. Cookies are always discarded. Very short or common credential values can conservatively block unrelated response text that happens to contain them. The intended API receives the credential and must be trusted: direct-reflection checks cannot defeat arbitrary transformations by a malicious recipient. Credential opacity does not prevent misuse of an authorized API action. An unrestricted agent is outside the assumed harness restrictions; BlindDrop does not detect or police that mode.
