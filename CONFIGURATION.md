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

Other `auth` objects use these fields. Names ending in `Secret`, plus `clientSecret` and `refreshSecret`, refer to vault entries. A reference may be vault-qualified and field-qualified as `vault#secret#field`; a bare name resolves in the default vault to its `value` or sole field (see [Secrets and fields](#secrets-and-fields)):

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

`blinddrop ui` starts an owner-only page on a loopback port and opens it in your default browser; `--no-browser` prints the URL instead and `--port` fixes the port. The page manages your vaults and connections: create, open, unlock or lock a vault; add, replace, turn off or remove typed multi-field secrets and connections; prefill a connection from a template; import a compound definition; group connections; read the use log; back up a vault and change its passphrase. The page's URL carries a one-time owner token; every request needs it, the listener accepts only its own origin, and the token is never given to an agent. Passphrases you type are held in the `ui` process's memory only, as `serve` holds them. Quit from the page or press Ctrl-C in the terminal to stop; closing the tab alone leaves the process running.

### Vaults

A vault is one encrypted file with its own passphrase and its own lock state, and you can have several. Each vault reuses the same key derivation and authenticated encryption as before, so no new cryptography is involved. A registry at `~/.config/blinddrop/vaults.json` records each vault's name and path only — never a passphrase. Before the first vault exists, the app offers `default` at `~/.config/blinddrop/vault.enc` as a suggestion. The owner may choose a different name and location; only actual registrations are saved. Existing registered names and paths are retained; opening or creating another vault adds its name and path to the registry, and removing one only unregisters it (the file stays on disk and the default vault cannot be removed).

You unlock and lock each vault on its own. Unlocking a vault decrypts only that vault into the page's process; the others stay encrypted at rest, so a mishandled passphrase exposes one vault rather than all of your secrets. This least-privilege unlock is the reason to keep separate trust domains in separate vaults.

Because every secret reference is vault-qualified (see [Secrets and fields](#secrets-and-fields)), a connection is usable in the session only while every vault holding its referenced secrets is unlocked. Locking a vault removes just its dependent connections from the running session and leaves the rest; the session is recomputed whenever any vault is locked or unlocked.

### Screens

The page opens on one of three screens, with Settings in a window of its own. **Welcome** creates a new vault at a location you choose, or opens an existing one from the recent list. **Unlock** takes the passphrase for a configured but locked vault; `Open another vault…` opens the shared vault picker. **The vault window** has the sidebar on the left, the top-level Connections, Secrets and Activity views in the middle, and the detail pane on the right. The sidebar lists your vaults with each one's locked or unlocked state and lets you unlock, lock, create or open another. Connections show as a list or a table and can be grouped; opening a secret shows its field editor; adding a connection offers the template picker with Custom last. **Settings** has the General, Security, Sessions, Vault and Advanced tabs.

Which screen opens first follows the configured vault: a `--vault` path if you gave one, otherwise the last vault recorded in settings, otherwise `~/.config/blinddrop/vault.enc`. An existing vault opens Unlock while all vaults are locked, whether or not connections have been saved. If no configured vault file exists, the page opens Welcome. Locking the last unlocked vault returns to Unlock. Once a vault is unlocked the vault window shows the full vault list, and you open, create, unlock or lock the others from there.

### The session

Unlocking a vault starts or recomputes the agent session using the secrets now available; locking every vault, quitting, or closing the owner process ends it. There is no session to start or stop by hand. The session grants every connection that is enabled and whose referenced secret fields all exist, are enabled, and resolve in a currently unlocked vault; a connection missing one of those is shown as not in the session, with the reason. Every owner change — a secret or connection written, turned on, turned off or removed, a passphrase change, or a vault locked or unlocked — recomputes the session from the new snapshot, so a change applies without further action. Requests in flight during that restart fail.

The app and CLI HTTP sessions share the port in Settings › Sessions. On first use, a cryptographically random port from 49152–65535 is saved in `~/.config/blinddrop/settings.json`; existing saved choices are preserved. If occupied, startup tries the next port and saves the one it binds, wrapping within the dynamic range after 65535. A lower custom port scans upward to 65535. Other bind failures or exhaustion remain visible errors. Change the preference in Settings, or use `serve --http --port PORT` / `run --port PORT`; a nonzero override is saved after successful binding. Explicit `--port 0` chooses a temporary OS-assigned port without changing the preference. The owner page session lasts up to 86400 seconds and renews while a vault stays unlocked. Managed integrations follow the actual endpoint, including a collision during renewal with no window open; follow their host reload guidance. Manual clients must use the reported URL.

While the session runs and Settings › Sessions › Agent access is on, which is the default, the session record is written to `~/.config/blinddrop/session.json` at mode 0600 with the MCP URL, session token, expiry and connection base URLs. It is always in the configuration directory, whatever path the vault file has, so the BlindDrop Claude Code plugin finds it. Its location is shown in Settings › Advanced. The file is deleted when the session ends. The CLI writes the same file only with `serve --http --session-file PATH`.

### Secrets and fields

A secret has a type and one or more named fields. Choosing a type in the field editor prefills the fields that type usually needs — for example an `aws` secret starts with an access-key id and a secret access key, a `login` with a username and password, a `tls` bundle with a certificate and private key — and you can edit labels and values, remove fields or add custom fields, with no fixed count of custom fields beyond the archive and request size limits. Existing field IDs are read-only so editing a label does not break connections; new field IDs are chosen before saving. The built-in types are `api-key`, `login`, `keypair`, `aws`, `tls`, `oauth`, `jwt` and `custom`. Each field records a human label, whether it is masked (concealed, like a password or token) or shown (like an access-key id), and whether it is multiline (a PEM block, whose exact bytes are kept). Replacing a secret keeps the value of any field you leave blank.

Field ids use the same snake_case as the source you copy from (`aws_secret_access_key`, `client_secret`, `private_key`), so a field name matches what the connection consumes and there is nothing to translate. Several parts of one credential can therefore live as fields of one secret instead of separate secrets. The `blinddrop secret set` command still creates a single-value secret (one `value` field); the field editor is where typed multi-field secrets are built.

A connection points at one field with a vault-qualified reference `vault#secret#field`. `secret#field` and a bare `secret` resolve in the default vault. A bare reference with no field resolves to the field named `value` — what a single-value or migrated secret uses — or to the only field of a single-field secret; a multi-field secret is addressed by field. The connection editor lets you select any stored field. On import or migration, unqualified references are bound to the selected/source vault and saved in the full form, so opening an old archive as another vault cannot use a same-named default-vault secret.

The connection editor identifies an existing secret and field separately from a new value. Leaving the replacement value empty keeps the stored credential. Custom connections select the authentication method and credential placement; custom secrets add named fields independently.

Import .env parses ordinary Node dotenv syntax, including unquoted inline comments, quoted hashes and quoted multiline values. Review destination names before saving. Parsing does not write the vault; final import keeps the existing collision checks and optional source-to-Trash choice.

### Connection storage and migration

When adding a connection with a bare secret reference, unlock that secret's
vault first so its default field can be resolved. An explicit field reference
can be saved while that vault is locked, provided another vault is unlocked;
the connection remains unavailable until every referenced vault is unlocked.

Connections belong to one independent list in `~/.config/blinddrop/connections.json`, at mode 0600. This file contains origins, authentication settings and secret references, never stored secret values. Vaults hold secrets. Connections are visible and editable only while at least one vault is unlocked. Their referenced fields alone determine whether they can join the agent session; an unrelated locked vault does not revoke them. When all vaults are locked, connection listing and edits, Activity and Groups are unavailable.

When an old archive is unlocked, its embedded connections are qualified against that vault and copied to this list before the encrypted archive is rewritten without them. Identical definitions are reused on retry. Different definitions with the same name retain both, adding a source-vault suffix to the imported name. No passphrase changes.

CLI commands for a registered vault use the same list. A standalone `--vault` archive uses `<vault-path>.connections.json`; opening it in the app imports that sidecar and remaps its `default` references to the registered vault name. Back up the sidecar with a standalone archive. CLI `serve` still unlocks only the archive selected by `--vault`; use the owner page for connections spanning multiple vaults.

### Connection templates

Adding a connection starts from a template rather than a blank form. A template is a static prefill — the provider's HTTPS origin, its authentication mechanism and placement, and the secret fields it needs — so picking one creates the connection and the shaped secret in a couple of steps. Templates are configuration in the page, not per-vendor code in the runtime: the request path still uses the generic authentication mechanisms, and there is no runtime provider catalogue. Custom is the explicit fallback, listed last, for anything without a template.

A template can only use a mechanism BlindDrop already implements. A provider that needs something else is flagged rather than faked — for example Backblaze's native B2 authorization returns a dynamic API host the fixed-origin runtime cannot follow, so its template uses Backblaze's S3-compatible endpoint with AWS SigV4 instead.

### Settings

Settings are stored in `~/.config/blinddrop/settings.json` at mode 0600 and read and written through the page, because the page's origin changes with its loopback port on every launch.

| Field | Type and default | Effect |
|---|---|---|
| `appearance` | `"system"`, `"light"` or `"dark"`; default `"system"` | Page and native Mac appearance |
| `sessionPort` | integer 1–65535; random 49152–65535 on first use | Saved preferred port for app and CLI HTTP sessions; advances if occupied |
| `sessionFile` | boolean; default true | Write the session file while the session runs |
| `lockOnSleep` | boolean; default true | App only: lock when the computer sleeps |
| `lockOnScreenLock` | boolean; default false | App only: lock when the screen locks |
| `idleLockMinutes` | 0, 1, 5, 15, 30 or 60; default 0 (Off) | App only: lock all vaults after this many minutes of system inactivity, including with no window open |
| `openAtLogin` | boolean; default false | App only: open at login |
| `showDockIcon` | boolean; default true | App only: show the Dock icon; hiding it keeps the menu-bar item available |
| `lastVault` | path or null | Vault opened at the next start |
| `recentVaults` | up to 10 paths, newest first | The Welcome screen's list of vaults to open |
| `lastBackupAt` | timestamp or null | Shown in Settings › Vault |
| `ui` | object of at most 4 KiB | The page's own view state |

### Groups

Groups are owner-side labels for connections. The encrypted archive does not store them and agents never see them: they live in a `<config dir>/groups.json` file at mode 0600 keyed by connection name, shared across vaults. Old `vault#connection` keys migrate when their archive is unlocked. Rename or remove a group from its connection-list header. Renaming preserves memberships; removing a group keeps its connections and secrets. Group names obey the same rules as other local names; at most 64 groups, and at most 16 groups per connection.

### Activity and backups

The owner page writes and reads `~/.config/blinddrop/vault.enc.events.jsonl` for every session, including when only another vault is unlocked. CLI sessions use `<vault-path>.events.jsonl`, as described under [Replace, disable, and back up](#replace-disable-and-back-up), taking a bounded tail of the file rather than all of it and showing the newest events first. Clearing it from the page truncates that file. **Export Encrypted Vault** copies the encrypted archive byte for byte to a path you choose; it refuses a path that already exists, so a backup never overwrites one, and records the time in Settings › Vault.

**Back Up Setup** creates a new folder containing every registered encrypted archive, `vaults.json`, `connections.json`, `groups.json` and `settings.json`. Archives retain their own passphrases. The other files are plaintext metadata and references, protected by owner-only file permissions; they contain no stored credential values. The live session file and Activity log are excluded. A missing or unreadable registered archive fails the whole backup, without publishing a partial folder.

**Restore Setup** is available on Welcome before creating or opening a vault. It validates the folder, copies archives into fresh app configuration, rebases their registered paths and starts locked. A fresh installation containing only preferences is allowed; the backup replaces those preferences. Existing archives, registrations, connections, groups or unknown files prevent restore. It refuses existing data rather than overwriting or merging it. Unlock each required vault with its existing passphrase to use its connections. If a registered vault file is missing, choose Locate file and select its original file or an encrypted backup. Its name and connection references are preserved, and the located file requires an explicit unlock. Encrypted-envelope shape can be checked while locked; authentication and payload integrity are checked on unlock.

### Browser and app

In the browser, the page draws its own menu bar — app, File, Edit, View, Window and Help — because those menus are the only way to reach Settings, About, the shortcut list and `Open vault…` there. Where the app opens a file dialog, the browser page takes a path in a text field.

The macOS app supplies its own runtime and hosts the same server and page in its own window. Normal installation needs no Node, global CLI, terminal or PATH changes. Closing its window keeps the app and current session running; Dock or menu-bar Open recreates one window. Lock All works with Settings focused or no window, and Quit ends the session. Every launch starts locked. It adds the native application menu, system file dialogs for creating, opening and backing up a vault, `Reveal in Finder` for the vault and the use log, locking when the computer sleeps or the screen locks, and opening at login. Linux and Windows can use the browser interface where independently verified; the Mac app does not establish those platforms' compatibility.

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

A headless host without a controlling terminal must supply owner input through inherited descriptors. Global `--password-fd 3` reads the passphrase from descriptor 3; `secret set ... --secret-fd 4` can similarly read a value. The trusted launcher must create and pass those descriptors: adding their numbers to MCP JSON alone does not create the input. Input is bounded UTF-8, read to EOF, with one trailing newline removed; descriptors close after use. No passphrase environment variable or plaintext cache is provided. Alternatively, start `serve --http` in your terminal and attach the headless host using the temporary session token ([HTTP setup](CLIENTS.md#attach-an-independently-launched-mcp-host)). The owner GUI is an owner-side page, not a host unlock dialog: unlock it and leave the session file on so the Claude Code plugin attaches automatically, or use `serve --http` in your terminal for a host you configure by hand.

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

Copy an encrypted archive to back up its secrets, and unlock a restored copy with the same passphrase. For complete app recovery, use **Back Up Setup** and **Restore Setup** as described above; the folder retains connection definitions, registry, groups and settings and restore rebases vault paths. For a standalone CLI archive, copy its `<vault-path>.connections.json` sidecar to the matching path beside the restored archive. **Export Encrypted Vault** copies only the selected encrypted archive, not the separate configuration. There is no passphrase-recovery bypass. Use events are appended to `<vault-path>.events.jsonl`, containing timestamp, grant identifier, known connection name, broker outcome, error code, and HTTP status for completed exchanges. Broker completion does not imply provider success: the UI shows HTTP 401 or HTTP 500 as an error result. Historical entries without HTTP status are shown as Completed. Request bodies, query values, and credentials are excluded. It is a local diagnostic log, not an audit ledger or automatically rotated archive. A log append failure produces a static warning while preserving the request's actual result.

## Limits

The expanded scope covers the HTTPS mechanisms above, JSON/form/text/XML, REST/GraphQL payloads, multipart and binary. Browser session automation, device authorization, other signing/challenge protocols, native database/SSH protocols, WebSocket and gRPC remain outside it. Ordinary HTTP/SSE streaming is available through the SDK endpoint. Default responses must be valid UTF-8; explicit base64 mode preserves binary bytes. Identity, gzip, deflate and Brotli content encodings are handled; unsupported encodings fail explicitly.

Buffered MCP requests are capped at 1 MiB including target, headers, and body; headers at 16 KiB; responses at 4 MiB before and after decompression. Up to four requests run concurrently, each with a 30-second total timeout. MCP input is capped at 2 MiB. SDK requests are capped at 16 MiB, responses at 64 MiB before and after decompression, with a ten-minute total timeout and the same four-operation cap. The CLI does not expose limit tuning. MCP returns redirects without following them; the SDK endpoint rejects redirects so the client stays within its connection. BlindDrop never retries ambiguous failures.

A complete bounded MCP response is checked for used secret values and constructed credential representations before release. The SDK endpoint inspects incremental bytes while withholding enough tail to detect split credentials. A late failure truncates delivery; already delivered safe bytes remain visible. This is explicitly different from buffered all-or-nothing delivery. Cookies are always discarded. Very short or common credential values can conservatively block unrelated response text that happens to contain them. The intended API receives the credential and must be trusted: direct-reflection checks cannot defeat arbitrary transformations by a malicious recipient. Credential opacity does not prevent misuse of an authorized API action. An unrestricted agent is outside the assumed harness restrictions; BlindDrop does not detect or police that mode.
