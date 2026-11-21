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
| `oauth2` | `tokenEndpoint`, `grant`, `clientAuth`, and exactly one of `clientId` or `clientIdSecret` | `grant` is `client_credentials` or `refresh_token`; the latter needs `refreshSecret`. `clientAuth` is `basic`, `body` or `none`; Basic/body need `clientSecret`. Optional `scope`, `audience`, `resource`. Obtain the initial refresh grant with **Save and connect** in the app or `oauth login` ([guide](OAUTH.md)), or provision it through the owner secret input. |
| `jwt-bearer` | `tokenEndpoint`, `issuer`, `scope`, `privateKeySecret` | Optional `subject`, `keyId`. RS256 assertion exchanged for a Bearer token; not a direct GitHub App JWT workflow. |
| `aws-sigv4` | `accessKeyIdSecret`, `secretAccessKeySecret`, `region`, `service` | Optional `sessionTokenSecret` for temporary AWS credentials. |
| `modal` | `tokenIdSecret`, `tokenSecretSecret` | A Modal account token pair used only by [`invoke_modal_function`](#modal-functions). The connection's origin must be `https://api.modal.com`, it needs the top-level `modal` object below, and it cannot use `tls` or `allowPrivate`. |
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

This is a configuration example, not a claim that this checkout was tested against a Google account. The client ID can instead be stored in the vault and referenced with `clientIdSecret`; exactly one of `clientId` and `clientIdSecret` is allowed. With a reference, replacing the stored client ID changes every connection that uses it at the next session, without editing the connection. Existing definitions with a literal `clientId` remain valid and are not converted.

```json
{
  "type": "oauth2",
  "tokenEndpoint": "https://oauth2.googleapis.com/token",
  "grant": "refresh_token",
  "clientIdSecret": "work#google-oauth#client_id",
  "clientAuth": "body",
  "clientSecret": "work#google-oauth#client_secret",
  "refreshSecret": "work#google-oauth#refresh_token"
}
```

Token endpoints are owner-configured HTTPS URLs. Token responses stay internal; rotating refresh tokens are saved into the encrypted archive before use. Failed exchanges or storage failures do not return tokens or replay the API operation. Access tokens are cached until the returned `expires_in` elapses; if omitted, they remain cached for the session. A resource 401 is returned without automatic refresh-and-replay. Restart the session to discard that cache. In the app, if a refresh token rotates during the moment an unlock replaces the app's access, the connection can keep the old refresh token and fail until the app next rebuilds access (your next change or the 24-hour renewal), or, if the provider revokes the grant when an old refresh token is reused, until you give it a new refresh token or consent; that window is one refresh exchange.

For mutual TLS, add a top-level `tls` object to the connection:

```json
{
  "certificateSecret": "client-certificate-pem",
  "privateKeySecret": "client-private-key-pem"
}
```

An encrypted private key can add `passphraseSecret`. Store PEM contents using the normal protected owner input; a trusted launcher can supply a multiline value through the inherited secret descriptor. TLS composes with the selected HTTP authentication. BlindDrop uses Node's certificate validation and does not install a MITM CA.

### Optional connection fields

A connection definition can also carry these top-level fields. None of them holds a credential value or a vault reference.

| Field | Meaning |
|---|---|
| `recipe` | Stable id of the bundled [template](#connection-templates) the owner page created the connection from: lowercase letters, digits and hyphens, up to 32 characters. It selects the usage guidance agents receive and never changes authentication. An absent or unknown id, or a definition no longer compatible with its template, gets generic guidance. `connection import` keeps a supplied valid id; `connection set` writes none. |
| `consent` | Owner-only browser consent settings for an OAuth `refresh_token` connection: `issuer`, `authorizationEndpoint`, optional `authorizationParameters` and optional `redirectPort` (zero or absent selects a free port). The rules match the `oauth login` file ([guide](OAUTH.md)). The owner's **Save and connect** and **Sign in again…** use it. The agent helper reads only `issuer`, to check an ID token that a token refresh may return (Google's issuer is not its token endpoint's origin); without `consent`, that check uses the token endpoint's origin. |
| `modal` | Required with, and only with, `modal` authentication: the deployed `app`, the name of its `function`, the Modal `environment`, and optional `usage`, up to 2,048 bytes of owner-written text describing the Function's arguments. Agents see this target but cannot change it. |

Normal owner saves, **Duplicate**, `connection import` and Back Up/Restore Setup keep these fields.

A Modal connection definition:

```json
{
  "origin": "https://api.modal.com",
  "allowPrivate": false,
  "enabled": true,
  "auth": {
    "type": "modal",
    "tokenIdSecret": "work#modal#token_id",
    "tokenSecretSecret": "work#modal#token_secret"
  },
  "modal": {
    "app": "text-tools",
    "function": "summarize",
    "environment": "main",
    "usage": "kwargs: {\"text\": string, \"max_words\": integer}. Returns {\"summary\": string}."
  }
}
```

The token pair is a Modal account token (ID and secret). A Modal web endpoint called over HTTPS is a different, ordinary connection that sends the endpoint's Proxy Token in the `Modal-Key` and `Modal-Secret` headers; use the **Modal web endpoint** option in the Modal template for it.

## Owner GUI

`blinddrop ui` starts an owner-only page on a loopback port and opens it in your default browser; `--no-browser` prints the URL instead and `--port` fixes the port. The page manages your vaults and connections: create, open, unlock or lock a vault; add, replace, turn off or remove typed multi-field secrets and connections; prefill a connection and its credential bundle from a template; sign in to an OAuth provider with **Save and connect**; import a compound definition; group connections; read the use log; back up a vault and change its passphrase. The page's URL carries a one-time owner token; every request needs it, the listener accepts only its own origin, and the token is never given to an agent. Passphrases you type are held in the `ui` process's memory only, as `serve` holds them. The process also runs the agent endpoint for as long as it runs ([The session](#the-session)). Quit from the page or press Ctrl-C in the terminal to stop; closing the tab alone leaves the process and its agent endpoint running.

### Vaults

A vault is one encrypted file with its own passphrase and its own lock state, and you can have several. Each vault reuses the same key derivation and authenticated encryption as before, so no new cryptography is involved. A registry at `~/.config/blinddrop/vaults.json` records each vault's name and path only — never a passphrase. Before the first vault exists, the app offers `default` at `~/.config/blinddrop/vault.enc` as a suggestion. The owner may choose a different name and location; only actual registrations are saved. Existing registered names and paths are retained; opening or creating another vault adds its name and path to the registry, and removing one only unregisters it (the file stays on disk and the default vault cannot be removed).

You unlock and lock each vault on its own. Unlocking a vault decrypts only that vault into the page's process; the others stay encrypted at rest, so a mishandled passphrase exposes one vault rather than all of your secrets. This least-privilege unlock is the reason to keep separate trust domains in separate vaults.

Because every secret reference is vault-qualified (see [Secrets and fields](#secrets-and-fields)), a connection is usable in the session only while every vault holding its referenced secrets is unlocked. Locking a vault removes just its dependent connections from the running session and leaves the rest; the session is recomputed whenever any vault is locked or unlocked.

### Screens

The page opens on one of three screens, with Settings in a window of its own. **Welcome** creates a new vault at a location you choose, or opens an existing one from the recent list. **Unlock** takes the passphrase for a configured but locked vault; `Open another vault…` opens the shared vault picker. **The vault window** has the sidebar on the left, the top-level Connections, Secrets and Activity views in the middle, and the detail pane on the right. The sidebar lists your vaults with each one's locked or unlocked state and lets you unlock, lock, create or open another. Connections show as a list or a table and can be grouped; opening a secret shows its field editor; adding a connection offers the template picker with Custom last. **Settings** has the General, Security, Sessions, Vaults and Advanced tabs.

Every launch starts locked; a vault set to Touch ID or Without asking then opens without its passphrase when an agent's call needs it or Unlock selects it at launch, Touch ID after a touch. With registered vaults, Unlock selects an explicitly requested vault first, otherwise the last successfully unlocked vault, otherwise the first existing registered vault. A selected missing vault stays visible with Locate; choose another vault to continue. First use without a registered or existing vault shows Welcome. The selector sits above the passphrase; changing it clears and conceals typed input. Return submits both the main unlock form and an additional-vault prompt. While an unlock is being committed, selection and cancellation are disabled.

Unlocking any one vault opens the workspace. Other vaults remain locked until you choose them. **Unlock multiple…** is optional: select vaults, then enter each vault's own passphrase. Each success becomes usable immediately; Skip leaves that vault locked, and Stop keeps only completed unlocks. A connection's **Unlock required vaults** action selects only its missing dependencies and returns you to that connection. Lock All ends the flow and revokes every vault regardless of its preferences.

In the Mac app, **Settings → Security** holds app defaults for sleep, screen lock and system inactivity. **Settings → Vaults → Automatic locking** lets each vault use those defaults or a Custom copy. Custom settings may be more or less restrictive and do not change when app defaults change. Choosing Use app defaults removes the override. Manual Lock All, Quit and relaunch always lock every vault. These preferences are included in setup backup/restore; they do not store passphrases or automatically unlock vaults.

**Settings → Vaults → Unlock**, in the Mac app only, chooses how each vault unlocks: **Passphrase** (the default), **Touch ID** or **Without asking**. Touch ID and Without asking need that vault unlocked; Touch ID also needs one confirming touch and is offered only on a Mac that can show the Touch ID prompt. Nothing reaches the macOS Keychain until you choose one of the two, so keeping Passphrase creates no Keychain item. The app then seals the vault's passphrase with Electron `safeStorage`, whose key the Keychain keeps, in `~/.config/blinddrop/quick-unlock.json` at mode 0600. Choosing Passphrase or removing the vault deletes it; changing the passphrase in the app, or the next successful passphrase unlock, seals the passphrase again. Creating or opening a vault under a name deletes any entry left for that name, so a new archive starts on Passphrase.

When an agent's call needs a locked Without asking vault, the app unlocks it where the call asks, with no prompt, no window and no unlock request, so it never waits on another vault; the agent's next send completes. A call that names no vault while every vault is locked unlocks every Without asking vault the same way. For what is still locked, the app shows the system Touch ID prompt for each Touch ID vault the request names, one at a time, or for a request that names no vault, for the vault the Unlock screen would select, never one whose file is missing, when it is on Touch ID. The BlindDrop window comes up only for a vault that still needs its passphrase; the page never starts a Touch ID prompt for an agent's request, except for a request that names no vault while a different Touch ID vault is selected on the Unlock screen. A Without asking unlock for an agent does not become the last unlocked or a recent vault. The Unlock screen tries on its own only when the app launches, and not when an agent's request is waiting. After Lock All, after automatic locking or in a reopened window it waits, offering **Use Touch ID**, or **Unlock** with no passphrase for a Without asking vault, so a lock holds until you or an agent asks; when its own selected vault is unlocked in the background, it moves to the workspace unless you are typing a passphrase or a prompt is open, and another vault unlocking leaves it, and the agent's request it shows, in place. A connection's unlock and **Unlock multiple…** try Touch ID and Without asking vaults before their passphrase prompts; if you open another dialog meanwhile, the unlock ends instead of covering it. An attempt that Lock All cancelled never opens a passphrase prompt, in any window. Your own Touch ID attempt counts as unlock work in progress: an agent's request waits for it, and neither its success nor an **Unlock multiple…** Touch ID or Without asking success discards a passphrase you typed for another vault. A cancelled or failed Touch ID prompt, a sealed passphrase the Keychain does not release, or one that does not open the vault falls back to the passphrase prompt with the reason. A sealed passphrase that fails is kept, because a failed decryption cannot tell a changed passphrase from a damaged archive; the next successful passphrase unlock replaces it.

Automatic locking (sleep, screen lock, idle) does not apply to a Without asking vault, because the next agent call would reopen it; Settings shows its Automatic locking as not applicable. An automatic lock closes editors and cancels unlock work only where a vault it actually locked is involved, including an **Unlock multiple…** queue that contains one, which stops as a whole; a passphrase you are typing for a vault it did not lock stays (the field is masked, and a sleep or screen lock already covers the screen). Lock All and Quit lock every vault and end every Touch ID and Without asking unlock in progress or waiting for its prompt: none of them unlocks a vault afterwards, and a prompt still waiting is not shown. A Touch ID prompt already on screen cannot be withdrawn, but a touch on it unlocks nothing. No attempt from before Lock All is joined afterwards or opens a window or a passphrase prompt. An agent still asking after Lock All opens a Without asking vault again at its next ask; a Touch ID or Passphrase vault is asked for again by a later request. Lock All also ends the launch window's own attempt. A Touch ID unlock restarts that vault's idle clock, on the wall clock, so a vault unlocked by a touch while the Mac is idle is not locked again at once (a touch on the sensor may not count as input to macOS); other unlocks follow the ordinary idle rule. A `quick-unlock.json` that cannot be read does not block the page, passphrase unlock, choosing Passphrase or removing a vault; the Touch ID and Without asking choices show as unavailable, and choosing Passphrase or removing a vault resets the file; creating or opening a vault leaves it as it is. Touch ID is a prompt in front of the sealed passphrase, not a separate key: the passphrase is as safe as the app's Keychain item, which macOS releases to the app, and in the unsigned build to any program running the same unmodified Electron release; a build with a different Electron release may ask for Keychain access again after an update; the whole app, its agent endpoint included, waits on that dialog. A Without asking vault is usable by any agent's call whenever BlindDrop runs. `blinddrop ui` and the CLI do not offer these choices.

### The session

While the app or `blinddrop ui` runs, it keeps one agent endpoint, whether or not any vault is unlocked. The endpoint starts with the process, before any unlock, and closes only when the process quits. There is no session to start or stop by hand. Agents reach the endpoint through `blinddrop agent` and `blinddrop run --app` ([Agent session](#agent-session)).

A connection is usable when it is enabled and its referenced secret fields all exist, are enabled, and resolve in a currently unlocked vault. A connection is locked when a vault it references is registered, has its file and is locked, while its references into unlocked vaults resolve. Agents still see a locked connection, marked unavailable, and calling it brings up the unlock for its vaults. A connection whose vault is unregistered or missing, or whose secret does not resolve in an unlocked vault, is not offered to agents, because no unlock can fix it; the page shows it as not in the session, with the reason.

Every owner change (a secret or connection written, turned on, turned off or removed, a passphrase change, or a vault locked or unlocked) changes what the endpoint authorizes at once, without restarting it, so hosts need no reload or reconnect. An unlock lets requests already running finish. Any other change, including a lock, Lock All, an owner edit, a backup, a port change and Quit, aborts requests running at that moment.

When an agent's call needs a locked vault, the page brings up its unlock: on the Unlock screen with that vault selected (or, when the request names no vault, the one Unlock normally selects), or in the workspace through the connection's unlock flow, with **Unlock multiple…** for several vaults. An unlock prompt you already have open, an unlock queue in progress or a passphrase you are typing is never disturbed. Cancelling the prompt stops that request from asking again; a later call asks again. The Mac app first unlocks Touch ID and Without asking vaults as described under Settings → Vaults → Unlock, then shows its main window at once if a vault still needs its passphrase; it takes keyboard focus only when none of its windows already has it, and a minimized main window stays minimized while you work in another BlindDrop window. In a browser, `blinddrop ui` shows the request at the page's next refresh, which runs every 15 seconds and when the tab gains focus, while the tab is visible and no dialog is open; if you miss the agent's 20-second wait, the agent asks again later. The passphrase is only ever typed in the page.

The app and CLI HTTP sessions share the port in Settings › Sessions. On first use, a cryptographically random port from 49152–65535 is saved in `~/.config/blinddrop/settings.json`; existing saved choices are preserved. If occupied, startup tries the next port and saves the one it binds, wrapping within the dynamic range after 65535. A lower custom port scans upward to 65535. If the app's endpoint cannot bind, the app still starts and reports the error. Change the preference in Settings, which moves the app's endpoint, or use `serve --http --port PORT` / `run --port PORT`; a nonzero override is saved after successful binding. Explicit `--port 0` chooses a temporary OS-assigned port without changing the preference.

The app's session token is replaced whenever every vault becomes locked, by any path (Lock All, locking the last vault, sleep, screen lock or inactivity), when Agent access is turned off, and at the 24-hour renewal; the old token is refused from then on, as is a token past its expiry. Unlocking, locking one of several vaults and owner edits keep the token. `blinddrop agent` reads the endpoint and token from the session file for each call, so a port change or a new token needs no host reload. A port change ends access for running `run --app` commands, whose base URL names the old port. Clients configured by hand with `serve --http` must use the URL that command reports.

While the app or `blinddrop ui` runs with Settings › Sessions › Agent access on, which is the default, the session record is written to `~/.config/blinddrop/session.json` at mode 0600 with the MCP URL, session token, expiry and the base URLs of the connections usable now (an empty map while every vault is locked). It is always in the configuration directory, whatever path the vault file has, so `blinddrop agent` and `blinddrop run --app` find it. Its location is shown in Settings › Advanced. Turning Agent access off deletes the file and replaces the session token, which ends running `run --app` commands' access; agents' calls then report that agent access is turned off instead of starting the app. Quitting deletes the file too. The CLI writes the same file only with `serve --http --session-file PATH`.

Run one of the app and `blinddrop ui` at a time: both write this file. Starting `blinddrop ui` while the app runs takes over agent access, and quitting it removes the file until the app's next lock, unlock, edit, token renewal or port change.

### Secrets and fields

A secret has a type and one or more named fields. Choosing a type in the field editor prefills the fields that type usually needs — for example an `aws` secret starts with an access-key id and a secret access key, a `login` with a username and password, a `tls` bundle with a certificate and private key — and you can edit labels and values, remove fields or add custom fields, with no fixed count of custom fields beyond the archive and request size limits. Existing field IDs are read-only so editing a label does not break connections; new field IDs are chosen before saving. The built-in types are `api-key`, `login`, `keypair`, `aws`, `tls`, `oauth`, `jwt` and `custom`. New Secret also offers each template's provider bundle as a type, with the same fields that template's connection sheet uses; see [Connection templates](#connection-templates). Each field records a human label, whether it is masked (concealed, like a password or token) or shown (like an access-key id), and whether it is multiline (a PEM block, whose exact bytes are kept). Replacing a secret keeps the value of any field you leave blank.

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

Adding a connection starts from a template rather than a blank form. A template, also called a recipe, is a static prefill — the provider's HTTPS origin, its authentication mechanism and placement, its fixed configuration, and the credential bundle it needs — so picking one creates the connection and the shaped secret in a couple of steps. Templates are static configuration bundled with BlindDrop and read by the page from its owner API, not per-vendor code in the runtime or a downloaded catalogue: the request path still uses the generic authentication mechanisms, with Modal's official SDK as the one exception, and there is no runtime provider catalogue. Custom is the explicit fallback, listed last, for anything without a template.

The picker has 25 choices:

- **Popular:** Fly.io, Anthropic, GitHub (personal access token), GitHub (OAuth app), Stripe, AWS (SigV4), AWS KMS, AWS SES, Google APIs.
- **More:** OpenAI, Postmark, Twilio, Dropbox, Cloudflare R2, DigitalOcean Spaces, Telegram Bot, Backblaze B2 (S3), Tigris, Together AI, Makora, Modal, AgentMail, Vast.ai, Lambda Cloud.
- **Custom**, last.

The Modal sheet also offers **Modal web endpoint** for an HTTPS web endpoint protected by a Proxy Token. A Tigris connection serves one bucket: Tigris buckets created after 19 February 2025 accept only virtual-hosted requests, so the template builds the origin `https://<bucket>.t3.storage.dev` from the bucket you enter, and another bucket needs its own connection. Its example lists up to 10 objects (`GET /?list-type=2&max-keys=10`). Twilio uses an API key SID and secret as the Basic username and password. With the Account SID as the username, Twilio echoes that SID in every response, so BlindDrop withholds those responses with `RESPONSE_BLOCKED`. The Google APIs template uses the Google API host you choose; any `https://<api>.googleapis.com` origin keeps its guidance. Its Drive example is schematic, because other Google APIs use their own documented paths.

New Connection and New Secret share each template's credential bundle. Its fields have one of three roles: a **credential** is consumed by the connection's authentication; **metadata**, such as a key name or recovery code, is stored but never sent; a **note** is a stored copy of a configuration value, such as an endpoint, and is labeled as a note because it never changes what the connection does. A secret saved before 0.6.2 keeps its generic type, such as `aws`; when it holds a template bundle's required credential fields, the editor still labels that bundle's note fields as notes, without changing the type or adding fields. Endpoint, region, signing service, OAuth scopes and the Modal target are set in the connection sheet; edit them with **Edit connection…**. Account-specific endpoints and regions must be entered: an example value is not a completed setup. A credential pair is saved as one typed secret in the selected vault, and an existing field can be selected instead of storing it twice. After saving a bundle from New Secret, **Create connection…** opens the connection sheet with it selected; a stored bundle alone is not a usable service. When editing, fields show as set, a blank input keeps the stored value, and stored values are never shown.

The page checks the whole form, including the lowercase field-id rule, before it writes anything. A failed save is shown in the open sheet and keeps what you entered. If a save involves several writes and only some succeed, the sheet says exactly what was saved — the credential bundle, the connection or its groups — and saving again completes the rest without duplicating it. Nothing is rolled back; Cancel after a partial save does not undo it.

A connection created from a template records the template's id as `recipe`. Its saved details and the guidance agents receive from `list_connections` come from the same template, so they agree. Connections without a recognized id — older connections, Custom, `connection set`, and connections edited so they no longer match their template — get generic guidance. BlindDrop never guesses a provider from a connection's name or origin.

**Test**, in a connection's details, sends its template's example request through BlindDrop as an agent's request is sent, so it also appears under Recent use and in Activity, and shows the provider's HTTP status with its short error message, or BlindDrop's error if the request could not be made. A non-2xx status is the provider's answer, not a verdict: a valid key without permission for the example, such as a least-privilege AWS key, answers 403. The test also runs after the connection is saved, and after a secret is saved for each connection using it, with a notice naming any that did not answer 2xx; saving never depends on it. Only templates with a concrete example have Test, so Custom, schematic templates and Modal do not.

A template can only use a mechanism BlindDrop already implements. A provider that needs something else is flagged rather than faked — for example Backblaze's native B2 authorization returns a dynamic API host the fixed-origin runtime cannot follow, so its template uses Backblaze's S3-compatible endpoint with AWS SigV4 instead.

### Settings

Settings are stored in `~/.config/blinddrop/settings.json` at mode 0600 and read and written through the page, because the page's origin changes with its loopback port on every launch.

| Field | Type and default | Effect |
|---|---|---|
| `appearance` | `"system"`, `"light"` or `"dark"`; default `"system"` | Page and native Mac appearance |
| `sessionPort` | integer 1–65535; random 49152–65535 on first use | Saved preferred port for app and CLI HTTP sessions; advances if occupied |
| `sessionFile` | boolean; default true | Agent access: write the session file while the app or `ui` runs. Turning it off deletes the file and replaces the session token, ending running `run --app` commands' access, and agents' calls report that agent access is turned off |
| `lockOnSleep` | boolean; default true | App only: default for locking when the computer sleeps |
| `lockOnScreenLock` | boolean; default false | App only: default for locking when the screen locks |
| `idleLockMinutes` | 0, 1, 5, 15, 30 or 60; default 0 (Off) | App only: default inactivity timeout; runs even with no window open |
| `vaultLockPolicies` | vault-name map; default `{}` | App only: complete per-vault custom sleep, screen-lock and idle settings; absent entries inherit app defaults |
| `openAtLogin` | boolean; default false | App only: open at login |
| `showDockIcon` | boolean; default true | App only: show the Dock icon; hiding it keeps the menu-bar item available |
| `lastVault` | path or null | Vault opened at the next start |
| `recentVaults` | up to 10 paths, newest first | The Welcome screen's list of vaults to open |
| `lastBackupAt` | timestamp or null | Shown in Settings › Vaults |
| `ui` | object of at most 4 KiB | The page's own view state |

### Groups

Groups are owner-side labels for connections. The encrypted archive does not store them and agents never see them: they live in a `<config dir>/groups.json` file at mode 0600 keyed by connection name, shared across vaults. Old `vault#connection` keys migrate when their archive is unlocked. Rename or remove a group from its connection-list header. Renaming preserves memberships; removing a group keeps its connections and secrets. Group names obey the same rules as other local names; at most 64 groups, and at most 16 groups per connection.

### Activity and backups

The owner page writes and reads `~/.config/blinddrop/vault.enc.events.jsonl` for every session, including when only another vault is unlocked. CLI sessions use `<vault-path>.events.jsonl`, as described under [Replace, disable, and back up](#replace-disable-and-back-up), taking a bounded tail of the file rather than all of it and showing the newest events first. Clearing it from the page truncates that file. **Export Encrypted Vault** copies the encrypted archive byte for byte to a path you choose; it refuses a path that already exists, so a backup never overwrites one, and records the time in Settings › Vaults.

**Back Up Setup** creates a new folder containing every registered encrypted archive, `vaults.json`, `connections.json`, `groups.json` and `settings.json`. Archives retain their own passphrases. The other files are plaintext metadata and references, protected by owner-only file permissions; they contain no stored credential values. The live session file, the Activity log and the Mac app's `quick-unlock.json` are excluded. A missing or unreadable registered archive fails the whole backup, without publishing a partial folder. While the backup collects its files, agent requests running at that moment are aborted, and new agent calls fail with `BUSY` without bringing up an unlock.

**Restore Setup** is available on Welcome before creating or opening a vault. It validates the folder, copies archives into fresh app configuration, rebases their registered paths and starts locked. A fresh installation containing only preferences is allowed; the backup replaces those preferences. Existing archives, registrations, connections, groups or unknown files prevent restore. BlindDrop's own session file and staged `integrations/` folder do not count, and restore keeps `integrations/`. A `quick-unlock.json` does not count either; restore deletes it, so every restored vault starts on Passphrase. Restore works while the app runs, provided no vault is unlocked; afterwards the app applies the restored session port and Agent access setting as a Settings change does. It refuses existing data rather than overwriting or merging it. Unlock each required vault with its existing passphrase to use its connections. If a registered vault file is missing, choose Locate file and select its original file or an encrypted backup. Its name and connection references are preserved, and the located file requires an explicit unlock. Encrypted-envelope shape can be checked while locked; authentication and payload integrity are checked on unlock.

### Browser and app

In the browser, the page draws its own menu bar — app, File, Edit, View, Window and Help — because those menus are the only way to reach Settings, About, the shortcut list and `Open vault…` there. Where the app opens a file dialog, the browser page takes a path in a text field.

The macOS app supplies its own runtime and hosts the same server and page in its own window. Normal installation needs no Node, global CLI, terminal or PATH changes. Closing its window keeps the app and current session running; Dock or menu-bar Open recreates one window. Lock All works with Settings focused or no window, and Quit ends the session. Every launch starts locked; a vault set to Touch ID or Without asking then opens without its passphrase when an agent's call needs it or Unlock selects it at launch, Touch ID after a touch. It adds the native application menu, system file dialogs for creating, opening and backing up a vault, `Reveal in Finder` for the vault and the use log, locking when the computer sleeps or the screen locks, and opening at login. Linux and Windows can use the browser interface where independently verified; the Mac app does not establish those platforms' compatibility.

## Agent session

With the app or `blinddrop ui`, a host runs `blinddrop agent` as a stdio MCP server. The app's managed integration configures it for Claude Code and local Codex, launching it from the runtime bundled in the app. For another host with the CLI installed:

```json
{
  "mcpServers": {
    "blinddrop": {
      "command": "blinddrop",
      "args": ["agent"]
    }
  }
}
```

`blinddrop agent` takes no connection list, port or token:

- It answers the MCP handshake and tool list itself, so the host's first connection never depends on the app. It exits only when the host closes its input; every failure is a tool result.
- It reads the app's session file for each call, forwards the call to the app's endpoint and returns the app's result unchanged. When the host cancels a call, it closes that call's connection, which aborts the request.
- When a call needs a locked vault, the app answers `VAULT_LOCKED` and brings up its unlock. `blinddrop agent` sends the same call again every second for up to 20 seconds, stops at once when the host cancels, and then returns the last result. Nothing is sent upstream while the vault is locked, so this never runs a request twice.
- When the app is unreachable (no session file, or its endpoint refuses the connection) before the call has first reached it, it reports that agent access is turned off if Agent access is off. Otherwise, running from the app's bundled runtime, it starts the app in the background and waits up to 8 seconds for its endpoint, or reports "BlindDrop's agent endpoint did not start within 8 seconds". Run from the CLI, it reports "BlindDrop is not running".
- Once a call has reached the app, a later connection failure (for example quitting the app during the unlock wait) ends the call with its last result; nothing is started or sent again.
- It sends a call again only when the app cannot have acted on it: the connection failed before the request was written and before the call first reached the app, the app refused a token that the session file has since replaced, or the call got `VAULT_LOCKED` within the 20-second wait. Any other failure after the request was written, including a timeout or a reset, is returned and never sent again; its outcome may be unknown.
- Each send ends within the app's own 30-second request limit, so the longest call takes about 58 seconds: up to 8 to start the app, 20 waiting for an unlock and 30 for the request.

Commands that agents run use `blinddrop run --app` ([client guide](CLIENTS.md#commands-that-agents-run)).

Without the app, configure a terminal-launched stdio MCP client to use the installed executable. Replace the example path with the result of `command -v blinddrop`:

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

A headless host without a controlling terminal must supply owner input through inherited descriptors. Global `--password-fd 3` reads the passphrase from descriptor 3; `secret set ... --secret-fd 4` can similarly read a value. The trusted launcher must create and pass those descriptors: adding their numbers to MCP JSON alone does not create the input. Input is bounded UTF-8, read to EOF, with one trailing newline removed; descriptors close after use. No passphrase environment variable or plaintext cache is provided. Alternatively, start `serve --http` in your terminal and attach the headless host using the temporary session token ([HTTP setup](CLIENTS.md#attach-an-independently-launched-mcp-host)). With the app or `blinddrop ui` running, a host needs neither: it attaches through `blinddrop agent` above, with no unlock in advance. Use `serve --http` in your terminal for a host you configure by hand without the app.

The server exposes exactly three tools: `list_connections` for permitted connections and their usage, `execute_http` for HTTPS requests, and `invoke_modal_function` for [Modal Functions](#modal-functions).

`list_connections` takes no arguments and returns `{ "connections": [...] }`. With the app or `blinddrop ui`, while at least one vault is unlocked, it lists every enabled connection that is usable or locked ([The session](#the-session)). While every vault is locked it returns `VAULT_LOCKED` and brings up the unlock; with no vault registered yet it returns an empty list. When vaults are registered but none of their files exists and none is unlocked, tool calls and SDK requests return `VAULT_NOT_FOUND` and bring up no unlock; connections of only some missing vaults are left out of the list. If the app cannot work out current access, for example because an unlocked vault's file has moved or `connections.json` is unreadable, tool calls and SDK requests return that failure's error, never an empty listing, and bring up no unlock; the owner page shows the error. CLI `serve` lists the connections available to its session, all marked available. Each item has these fields:

| Field | Meaning |
|---|---|
| `name`, `origin`, `authType` | The connection name, its HTTPS origin and its authentication type |
| `recipe` | The id of the connection's template, or `null` for generic guidance |
| `tool` | The tool to call for this connection: `execute_http` or `invoke_modal_function` |
| `summary` | One line describing what the connection is for |
| `example` | A complete input for `tool`, naming this connection |
| `schematic` | `true` when `example` contains placeholders such as `<bucket>`, or is not a documented provider operation |
| `notes` | Usage notes, such as required headers, permissions or inputs |
| `target` | Modal connections only: the fixed `app`, `function`, `environment` and optional `usage` |
| `available` | `true` when the connection can be used now; `false` when a vault it needs is locked |
| `reason` | `"locked"` when `available` is `false` |

The example names the connection; its account, region or bucket is already in the connection's origin, and for an AWS SigV4 connection the summary states the signing region and service. Values that depend on the task, such as a bucket, key ID or sender, stay placeholders. Listing never reads a vault: items contain no stored values, field labels, stored notes, vault names, secret references, client IDs or token IDs. A locked connection carries the same guidance as a usable one.

`execute_http` example request:

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

Results contain `status`, `headers`, and a UTF-8 `body` by default. Set `responseEncoding: "base64"` to receive binary bytes as base64 with `bodyEncoding: "base64"`. This still checks the decoded response for credential material before returning it. Base64 and MCP JSON add size overhead; the request/response byte limits below apply to the HTTP data. Broker errors contain static `error.code` and `error.message` fields with MCP `isError: true`. `SECRET_INVALID` means the connection's stored credential cannot be sent as stored (for example, a stray character pasted with it); nothing was sent, and the owner re-enters it in BlindDrop. `UNSUPPORTED_OPERATION` means the connection does not support the tool that was called — for example `execute_http`, or the SDK base-URL endpoint, with a Modal connection; call `list_connections` and use the connection's `tool`. `VAULT_LOCKED` (HTTP 423 on the HTTP endpoint) means the call needed a locked vault: BlindDrop brought up its unlock and sent nothing upstream. Through `blinddrop agent` it arrives only after the 20-second wait; continue other work and call again later. An unknown, disabled or unresolvable connection keeps its existing error and brings up nothing. Agent tools cannot read secrets or perform owner administration.

### Modal Functions

`invoke_modal_function` calls the one deployed Modal Function the owner fixed in the connection's `modal` target, using Modal's official JavaScript SDK inside BlindDrop. The agent supplies only the connection name and JSON arguments:

```json
{
  "connection": "text-tools",
  "args": [],
  "kwargs": { "text": "BlindDrop keeps credentials opaque.", "max_words": 12 }
}
```

`args` is an optional array of positional arguments and `kwargs` an optional object of keyword arguments. A successful call returns the Function's JSON return value:

```json
{ "result": { "summary": "Credentials stay opaque." } }
```

The agent cannot choose another app, deployment, environment, credential, SDK method or network endpoint. The tool describes the call, not the Function's signature: take the arguments from the target's `usage`, the task or the application's code, and otherwise ask the owner.

Each request makes exactly one invocation (`spawn`, then a wait for its result) and BlindDrop never repeats it, including after a timeout, transport error or cancellation. `TIMEOUT` and `UPSTREAM_ERROR` mean the Function may still have run. The SDK can retry its own control-plane calls, so exactly-once execution is not promised. A result that is not JSON fails with `UNSUPPORTED_RESPONSE`. The complete result is checked for the token pair and the session token before release. Locking a required vault, Lock All, Quit or the end of the session stops waiting immediately, discards a late result and asks Modal to cancel the call; work already done remotely is not undone.

BlindDrop keeps one SDK client per Modal connection for the session. The SDK cannot close its gRPC channel, so the channel closes after gRPC's idle timeout. Three limits of the pinned SDK (`modal` 0.11.1) remain:

- The target Function must be deployed with Modal's Python SDK 1.2 or later. The JavaScript SDK sends CBOR arguments and cannot read pickled results, so against an older deployment every call fails with `UPSTREAM_ERROR` and nothing is submitted. Redeploy the Function with Python SDK 1.2 or later.
- Arguments larger than the SDK's 8 KiB inline size are uploaded, and results larger than 2 MiB are downloaded, by SDK transfers that cannot be aborted. After a lock, Lock All, Quit or the deadline, BlindDrop stops waiting and discards the result immediately, but such a transfer can finish in the background.
- Calls on one Modal connection share the SDK's auth-token fetch. If one call is cancelled during the session's first token fetch, a concurrent call on the same connection can fail with `UPSTREAM_ERROR` before anything is spawned. That failure is never reported as success, and nothing is replayed.

BlindDrop passes the token pair and environment from the connection to the SDK, so a local Modal profile or `MODAL_TOKEN_ID`/`MODAL_TOKEN_SECRET` never supplies credentials. If `MODAL_SERVER_URL` or the active profile's `server_url` is set to anything other than Modal's default service, `https://api.modal.com:443` or `https://api.modal.com`, the call fails with `DESTINATION_DENIED`. The SDK uses its own gRPC transport and may transfer large payloads itself; that traffic does not go through BlindDrop's HTTPS sender or its address pinning. Activity records the connection, operation, outcome and error code, without an HTTP status, arguments or result.

## Replace, disable, and back up

Changes made in the app or `blinddrop ui` apply to agents at once ([The session](#the-session)). A CLI helper (`serve`, or `run` without `--app`) keeps the snapshot it opened: stop it before changing credentials or connections from the CLI, then start a new one. Editing the archive does not revoke a running CLI helper.

```sh
blinddrop secret set work-key
blinddrop secret disable work-key
blinddrop connection disable work-api
blinddrop passwd
```

`secret set` replaces and enables a secret; `connection set` replaces and enables a connection. `connection import` uses the definition's explicit `enabled` value. `secret remove NAME` removes an unreferenced secret and rejects removal while a connection references it. `list` shows metadata only.

`passwd` unlocks with the old passphrase, prompts for and confirms the new one, then atomically re-encrypts the archive. A trusted launcher can supply `--password-fd 3 passwd --new-password-fd 4`. Existing helpers must be stopped first; backups retain their original passphrase.

Copy an encrypted archive to back up its secrets, and unlock a restored copy with the same passphrase. For complete app recovery, use **Back Up Setup** and **Restore Setup** as described above; the folder retains connection definitions, registry, groups and settings and restore rebases vault paths. For a standalone CLI archive, copy its `<vault-path>.connections.json` sidecar to the matching path beside the restored archive. **Export Encrypted Vault** copies only the selected encrypted archive, not the separate configuration. There is no passphrase-recovery bypass. Use events are appended to `<vault-path>.events.jsonl`, containing timestamp, grant identifier, known connection name, operation (`execute_http`, which includes the SDK base-URL route, or `invoke_modal_function`), broker outcome, error code, and HTTP status for completed exchanges; Modal invocations have no HTTP status. Broker completion does not imply provider success: the UI shows HTTP 401 or HTTP 500 as an error result. Historical entries without HTTP status are shown as Completed. Request bodies, query values, and credentials are excluded. It is a local diagnostic log, not an audit ledger or automatically rotated archive. A log append failure produces a static warning while preserving the request's actual result.

## Limits

BlindDrop supports the HTTPS mechanisms above, JSON/form/text/XML, REST/GraphQL payloads, multipart and binary. Browser session automation, device authorization, other signing/challenge protocols, native database/SSH protocols and WebSocket remain outside it. gRPC is outside it except the bounded [Modal Function](#modal-functions) invocation through Modal's official SDK. Ordinary HTTP/SSE streaming is available through the SDK endpoint. Default responses must be valid UTF-8; explicit base64 mode preserves binary bytes. Identity, gzip, deflate and Brotli content encodings are handled; unsupported encodings fail explicitly.

Buffered MCP requests are capped at 1 MiB including target, headers, and body; headers at 16 KiB; responses at 4 MiB before and after decompression. Up to four requests run concurrently, each with a 30-second total timeout. MCP input is capped at 2 MiB. SDK requests are capped at 16 MiB, responses at 64 MiB before and after decompression, with a ten-minute total timeout and the same four-operation cap. The CLI does not expose limit tuning. MCP returns redirects without following them; the SDK endpoint rejects redirects so the client stays within its connection. BlindDrop never retries ambiguous failures. A Modal invocation reuses the buffered limits: 1 MiB of input, 4 MiB of returned JSON, 30 seconds, and the same four-operation cap.

A complete bounded MCP response is checked for used secret values and constructed credential representations before release. The SDK endpoint inspects incremental bytes while withholding enough tail to detect split credentials. A late failure truncates delivery; already delivered safe bytes remain visible. This is explicitly different from buffered all-or-nothing delivery. Cookies are always discarded. Very short or common credential values can conservatively block unrelated response text that happens to contain them. The intended API receives the credential and must be trusted: direct-reflection checks cannot defeat arbitrary transformations by a malicious recipient. Credential opacity does not prevent misuse of an authorized API action. An unrestricted agent is outside the assumed harness restrictions; BlindDrop does not detect or police that mode.
