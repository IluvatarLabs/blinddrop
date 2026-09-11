# Use Fly.io through BlindDrop

This workflow lists your apps using Fly's existing Machines API. The vault
and helper run on your computer; nothing is deployed on Fly. Fly needs no
integration with BlindDrop.

## Owner setup

If you already have a `fly` connection in your vault, skip to the next section.
Otherwise, initialize the vault once (`blinddrop init`) and create a read-only
Fly token in your own terminal:

```sh
flyctl tokens create readonly --org personal \
  --name blinddrop-first-use --expiry 1h
blinddrop secret set fly-readonly
blinddrop connection set fly \
  --origin https://api.machines.dev \
  --auth header --field Authorization --secret fly-readonly
```

Substitute your organization for `personal`. The Fly command displays a
complete Authorization value beginning with `FlyV1 `. Paste that **whole
value** at BlindDrop's hidden `Secret value:` prompt, after the archive
passphrase prompt. Named-header authentication sends it unchanged. Do not
paste it into chat, source code, or client configuration.

The one-hour expiry above is suitable for a first check. Choose a lifetime
appropriate for ongoing use through Fly's existing token controls. The saved
entry persists in `~/.config/blinddrop/vault.enc` after the helper exits;
provider expiry/revocation is independent of that storage. Static Fly tokens
are not automatically renewed by BlindDrop. Replace one with `secret set`
and start a new helper after stopping the old one.

## Read your apps now

From the source checkout:

```sh
blinddrop run fly -- node examples/request.mjs '/v1/apps?org_slug=personal'
```

Unlock at the normal owner prompt. The child receives a local URL and
short-lived BlindDrop session token, never the stored Fly token. A successful
response has status 200, `apps` and `total_apps`. The helper closes when the
command exits. With the README's global user installation, the example is
also at `~/.local/lib/node_modules/blinddrop/examples/request.mjs`.

For another useful read, use `/v1/apps/APP_NAME`. These requests do not deploy,
restart, or change apps. The permissions attached to the Fly token govern
what the API allows.

## Use an agent

Start an HTTP MCP session in your terminal:

```sh
blinddrop serve --http --allow fly --ttl 3600
```

Unlock once, then configure the MCP host with the printed `mcpUrl` and token
as described in [Client setup](CLIENTS.md#attach-an-independently-launched-mcp-host).
An existing terminal stdio host may instead launch
`blinddrop serve --allow fly --ttl 3600`. In either case, the tool call is:

```json
{
  "connection": "fly",
  "method": "GET",
  "path": "/v1/apps",
  "query": { "org_slug": "personal" }
}
```

Ask the agent to report the status, count and app names. No token is included
in the prompt or tool arguments. Ctrl-C in the owner HTTP terminal or session
expiry revokes the helper session. The archive retains the credential for
later owner-unlocked sessions.

## Verified use and references

This read-only app listing has been exercised against a real Fly account through both the stdio helper and `run`. Controlled receiver checks and live provider checks are separate evidence layers; [CHANGELOG.md](CHANGELOG.md) states which providers have been exercised live.

- [Machines API authentication](https://fly.io/docs/machines/api/working-with-machines-api/)
- [List apps](https://docs.machines.dev/apps/Apps_list)
- [Read-only token command](https://fly.io/docs/flyctl/tokens-create-readonly/)
- [Token management and revocation](https://fly.io/docs/security/tokens/)
- [FlyV1 header formatter](https://github.com/superfly/macaroon/blob/v0.3.2/format.go#L100-L104)
