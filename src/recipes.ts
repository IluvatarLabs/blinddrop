// Bundled static provider recipes: configuration and guidance over the generic
// authentication mechanisms in src/auth.ts. No runtime per-vendor code, no
// fetched catalogue. The owner page reads RECIPES through its owner API; the
// broker derives agent usage guidance from the same data.

import type {
  Authentication,
  Connection,
  ConnectionGuidance,
} from "./types.js";
import { MODAL_ORIGIN } from "./vault.js";

export interface RecipeField {
  /** Vault field id: /^[a-z][a-z0-9_]{0,63}$/. */
  id: string;
  /** Display label; keeps provider capitalization. */
  label: string;
  masked: boolean;
  multiline: boolean;
  /**
   * credential: consumed by an auth slot. metadata: stored information that is
   * never sent. note: a stored copy of operative configuration, never operative.
   */
  role: "credential" | "metadata" | "note";
  optional: boolean;
  hint?: string;
}

export interface RecipeConsent {
  issuer: string;
  authorizationEndpoint: string;
  authorizationParameters: Record<string, string>;
  /** True when the provider requires the exact registered callback port. */
  fixedPort: boolean;
  /** Callback registration instructions shown before consent. */
  registration: string;
  /** Scope guidance; the owner chooses the actual scope. */
  scopeHint?: string;
  /** True when the provider rejects an authorization request without a scope. */
  scopeRequired?: boolean;
}

export interface RecipeUsage {
  summary: string;
  /** Tool input without `connection`; connectionGuidance adds it. */
  example: Record<string, unknown>;
  schematic: boolean;
  notes: string[];
}

export interface Recipe {
  /** Stable id: /^[a-z][a-z0-9-]{0,31}$/. Persisted in connection definitions. */
  id: string;
  name: string;
  /** Picker section. Custom is the single "custom" entry and is always last. */
  group: "popular" | "more" | "custom";
  /** Not a picker card; reachable from another recipe's sheet. */
  hidden?: boolean;
  /** Card subtitle: the credentials this service needs. */
  needs: string;
  /** Inline guidance in the connection sheet. */
  guide: string;
  /** A fixed HTTPS origin; "" when derived from originTemplate or owner-entered. */
  origin: string;
  /** With `origin`: the owner chooses the API host, so any HTTPS origin on this host suffix also matches. */
  originSuffix?: string;
  /** `{region}` binds to auth.region; `{account}` and `{bucket}` are owner input that only compose the origin. */
  originTemplate?: string;
  /** Default authentication configuration; never a secret reference. */
  auth: { type: Authentication["type"] } & Record<string, unknown>;
  /** Auth keys whose saved values must equal `auth` for the recipe to apply. */
  fixed: string[];
  /** Auth slot key (for example "accessKeyIdSecret") or "tls.<key>" -> bundle field id. Only listed slots appear. */
  slots: Record<string, string>;
  /** The reusable credential bundle; `type` is the stored secret type. */
  bundle: { type: string; fields: RecipeField[] };
  consent?: RecipeConsent;
  /** Modal recipes only: the default environment shown in the sheet. */
  modal?: { environment: string };
  usage: RecipeUsage;
}

const CUSTOM_ID = "custom";

const AUTH_NOTE = "BlindDrop adds the authentication. Do not send credential headers yourself.";

function field(
  id: string,
  label: string,
  role: RecipeField["role"],
  masked: boolean,
  optional: boolean,
  hint?: string,
): RecipeField {
  return { id, label, masked, multiline: false, role, optional, ...(hint === undefined ? {} : { hint }) };
}

/** A credential consumed by a required slot. */
function required(id: string, label: string, masked: boolean): RecipeField {
  return field(id, label, "credential", masked, false);
}

function optionalCredential(id: string, label: string, masked: boolean, hint: string): RecipeField {
  return field(id, label, "credential", masked, true, hint);
}

function metadata(id: string, label: string, masked: boolean, hint?: string): RecipeField {
  return field(id, label, "metadata", masked, true, hint);
}

/** The refresh grant an OAuth recipe's consent fills. */
function refreshToken(): RecipeField {
  return optionalCredential(
    "refresh_token",
    "Refresh token",
    true,
    "Filled by Save and connect. Paste one only to import an existing grant.",
  );
}

const AWS_SLOTS = {
  accessKeyIdSecret: "aws_access_key_id",
  secretAccessKeySecret: "aws_secret_access_key",
  sessionTokenSecret: "aws_session_token",
};

// The generic AWS access-key archetype fields, shared by the AWS, KMS and SES recipes.
function awsFields(): RecipeField[] {
  return [
    required("aws_access_key_id", "Access key ID", false),
    required("aws_secret_access_key", "Secret access key", true),
    optionalCredential("aws_session_token", "Session token", true, "Only for temporary credentials."),
  ];
}

const S3_KEY_SLOTS = {
  accessKeyIdSecret: "aws_access_key_id",
  secretAccessKeySecret: "aws_secret_access_key",
};

function s3KeyFields(idLabel: string, secretLabel: string): RecipeField[] {
  return [
    required("aws_access_key_id", idLabel, false),
    required("aws_secret_access_key", secretLabel, true),
  ];
}

// ListObjectsV2 with path-style addressing on the fixed service origin.
function s3ListExample(): Record<string, unknown> {
  return { method: "GET", path: "/<bucket>", query: { "list-type": "2", "max-keys": "10" } };
}

const S3_BUCKET_NOTE = "<bucket> is a request input from the task or the owner; object keys go after it in the path.";
const S3_WRITE_NOTE = "Deleting or overwriting objects cannot be undone; confirm with the owner first.";

function githubUserExample(): Record<string, unknown> {
  return {
    method: "GET",
    path: "/user",
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "blinddrop-agent",
    },
  };
}

const GITHUB_USER_AGENT_NOTE =
  "GitHub rejects requests without a User-Agent header, and BlindDrop does not add one; send it on every request.";

export const RECIPES: readonly Recipe[] = [
  // https://docs.fly.io/machines/api/apps-resource
  {
    id: "fly",
    name: "Fly.io",
    group: "popular",
    needs: "Complete FlyV1 Authorization value",
    guide: "Paste the complete Authorization value beginning with FlyV1, not only the token body.",
    origin: "https://api.machines.dev",
    auth: { type: "header", name: "Authorization" },
    fixed: ["name"],
    slots: { secret: "token" },
    bundle: { type: "fly", fields: [required("token", "Complete FlyV1 value", true)] },
    usage: {
      summary: "Fly Machines API: apps, Machines and volumes.",
      example: { method: "GET", path: "/v1/apps", query: { org_slug: "<org-slug>" } },
      schematic: true,
      notes: [
        "org_slug is required: the organization slug from the task or the owner. Fly's documented example uses personal.",
        "Creating, updating or deleting apps and Machines changes running infrastructure and can be billed; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://platform.claude.com/docs/en/api/overview and /docs/en/manage-claude/authentication
  {
    id: "anthropic",
    name: "Anthropic",
    group: "popular",
    needs: "API key",
    guide: "Paste an API key from the Claude Console. It is sent in the x-api-key header.",
    origin: "https://api.anthropic.com",
    auth: { type: "header", name: "x-api-key" },
    fixed: ["name"],
    slots: { secret: "api_key" },
    bundle: { type: "anthropic", fields: [required("api_key", "API key", true)] },
    usage: {
      summary: "Claude API: models, messages, batches and files.",
      example: { method: "GET", path: "/v1/models", headers: { "anthropic-version": "2023-06-01" } },
      schematic: false,
      notes: [
        "Send anthropic-version on every request; JSON bodies also need content-type: application/json.",
        "A key that is not scoped to one workspace must also send anthropic-workspace-id; a workspace-scoped key works only in its own workspace.",
        "Message and batch requests are billed per token.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
  {
    id: "github",
    name: "GitHub (personal access token)",
    group: "popular",
    needs: "Personal access token",
    guide: "Paste a fine-grained or classic personal access token. To sign in with an OAuth app instead, choose GitHub (OAuth app).",
    origin: "https://api.github.com",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "token" },
    bundle: { type: "github", fields: [required("token", "Personal access token", true)] },
    usage: {
      summary: "GitHub REST API as the token's user.",
      example: githubUserExample(),
      schematic: false,
      notes: [
        GITHUB_USER_AGENT_NOTE,
        "The token's scopes or fine-grained permissions limit what each request can read or change.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
  {
    id: "github-oauth",
    name: "GitHub (OAuth app)",
    group: "popular",
    needs: "OAuth app client ID + secret, then sign-in",
    guide: "Enter the OAuth app's client ID and client secret, then Save and connect to sign in. The connection is added after GitHub returns a refresh token.",
    origin: "https://api.github.com",
    auth: {
      type: "oauth2",
      grant: "refresh_token",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      clientAuth: "body",
      scope: "read:user offline_access",
    },
    fixed: ["tokenEndpoint", "grant"],
    slots: { clientIdSecret: "client_id", clientSecret: "client_secret", refreshSecret: "refresh_token" },
    bundle: {
      type: "github-oauth",
      fields: [
        required("client_id", "Client ID", false),
        required("client_secret", "Client secret", true),
        refreshToken(),
      ],
    },
    consent: {
      issuer: "https://github.com/login/oauth",
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      authorizationParameters: {},
      fixedPort: false,
      registration: "Add http://127.0.0.1/oauth/callback to the OAuth app's callback URLs, keeping any callback URL another application uses. GitHub accepts any loopback port for it.",
      scopeHint: "Keep offline_access so GitHub returns a refresh token; if sign-in reports none, enable expiring user tokens for the OAuth app. Add only the scopes the task needs.",
    },
    usage: {
      summary: "GitHub REST API as the user who signed in.",
      example: githubUserExample(),
      schematic: false,
      notes: [
        GITHUB_USER_AGENT_NOTE,
        "Requests act as the user who granted consent, limited to the granted scopes.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.stripe.com/api/authentication and https://docs.stripe.com/api/balance/balance_retrieve
  {
    id: "stripe",
    name: "Stripe",
    group: "popular",
    needs: "Secret or restricted key",
    guide: "Paste a secret (sk_) or restricted (rk_) key; it is sent as the Basic username with an empty password. The publishable key and backup code are stored only.",
    origin: "https://api.stripe.com",
    auth: { type: "basic" },
    fixed: [],
    slots: { usernameSecret: "secret_key" },
    bundle: {
      type: "stripe",
      fields: [
        required("secret_key", "Secret key", true),
        metadata("publishable_key", "Publishable key", false),
        metadata("backup_code", "Backup code", true),
      ],
    },
    usage: {
      summary: "Stripe API with the configured secret or restricted key.",
      example: { method: "GET", path: "/v1/balance" },
      schematic: false,
      notes: [
        "A restricted key needs Balance read permission for this example; other endpoints need their own permissions.",
        "POST bodies are form-encoded (application/x-www-form-urlencoded).",
        "Charges, refunds, payouts and transfers move money; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
  {
    id: "aws",
    name: "AWS (SigV4)",
    group: "popular",
    needs: "Access key ID + secret access key",
    guide: "Defaults call STS in us-east-1. For KMS or SES choose those presets; for another AWS API set its endpoint, region and service.",
    origin: "https://sts.us-east-1.amazonaws.com",
    auth: { type: "aws-sigv4", region: "us-east-1", service: "sts" },
    fixed: ["service"],
    slots: AWS_SLOTS,
    bundle: { type: "aws", fields: awsFields() },
    usage: {
      summary: "AWS STS Query API, signed with SigV4.",
      example: {
        method: "POST",
        path: "/",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "Action=GetCallerIdentity&Version=2011-06-15",
      },
      schematic: false,
      notes: [
        "GetCallerIdentity returns the caller's account and ARN and needs no IAM permission.",
        "Other STS actions use the same form body with their own Action and parameters.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.aws.amazon.com/general/latest/gr/kms.html and https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
  {
    id: "aws-kms",
    name: "AWS KMS",
    group: "popular",
    needs: "Region + access key pair",
    guide: "Enter the region that holds your KMS keys; the origin is https://kms.<region>.amazonaws.com and the signing service is kms. Key IDs are request inputs, not credentials.",
    origin: "",
    originTemplate: "https://kms.{region}.amazonaws.com",
    auth: { type: "aws-sigv4", region: "", service: "kms" },
    fixed: ["service"],
    slots: AWS_SLOTS,
    bundle: { type: "aws", fields: awsFields() },
    usage: {
      summary: "AWS KMS JSON API, signed with SigV4.",
      example: {
        method: "POST",
        path: "/",
        headers: { "X-Amz-Target": "TrentService.DescribeKey", "Content-Type": "application/x-amz-json-1.1" },
        body: "{\"KeyId\":\"<key-id>\"}",
      },
      schematic: true,
      notes: [
        "<key-id> is a key ID, key ARN or alias/<name> from the task or the owner; it is a request input, not a credential.",
        "DescribeKey needs kms:DescribeKey on that key. Encrypt, Decrypt and other operations use X-Amz-Target TrentService.<Operation> and need their own permissions.",
        "Disabling a key, scheduling its deletion or changing its policy can make data unrecoverable; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.aws.amazon.com/general/latest/gr/ses.html and https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetAccount.html (SESv2 signing name: ses)
  {
    id: "aws-ses",
    name: "AWS SES",
    group: "popular",
    needs: "Region + access key pair",
    guide: "Enter the SES region; the origin is https://email.<region>.amazonaws.com and the signing service is ses. Sender identities are request inputs, not credentials.",
    origin: "",
    originTemplate: "https://email.{region}.amazonaws.com",
    auth: { type: "aws-sigv4", region: "", service: "ses" },
    fixed: ["service"],
    slots: AWS_SLOTS,
    bundle: { type: "aws", fields: awsFields() },
    usage: {
      summary: "Amazon SES v2 API, signed with SigV4.",
      example: { method: "GET", path: "/v2/email/account" },
      schematic: false,
      notes: [
        "GetAccount needs ses:GetAccount and reports sending status and quota for this region.",
        "Sending email (POST /v2/email/outbound-emails) delivers real mail; confirm sender, recipients and content with the owner first.",
        "The sender is a request input and must be a verified identity in this region.",
        AUTH_NOTE,
      ],
    },
  },
  // https://developers.google.com/identity/protocols/oauth2/native-app and https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list
  {
    id: "google",
    name: "Google APIs",
    group: "popular",
    needs: "OAuth client ID (+ secret), then sign-in",
    guide: "Enter the OAuth client ID and its client secret. Desktop app clients have a secret too: enter it, because Google's token endpoint is reported to reject a Desktop sign-in without one even though Google documents it as optional. Then enter the target API's origin and exact scopes, and Save and connect to sign in.",
    origin: "https://www.googleapis.com",
    originSuffix: ".googleapis.com",
    auth: {
      type: "oauth2",
      grant: "refresh_token",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      clientAuth: "body",
      scope: "",
    },
    fixed: ["tokenEndpoint", "grant"],
    slots: { clientIdSecret: "client_id", clientSecret: "client_secret", refreshSecret: "refresh_token" },
    bundle: {
      type: "google",
      fields: [
        required("client_id", "Client ID", false),
        optionalCredential("client_secret", "Client secret", true, "Desktop app clients have one too; enter it."),
        refreshToken(),
      ],
    },
    consent: {
      issuer: "https://accounts.google.com",
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      authorizationParameters: { access_type: "offline", prompt: "consent" },
      fixedPort: false,
      registration: "A Desktop app client accepts the loopback callback on any port. A Web application client must list the exact http://127.0.0.1:<port>/oauth/callback redirect URI; choose that fixed port here.",
      scopeHint: "Enter the exact scopes the target API needs; the Drive example needs a Drive scope such as https://www.googleapis.com/auth/drive.metadata.readonly.",
      scopeRequired: true,
    },
    usage: {
      summary: "Google API requests with an OAuth access token.",
      example: { method: "GET", path: "/drive/v3/files", query: { pageSize: "10" } },
      schematic: true,
      notes: [
        "This example is the Drive API on https://www.googleapis.com and assumes the Drive API is enabled for the client's project and a Drive scope was granted. Other Google APIs use their own documented paths on this connection's origin; an API on another origin needs its own connection.",
        "Requests act as the Google account that granted consent, limited to the granted scopes.",
        AUTH_NOTE,
      ],
    },
  },
  // https://developers.openai.com/api/reference/overview#authentication
  {
    id: "openai",
    name: "OpenAI",
    group: "more",
    needs: "API key",
    guide: "Paste an OpenAI API key.",
    origin: "https://api.openai.com",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: { type: "openai", fields: [required("api_key", "API key", true)] },
    usage: {
      summary: "OpenAI API.",
      example: { method: "GET", path: "/v1/models" },
      schematic: false,
      notes: [
        "Send OpenAI-Organization or OpenAI-Project only when the key belongs to several organizations or is a legacy user key.",
        "Model requests are billed per token.",
        AUTH_NOTE,
      ],
    },
  },
  // https://postmarkapp.com/developer/api/overview, https://postmarkapp.com/developer/api/stats-api and https://postmarkapp.com/developer/api/server-api
  {
    id: "postmark",
    name: "Postmark",
    group: "more",
    needs: "Server token",
    guide: "Paste a server API token. Account-level endpoints need a separate connection using the account token.",
    origin: "https://api.postmarkapp.com",
    auth: { type: "header", name: "X-Postmark-Server-Token" },
    fixed: ["name"],
    slots: { secret: "server_token" },
    bundle: { type: "postmark", fields: [required("server_token", "Server token", true)] },
    usage: {
      summary: "Postmark server API.",
      example: { method: "GET", path: "/stats/outbound", headers: { Accept: "application/json" } },
      schematic: false,
      notes: [
        "Returns this server's sending overview (sent, bounced, spam complaints).",
        "GET /server lists the server's API tokens, including this connection's, so BlindDrop withholds its response (RESPONSE_BLOCKED).",
        "Send Accept: application/json; JSON bodies also need Content-Type: application/json.",
        "Account-level endpoints, such as servers, domains and sender signatures, need a separate connection using X-Postmark-Account-Token.",
        "Sending email delivers real messages; confirm recipients and content with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://www.twilio.com/docs/usage/requests-to-twilio, https://www.twilio.com/docs/iam/api-keys and https://www.twilio.com/docs/phone-numbers/api/incomingphonenumber-resource
  {
    id: "twilio",
    name: "Twilio",
    group: "more",
    needs: "API key SID + secret",
    guide: "Use an API key SID and secret as username and password. With the Account SID as username, Twilio echoes it in every response, so BlindDrop withholds those responses (RESPONSE_BLOCKED).",
    origin: "https://api.twilio.com",
    auth: { type: "basic" },
    fixed: [],
    slots: { usernameSecret: "username", passwordSecret: "password" },
    bundle: {
      type: "twilio",
      fields: [
        required("username", "API key SID", false),
        required("password", "API key secret", true),
      ],
    },
    usage: {
      summary: "Twilio REST API (2010-04-01).",
      example: { method: "GET", path: "/2010-04-01/Accounts/<AccountSid>/IncomingPhoneNumbers.json", query: { PageSize: "1" } },
      schematic: true,
      notes: [
        "<AccountSid> is the account's SID (AC…); it stays in the path when an API key authenticates. The example lists one of the account's phone numbers.",
        "Do not request the Account resource itself (/2010-04-01/Accounts/<AccountSid>.json): Standard API keys are refused, and with a Main key its response includes the account's Auth Token.",
        "Authenticate with an API key: responses echo the Account SID, so an Account SID username makes every response RESPONSE_BLOCKED.",
        "POST bodies are form-encoded (application/x-www-form-urlencoded).",
        "Sending messages or placing calls is billed and reaches real people; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.dropboxapi.com/dropbox-api/docs/oauth; route: github.com/dropbox/dropbox-api-spec users.stone
  {
    id: "dropbox",
    name: "Dropbox",
    group: "more",
    needs: "App key, then sign-in",
    guide: "Enter the app key, register the exact callback URL, then Save and connect. Add the app secret only if your app sends it instead of using PKCE.",
    origin: "https://api.dropboxapi.com",
    auth: {
      type: "oauth2",
      grant: "refresh_token",
      tokenEndpoint: "https://api.dropbox.com/oauth2/token",
      clientAuth: "none",
    },
    fixed: ["tokenEndpoint", "grant"],
    slots: { clientIdSecret: "app_key", clientSecret: "app_secret", refreshSecret: "refresh_token" },
    bundle: {
      type: "dropbox",
      fields: [
        required("app_key", "App key", false),
        optionalCredential("app_secret", "App secret", true, "Only when the app sends its secret; PKCE sign-in does not need it."),
        refreshToken(),
      ],
    },
    consent: {
      issuer: "https://www.dropbox.com",
      authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
      authorizationParameters: { token_access_type: "offline" },
      fixedPort: true,
      registration: "Dropbox requires an exact redirect URI: add http://127.0.0.1:<port>/oauth/callback to the app's Redirect URIs and choose the same fixed port here.",
      scopeHint: "Optional. Without a scope, Dropbox grants the permissions selected for the app; the example needs account_info.read.",
    },
    usage: {
      summary: "Dropbox API v2 RPC endpoints.",
      example: { method: "POST", path: "/2/users/get_current_account" },
      schematic: false,
      notes: [
        "Needs the account_info.read scope. Send no body for this call; RPC calls with arguments send JSON with Content-Type: application/json.",
        "Uploads and downloads use content.dropboxapi.com and need their own connection.",
        "Deleting or overwriting files changes the owner's Dropbox; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://developers.cloudflare.com/r2/api/s3/api/
  {
    id: "r2",
    name: "Cloudflare R2",
    group: "more",
    needs: "Account endpoint + R2 access key pair",
    guide: "Enter your Cloudflare account ID for https://<account-id>.r2.cloudflarestorage.com; region stays auto. Use an R2 API token's S3 access key pair, not a Cloudflare API token.",
    origin: "",
    originTemplate: "https://{account}.r2.cloudflarestorage.com",
    auth: { type: "aws-sigv4", region: "auto", service: "s3" },
    fixed: ["service", "region"],
    slots: S3_KEY_SLOTS,
    bundle: { type: "r2", fields: s3KeyFields("Access key ID", "Secret access key") },
    usage: {
      summary: "Cloudflare R2 S3-compatible API.",
      example: s3ListExample(),
      schematic: true,
      notes: [
        S3_BUCKET_NOTE,
        "Cloudflare API tokens for other Cloudflare APIs are different credentials and need their own connection.",
        S3_WRITE_NOTE,
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.digitalocean.com/reference/api/spaces/ and https://docs.digitalocean.com/products/spaces/how-to/use-aws-sdks/
  {
    id: "dospaces",
    name: "DigitalOcean Spaces",
    group: "more",
    needs: "Spaces region + Spaces key pair",
    guide: "Enter the region shown for your Space; the origin is https://<region>.digitaloceanspaces.com and signing uses the same region.",
    origin: "",
    originTemplate: "https://{region}.digitaloceanspaces.com",
    auth: { type: "aws-sigv4", region: "", service: "s3" },
    fixed: ["service"],
    slots: S3_KEY_SLOTS,
    bundle: { type: "dospaces", fields: s3KeyFields("Access key", "Secret key") },
    usage: {
      summary: "DigitalOcean Spaces S3-compatible API.",
      example: s3ListExample(),
      schematic: true,
      notes: [S3_BUCKET_NOTE, S3_WRITE_NOTE, AUTH_NOTE],
    },
  },
  // https://core.telegram.org/bots/api
  {
    id: "telegram",
    name: "Telegram Bot",
    group: "more",
    needs: "Bot token",
    guide: "Paste the bot token from BotFather; BlindDrop places it in the required URL path.",
    origin: "https://api.telegram.org",
    auth: { type: "bindings", bindings: [{ in: "path", prefix: "/bot" }] },
    fixed: ["bindings"],
    slots: { "bindings.0": "bot_token" },
    bundle: { type: "telegram", fields: [required("bot_token", "Bot token", true)] },
    usage: {
      summary: "Telegram Bot API methods.",
      example: { method: "GET", path: "/getMe" },
      schematic: false,
      notes: [
        "Send only /<method>; BlindDrop prepends /bot<token>.",
        "File downloads use the /file/bot<token>/ prefix and need a separate connection.",
        "sendMessage and similar methods post to real chats; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://www.backblaze.com/docs/cloud-storage-call-the-s3-compatible-api and https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
  {
    id: "backblaze",
    name: "Backblaze B2 (S3)",
    group: "more",
    needs: "Bucket region + application key pair",
    guide: "Enter the region from your bucket's S3 endpoint, s3.<region>.backblazeb2.com. This preset uses the S3-compatible API with an application key, not the native B2 API.",
    origin: "",
    originTemplate: "https://s3.{region}.backblazeb2.com",
    auth: { type: "aws-sigv4", region: "", service: "s3" },
    fixed: ["service"],
    slots: { accessKeyIdSecret: "key_id", secretAccessKeySecret: "application_key" },
    bundle: {
      type: "backblaze",
      fields: [
        required("key_id", "keyID", false),
        required("application_key", "applicationKey", true),
        metadata("key_name", "keyName", false),
        metadata("bucket_name", "Bucket name", false),
        metadata("capabilities", "Capabilities", false),
        metadata("expiration", "Expiration", false),
        metadata("name_prefix", "Name prefix", false),
      ],
    },
    usage: {
      summary: "Backblaze B2 S3-compatible API.",
      example: s3ListExample(),
      schematic: true,
      notes: [
        S3_BUCKET_NOTE,
        "A key restricted to one bucket or name prefix reaches only that bucket or prefix.",
        S3_WRITE_NOTE,
        AUTH_NOTE,
      ],
    },
  },
  // https://www.tigrisdata.com/docs/sdks/s3/; new buckets are virtual-hosted only: https://www.tigrisdata.com/blog/virtual-hosted-urls/
  {
    id: "tigris",
    name: "Tigris",
    group: "more",
    needs: "Bucket + access key pair",
    guide: "Enter the bucket name; it goes in the hostname (https://<bucket>.t3.storage.dev), as Tigris requires for buckets created after 19 Feb 2025.",
    origin: "",
    originTemplate: "https://{bucket}.t3.storage.dev",
    auth: { type: "aws-sigv4", region: "auto", service: "s3" },
    fixed: ["service"],
    slots: S3_KEY_SLOTS,
    bundle: {
      type: "tigris",
      fields: [
        required("aws_access_key_id", "AWS_ACCESS_KEY_ID", false),
        required("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", true),
        field("bucket_name", "Bucket name", "note", false, true,
          "Stored note. The connection's Origin names the bucket; change it with Edit connection…"),
        field("aws_endpoint_url_s3", "AWS_ENDPOINT_URL_S3", "note", false, true,
          "Stored note. The connection's Origin and Region are operative; change them with Edit connection…"),
        field("aws_region", "AWS_REGION", "note", false, true,
          "Stored note. The connection's Origin and Region are operative; change them with Edit connection…"),
      ],
    },
    usage: {
      summary: "Tigris S3-compatible API.",
      example: { method: "GET", path: "/", query: { "list-type": "2", "max-keys": "10" } },
      schematic: false,
      notes: [
        "Lists up to 10 objects in this connection's bucket (ListObjectsV2).",
        "Object keys are request paths (/<key>). One connection serves one bucket; another bucket needs its own connection.",
        S3_WRITE_NOTE,
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.together.ai/docs/api-keys-authentication and https://docs.together.ai/reference/whoami.md
  {
    id: "together",
    name: "Together AI",
    group: "more",
    needs: "API key",
    guide: "Paste a Together AI API key.",
    origin: "https://api.together.ai",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: { type: "together", fields: [required("api_key", "API key", true)] },
    usage: {
      summary: "Together AI API.",
      example: { method: "GET", path: "/v3/whoami" },
      schematic: false,
      notes: [
        "Identifies the key's project and organization.",
        "Inference requests such as POST /v1/chat/completions are billed per token.",
        AUTH_NOTE,
      ],
    },
  },
  // https://github.com/makora-ai/makora: makora/config.py (MAKORA_URL), makora/web/auth.py (auth/me), data/openapi.json
  {
    id: "makora",
    name: "Makora",
    group: "more",
    needs: "API key",
    guide: "Paste an API token from the Makora tokens page.",
    origin: "https://generate.makora.com",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: { type: "makora", fields: [required("api_key", "API key", true)] },
    usage: {
      summary: "Makora API under /api/v1/.",
      example: { method: "GET", path: "/api/v1/auth/me" },
      schematic: false,
      notes: [
        "The official Makora client checks a token with this request.",
        "Starting an agent session (POST /api/v1/agent-session) runs generation work for the account; confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://modal.com/docs/guide/sdk-javascript-go and https://modal.com/docs/guide/environments ("main")
  {
    id: "modal",
    name: "Modal",
    group: "more",
    needs: "Token ID + token secret, deployed Function",
    guide: "Enter the account token ID and token secret, then the deployed app, Function and environment that agents may invoke. The Function must be deployed with Modal's Python SDK 1.2 or later.",
    origin: MODAL_ORIGIN,
    auth: { type: "modal" },
    fixed: [],
    slots: { tokenIdSecret: "token_id", tokenSecretSecret: "token_secret" },
    bundle: {
      type: "modal",
      fields: [
        required("token_id", "Token ID", false),
        required("token_secret", "Token secret", true),
        metadata("profile", "Profile", false, "Stored note; BlindDrop never uses a local Modal profile."),
      ],
    },
    modal: { environment: "main" },
    usage: {
      summary: "Invoke the owner-selected Modal Function.",
      example: { args: [], kwargs: {} },
      schematic: true,
      notes: [
        "Arguments must match the Function's signature. If the target usage, the task or the application's code does not establish them, ask the owner; do not guess.",
        "BlindDrop submits one invocation and never retries it. TIMEOUT or UPSTREAM_ERROR means the Function may still have run.",
        "A Function deployed with a Modal Python SDK older than 1.2 cannot be called: every call fails with UPSTREAM_ERROR before anything is submitted. Report this to the owner, who must redeploy it with SDK 1.2 or later.",
        "Default limits: 1 MiB of JSON arguments, a 4 MiB JSON result and 30 seconds.",
        "Each invocation runs the owner's code and can be billed; confirm consequential runs with the owner.",
      ],
    },
  },
  // https://docs.agentmail.to/api-reference/auth/me
  {
    id: "agentmail",
    name: "AgentMail",
    group: "more",
    needs: "API key",
    guide: "Paste an AgentMail API key. The display name and key prefix are stored only.",
    origin: "https://api.agentmail.to",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: {
      type: "agentmail",
      fields: [
        required("api_key", "API key", true),
        metadata("display_name", "Display name", false),
        metadata("key_prefix", "Key prefix", false),
      ],
    },
    usage: {
      summary: "AgentMail API under /v0/.",
      example: { method: "GET", path: "/v0/auth/me" },
      schematic: false,
      notes: [
        "Returns the key's scope: organization, pod or inbox.",
        "Sending messages delivers real email; confirm recipients and content with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.vast.ai/api-reference/introduction and https://docs.vast.ai/api-reference/accounts/show-user
  {
    id: "vast",
    name: "Vast.ai",
    group: "more",
    needs: "API key",
    guide: "Paste a Vast.ai API key.",
    origin: "https://console.vast.ai",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: { type: "vast", fields: [required("api_key", "API key", true)] },
    usage: {
      summary: "Vast.ai API under /api/v0/.",
      example: { method: "GET", path: "/api/v0/users/current" },
      schematic: false,
      notes: [
        "Renting or creating instances is billed; never do it as a credential check, and confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://docs.lambda.ai/api/cloud and its spec.json (Bearer recommended; Basic with empty password is legacy)
  {
    id: "lambda",
    name: "Lambda Cloud",
    group: "more",
    needs: "API key",
    guide: "Paste a Lambda Cloud API key; it is sent as a Bearer token. The name and recovery code are stored only.",
    origin: "https://cloud.lambda.ai",
    auth: { type: "bearer" },
    fixed: [],
    slots: { secret: "api_key" },
    bundle: {
      type: "lambda",
      fields: [
        required("api_key", "API key", true),
        metadata("name", "Name", false),
        metadata("recovery_code", "Recovery code", true),
      ],
    },
    usage: {
      summary: "Lambda Cloud API under /api/v1/.",
      example: { method: "GET", path: "/api/v1/account" },
      schematic: false,
      notes: [
        "Returns the account's id and name.",
        "Instance listings (/api/v1/instances) include each running instance's JupyterLab login token (jupyter_token); request them only when the task needs them.",
        "Launching instances is billed; never launch one as a credential check, and confirm with the owner first.",
        AUTH_NOTE,
      ],
    },
  },
  // https://modal.com/docs/guide/webhook-proxy-auth (reached from the Modal sheet)
  {
    id: "modal-web",
    name: "Modal web endpoint",
    group: "more",
    hidden: true,
    needs: "Endpoint origin + Proxy Token ID and secret",
    guide: "For a web endpoint that requires proxy auth: enter its https://…modal.run origin and a Proxy Token ID and secret, which differ from account tokens.",
    origin: "",
    auth: {
      type: "bindings",
      bindings: [
        { in: "header", name: "Modal-Key" },
        { in: "header", name: "Modal-Secret" },
      ],
    },
    fixed: ["bindings"],
    slots: { "bindings.0": "proxy_token_id", "bindings.1": "proxy_token_secret" },
    bundle: {
      type: "modal-web",
      fields: [
        required("proxy_token_id", "Proxy token ID", false),
        required("proxy_token_secret", "Proxy token secret", true),
      ],
    },
    usage: {
      summary: "Requests to the owner's Modal web endpoint with proxy auth.",
      example: { method: "GET", path: "/" },
      schematic: true,
      notes: [
        "The method, path and body depend on the endpoint's code; take them from the task or the application.",
        "Each request runs the owner's code and can be billed.",
        AUTH_NOTE,
      ],
    },
  },
  // Generic fallback; the owner page uses its generic slot specs.
  {
    id: CUSTOM_ID,
    name: "Custom",
    group: "custom",
    needs: "Origin + supported credential placement",
    guide: "Choose how the API accepts credentials and enter only its HTTPS origin.",
    origin: "",
    auth: { type: "bearer" },
    fixed: [],
    slots: {},
    bundle: { type: "custom", fields: [] },
    usage: {
      summary: "Authenticated HTTPS requests to the configured origin.",
      example: { method: "GET", path: "/<path>" },
      schematic: true,
      notes: [
        "No provider recipe applies. Use the provider's API documentation for paths, headers and bodies.",
        AUTH_NOTE,
      ],
    },
  },
];

export function recipeById(id: string | undefined): Recipe | undefined {
  return id === undefined ? undefined : RECIPES.find((recipe) => recipe.id === id);
}

const BINDING_KEYS = ["in", "name", "prefix", "suffix"] as const;

function property(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

// Bindings match on placement only, in order; the secret reference is ignored.
function sameBindings(actual: unknown, expected: unknown): boolean {
  if (!Array.isArray(actual) || !Array.isArray(expected) || actual.length !== expected.length) {
    return false;
  }
  return expected.every((binding: unknown, index) =>
    BINDING_KEYS.every((key) => property(actual[index], key) === property(binding, key)));
}

// `{bucket}` excludes dots: virtual-hosted TLS fails for dotted bucket names.
const PLACEHOLDER_PATTERNS: ReadonlyMap<string, string> = new Map([
  ["{region}", "([a-z0-9-]+)"],
  ["{account}", "([A-Za-z0-9-]+)"],
  ["{bucket}", "([a-z0-9][a-z0-9-]*)"],
]);

const TEMPLATE_PLACEHOLDER = /(\{region\}|\{account\}|\{bucket\})/;

// `{region}` must equal the signing region; `{account}` and `{bucket}` only
// compose the origin. Connection origins are already normalized by validation
// (URL.origin).
function matchesOriginTemplate(template: string, connection: Connection): boolean {
  const placeholders: string[] = [];
  const source = template
    .split(TEMPLATE_PLACEHOLDER)
    .map((part) => {
      const pattern = PLACEHOLDER_PATTERNS.get(part);
      if (pattern !== undefined) {
        placeholders.push(part);
        return pattern;
      }
      return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("");
  const match = new RegExp(`^${source}$`).exec(connection.origin);
  if (match === null) {
    return false;
  }
  const region = connection.auth.type === "aws-sigv4" ? connection.auth.region : undefined;
  return placeholders.every((placeholder, index) =>
    placeholder !== "{region}" || match[index + 1] === region);
}

// An HTTPS origin on the default port whose host is a subdomain of `suffix`.
function onHostSuffix(origin: string, suffix: string): boolean {
  const url = new URL(origin);
  return url.protocol === "https:" && url.port === "" &&
    url.hostname.length > suffix.length && url.hostname.endsWith(suffix);
}

/**
 * Whether a saved connection still matches the recipe it names: the same
 * mechanism, the recipe's fixed configuration, and its origin or origin
 * template. Account and region edits that keep the template stay compatible.
 * Custom is never compatible: it has no configuration to match, so its
 * connections use the generic guidance.
 */
export function recipeCompatible(recipe: Recipe, connection: Connection): boolean {
  if (recipe.id === CUSTOM_ID) {
    return false;
  }
  const auth: Readonly<Record<string, unknown>> = connection.auth;
  if (auth.type !== recipe.auth.type) {
    return false;
  }
  for (const key of recipe.fixed) {
    const same = key === "bindings"
      ? sameBindings(auth[key], recipe.auth[key])
      : auth[key] === recipe.auth[key];
    if (!same) {
      return false;
    }
  }
  if (recipe.origin !== "") {
    return connection.origin === recipe.origin ||
      (recipe.originSuffix !== undefined && onHostSuffix(connection.origin, recipe.originSuffix));
  }
  if (recipe.originTemplate !== undefined) {
    return matchesOriginTemplate(recipe.originTemplate, connection);
  }
  return true;
}

function genericGuidance(name: string, connection: Connection): ConnectionGuidance {
  if (connection.auth.type === "modal") {
    return {
      recipe: null,
      tool: "invoke_modal_function",
      summary: "Invoke the owner-selected Modal Function.",
      example: { connection: name, args: [], kwargs: {} },
      schematic: true,
      notes: [
        "Arguments must match the Function's signature. If the target usage, the task or the application's code does not establish them, ask the owner; do not guess.",
        "BlindDrop submits one invocation and never retries it. TIMEOUT or UPSTREAM_ERROR means the Function may still have run.",
      ],
      ...(connection.modal === undefined ? {} : { target: connection.modal }),
    };
  }
  return {
    recipe: null,
    tool: "execute_http",
    summary: `Authenticated HTTPS requests to ${connection.origin}.${signing(connection)}`,
    example: { connection: name, method: "GET", path: "/<path>" },
    schematic: true,
    notes: [
      "No compatible provider recipe applies to this connection. Use the provider's API documentation for paths, headers and bodies.",
      "BlindDrop adds the authentication. Do not send credential headers yourself.",
    ],
  };
}

// Only the signing region and service are added; both are ordinary owner
// configuration, never a secret, reference or stored value.
function signing(connection: Connection): string {
  return connection.auth.type === "aws-sigv4"
    ? ` Signing region ${connection.auth.region}, service ${connection.auth.service}.`
    : "";
}

function summary(recipe: Recipe, connection: Connection): string {
  return `${recipe.usage.summary}${signing(connection)}`;
}

/**
 * Credential-free guidance for one connection: the recipe's documented
 * operation when the connection still matches it, otherwise the generic
 * schema. Never reads a vault and never emits references or stored values.
 */
export function connectionGuidance(name: string, connection: Connection): ConnectionGuidance {
  const recipe = recipeById(connection.recipe);
  if (recipe === undefined || !recipeCompatible(recipe, connection)) {
    return genericGuidance(name, connection);
  }
  const modal = connection.auth.type === "modal";
  return {
    recipe: recipe.id,
    tool: modal ? "invoke_modal_function" : "execute_http",
    summary: summary(recipe, connection),
    example: { connection: name, ...structuredClone(recipe.usage.example) },
    schematic: recipe.usage.schematic,
    notes: [...recipe.usage.notes],
    ...(modal && connection.modal !== undefined ? { target: connection.modal } : {}),
  };
}
