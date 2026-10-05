import { constants as fsConstants } from "node:fs";
import {
  access,
  cp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

const execFileAsync = promisify(execFile);

const BUNDLED_VERSION = "0.6.0";
const MARKETPLACE = "blinddrop-desktop";
const PLUGIN = "blinddrop";
const SELECTOR = `${PLUGIN}@${MARKETPLACE}`;
const DEFAULT_PORT = 8787;
const COMMAND_TIMEOUT_MS = 30_000;
const COMMAND_MAX_BYTES = 1024 * 1024;

const HOSTS = {
  claude: {
    name: "Claude Code",
    candidates: home => [
      join(home, ".local", "bin", "claude"),
      "/opt/homebrew/bin/claude",
      "/usr/local/bin/claude",
    ],
    installed(args) {
      return Array.isArray(args) ? args : [];
    },
  },
  codex: {
    name: "Codex",
    candidates: home => [
      join(
        home,
        "Applications",
        "ChatGPT.app",
        "Contents",
        "Resources",
        "codex-cli",
        "CodexCLI.app",
        "Contents",
        "MacOS",
        "codex",
      ),
      join(
        home,
        "Applications",
        "Codex.app",
        "Contents",
        "Resources",
        "codex-cli",
        "CodexCLI.app",
        "Contents",
        "MacOS",
        "codex",
      ),
      "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
      "/Applications/Codex.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
      join(home, ".local", "bin", "codex"),
      "/opt/homebrew/bin/codex",
      "/usr/local/bin/codex",
    ],
    installed(value) {
      return Array.isArray(value?.installed) ? value.installed : [];
    },
  },
};

class HostFailure extends Error {}

function validPort(value) {
  return Number.isInteger(value) && value >= 1 && value <= 65_535;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function bundledCommand(executablePath, scriptPath) {
  return (
    `/usr/bin/env ELECTRON_RUN_AS_NODE=1 ${shellQuote(executablePath)} ` +
    shellQuote(scriptPath)
  );
}

function unique(values) {
  return [...new Set(values.filter(value => typeof value === "string" && value !== ""))];
}

async function executable(path) {
  try {
    await access(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function normalizedPath(path) {
  try {
    return await realpath(path);
  } catch {
    return resolve(path);
  }
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new HostFailure();
  }
}

function pluginVersion(host, entry) {
  if (host === "claude") {
    return entry?.id === SELECTOR && typeof entry.version === "string" ? entry.version : null;
  }
  return entry?.pluginId === SELECTOR && typeof entry.version === "string" ? entry.version : null;
}

function guidance(host, state) {
  if (state === "unavailable") {
    return host === "claude"
      ? "Install Claude Code, then return here."
      : "Install the Codex Mac app or local Codex CLI, then return here.";
  }
  if (state === "not-installed") {
    return host === "claude"
      ? "Install BlindDrop for Claude Code to add its skill, credential-file guard hook, and authenticated MCP connection."
      : "Install BlindDrop for Codex to add its skill and authenticated MCP connection.";
  }
  if (host === "claude") {
    return state === "update-available"
      ? "Update, then restart Claude Code or run /reload-plugins in an existing session."
      : "Configured. Restart Claude Code or run /reload-plugins in an existing session; unlock a vault before use.";
  }
  return state === "update-available"
    ? "Update, then start a new Codex session and review the BlindDrop plugin if Codex prompts."
    : "Configured. Start a new Codex session and review the BlindDrop plugin if Codex prompts; unlock a vault before use.";
}

function unavailableStatus(host, available = false, message) {
  return {
    host,
    name: HOSTS[host].name,
    hostAvailable: available,
    configured: false,
    installedVersion: null,
    bundledVersion: BUNDLED_VERSION,
    updateAvailable: false,
    state: "unavailable",
    actions: { install: false, update: false, remove: false },
    connected: null,
    activation: "new-session",
    trustRequired: host === "codex",
    guidance: message ?? guidance(host, "unavailable"),
  };
}

/**
 * App-owned installation of one local plugin through each host's own CLI.
 * Host configuration is never parsed or rewritten here; the host remains the
 * authority for marketplace and plugin state.
 */
export class IntegrationManager {
  constructor({
    configDir,
    pluginRoot,
    executablePath,
    endpointPort = DEFAULT_PORT,
    homeDir = homedir(),
    environment = process.env,
    binaryOverrides = {},
  }) {
    this.configDir = configDir;
    this.pluginRoot = pluginRoot;
    this.executablePath = executablePath;
    this.endpointPort = validPort(endpointPort) ? endpointPort : DEFAULT_PORT;
    this.homeDir = homeDir;
    this.environment = { ...environment, HOME: homeDir };
    this.binaryOverrides = binaryOverrides;
    this.marketplaceRoot = join(configDir, "integrations", MARKETPLACE);
    this.refreshFailures = new Set();
  }

  async findHost(host) {
    const override = this.binaryOverrides[host];
    const pathEntries = String(this.environment.PATH ?? "")
      .split(delimiter)
      .filter(Boolean)
      .map(path => join(path, host === "claude" ? "claude" : "codex"));
    const candidates = unique([override, ...HOSTS[host].candidates(this.homeDir), ...pathEntries]);
    for (const candidate of candidates) {
      if (await executable(candidate)) return candidate;
    }
    return null;
  }

  async run(binary, args) {
    try {
      return await execFileAsync(binary, args, {
        env: this.environment,
        timeout: COMMAND_TIMEOUT_MS,
        maxBuffer: COMMAND_MAX_BYTES,
        windowsHide: true,
      });
    } catch {
      throw new HostFailure();
    }
  }

  async stage() {
    const parent = join(this.configDir, "integrations");
    await mkdir(parent, { recursive: true, mode: 0o700 });
    const suffix = `${process.pid}-${Date.now()}`;
    const temporary = `${this.marketplaceRoot}.next-${suffix}`;
    const previous = `${this.marketplaceRoot}.previous-${suffix}`;
    await rm(temporary, { recursive: true, force: true });
    await cp(this.pluginRoot, join(temporary, "plugins", PLUGIN), { recursive: true });

    const stagedPlugin = join(temporary, "plugins", PLUGIN);
    // Both host catalogues keep this app-owned marketplace path. Codex does
    // not populate Claude's plugin-root environment variable for MCP header
    // helpers, so write the stable post-rename path that both hosts can run.
    const publishedPlugin = join(this.marketplaceRoot, "plugins", PLUGIN);
    const mcpPath = join(stagedPlugin, ".mcp.json");
    const mcp = parseJson(await readFile(mcpPath, "utf8"));
    const server = mcp?.mcpServers?.[PLUGIN];
    if (server === null || typeof server !== "object") throw new HostFailure();
    server.type = "http";
    server.url = `http://127.0.0.1:${this.endpointPort}/mcp`;
    const helper = bundledCommand(
      this.executablePath,
      join(publishedPlugin, "scripts", "session-headers.mjs"),
    );
    server.headersHelper = helper;
    server.http_headers_helper = helper;
    await writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`, { mode: 0o600 });

    const hooksPath = join(stagedPlugin, "hooks", "hooks.json");
    const hooks = parseJson(await readFile(hooksPath, "utf8"));
    for (const entries of Object.values(hooks?.hooks ?? {})) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        for (const hook of Array.isArray(entry?.hooks) ? entry.hooks : []) {
          if (typeof hook?.command !== "string") continue;
          const match = hook.command.match(/scripts\/(guard|session-context)\.mjs/u);
          if (match !== null) {
            hook.command = bundledCommand(
              this.executablePath,
              join(publishedPlugin, "scripts", `${match[1]}.mjs`),
            );
          }
        }
      }
    }
    await writeFile(hooksPath, `${JSON.stringify(hooks, null, 2)}\n`, { mode: 0o600 });

    const pluginEntry = {
      name: PLUGIN,
      source: `./plugins/${PLUGIN}`,
      description: "Use encrypted local credentials through BlindDrop without exposing them to agents.",
      version: BUNDLED_VERSION,
    };
    await mkdir(join(temporary, ".claude-plugin"), { recursive: true, mode: 0o700 });
    await writeFile(
      join(temporary, ".claude-plugin", "marketplace.json"),
      `${JSON.stringify(
        { name: MARKETPLACE, owner: { name: "IluvatarLabs" }, plugins: [pluginEntry] },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );
    await mkdir(join(temporary, ".agents", "plugins"), { recursive: true, mode: 0o700 });
    await writeFile(
      join(temporary, ".agents", "plugins", "marketplace.json"),
      `${JSON.stringify({ name: MARKETPLACE, plugins: [pluginEntry] }, null, 2)}\n`,
      { mode: 0o600 },
    );

    let movedPrevious = false;
    try {
      await rename(this.marketplaceRoot, previous);
      movedPrevious = true;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    try {
      await rename(temporary, this.marketplaceRoot);
    } catch (error) {
      if (movedPrevious) await rename(previous, this.marketplaceRoot).catch(() => {});
      throw error;
    }
    if (movedPrevious) await rm(previous, { recursive: true, force: true });
    return this.marketplaceRoot;
  }

  async installedVersion(host, binary) {
    const { stdout } = await this.run(binary, ["plugin", "list", "--json"]);
    const entries = HOSTS[host].installed(parseJson(stdout));
    for (const entry of entries) {
      const version = pluginVersion(host, entry);
      if (version !== null) return version;
    }
    return null;
  }

  async marketplaceEntries(host, binary) {
    const { stdout } = await this.run(binary, ["plugin", "marketplace", "list", "--json"]);
    const value = parseJson(stdout);
    return host === "claude"
      ? (Array.isArray(value) ? value : [])
      : (Array.isArray(value?.marketplaces) ? value.marketplaces : []);
  }

  marketplacePath(host, entry) {
    if (host === "claude") return entry?.path ?? entry?.installLocation ?? null;
    return entry?.root ?? entry?.marketplaceSource?.source ?? null;
  }

  async ensureMarketplace(host, binary) {
    const entries = await this.marketplaceEntries(host, binary);
    const current = entries.find(entry => entry?.name === MARKETPLACE);
    if (current !== undefined) {
      const currentPath = this.marketplacePath(host, current);
      if (typeof currentPath !== "string") throw new HostFailure();
      const [actual, expected] = await Promise.all([
        normalizedPath(currentPath),
        normalizedPath(this.marketplaceRoot),
      ]);
      if (actual !== expected) throw new HostFailure();
      return false;
    }
    await this.run(binary, ["plugin", "marketplace", "add", this.marketplaceRoot]);
    return true;
  }

  async removeMarketplace(host, binary) {
    try {
      const entries = await this.marketplaceEntries(host, binary);
      const current = entries.find(entry => entry?.name === MARKETPLACE);
      if (current === undefined) return;
      const currentPath = this.marketplacePath(host, current);
      if (typeof currentPath !== "string") return;
      const [actual, expected] = await Promise.all([
        normalizedPath(currentPath),
        normalizedPath(this.marketplaceRoot),
      ]);
      if (actual !== expected) return;
      await this.run(binary, ["plugin", "marketplace", "remove", MARKETPLACE, "--json"]);
    } catch {
      // The integration itself is already gone. A stale app-owned catalogue is
      // harmless and can be removed on the next explicit remove action.
    }
  }

  async status(host) {
    const binary = await this.findHost(host);
    if (binary === null) return unavailableStatus(host);
    let installedVersion;
    try {
      installedVersion = await this.installedVersion(host, binary);
    } catch {
      return unavailableStatus(host, true, `BlindDrop could not read ${HOSTS[host].name} integration status.`);
    }
    const configured = installedVersion !== null;
    const updateAvailable =
      configured &&
      (installedVersion !== BUNDLED_VERSION || this.refreshFailures.has(host));
    const state = configured ? (updateAvailable ? "update-available" : "current") : "not-installed";
    return {
      host,
      name: HOSTS[host].name,
      hostAvailable: true,
      configured,
      installedVersion,
      bundledVersion: BUNDLED_VERSION,
      updateAvailable,
      state,
      actions: {
        install: !configured,
        // Refresh is always available for a configured host. Besides a version
        // change, it repairs a changed endpoint or app executable path through
        // the host's own supported update command.
        update: configured,
        remove: configured,
      },
      connected: null,
      activation: "new-session",
      trustRequired: host === "codex",
      guidance: guidance(host, state),
    };
  }

  async getIntegrations() {
    const [claude, codex] = await Promise.all([this.status("claude"), this.status("codex")]);
    return { bundledVersion: BUNDLED_VERSION, claude, codex };
  }

  async installOrUpdate(host, binary, action) {
    await this.stage();
    const addedMarketplace = await this.ensureMarketplace(host, binary);
    try {
      if (host === "claude") {
        if (action === "update") {
          await this.run(binary, ["plugin", "marketplace", "update", MARKETPLACE]);
          await this.run(binary, ["plugin", "update", SELECTOR, "--scope", "user", "--json"]);
        } else {
          await this.run(binary, ["plugin", "install", SELECTOR, "--scope", "user", "--json"]);
        }
      } else {
        await this.run(binary, ["plugin", "add", SELECTOR, "--json"]);
      }
    } catch (error) {
      if (addedMarketplace) await this.removeMarketplace(host, binary);
      throw error;
    }
  }

  async remove(host, binary) {
    if (host === "claude") {
      await this.run(binary, ["plugin", "uninstall", SELECTOR, "--scope", "user", "--json"]);
    } else {
      await this.run(binary, ["plugin", "remove", SELECTOR, "--json"]);
    }
    await this.removeMarketplace(host, binary);
  }

  async manageIntegration(input) {
    const host = input?.host;
    const action = input?.action;
    if (!Object.hasOwn(HOSTS, host) || !["install", "update", "remove"].includes(action)) {
      return {
        ok: false,
        changed: false,
        status: unavailableStatus(host === "codex" ? "codex" : "claude"),
        error: { code: "INVALID_REQUEST", message: "Choose a supported integration action." },
      };
    }
    const binary = await this.findHost(host);
    if (binary === null) {
      return {
        ok: false,
        changed: false,
        status: unavailableStatus(host),
        error: { code: "HOST_NOT_FOUND", message: `${HOSTS[host].name} is not installed.` },
      };
    }
    const before = await this.status(host);
    const permitted =
      (action === "install" && !before.configured) ||
      (action === "update" && before.configured) ||
      (action === "remove" && before.configured);
    if (!permitted) {
      return {
        ok: false,
        changed: false,
        status: before,
        error: { code: "INVALID_REQUEST", message: "That integration action is not available." },
      };
    }
    try {
      if (action === "remove") await this.remove(host, binary);
      else await this.installOrUpdate(host, binary, action);
      this.refreshFailures.delete(host);
      return { ok: true, changed: true, status: await this.status(host) };
    } catch {
      if (action === "update") this.refreshFailures.add(host);
      return {
        ok: false,
        changed: false,
        status: await this.status(host),
        error: {
          code: "HOST_COMMAND_FAILED",
          message: `${HOSTS[host].name} could not ${action} the BlindDrop integration.`,
        },
      };
    }
  }

  async applyEndpoint(port) {
    if (!validPort(port)) return this.getIntegrations();
    this.endpointPort = port;
    const statuses = await this.getIntegrations();
    if (!statuses.claude.configured && !statuses.codex.configured) {
      this.refreshFailures.clear();
      return statuses;
    }
    try {
      await this.stage();
    } catch {
      for (const host of ["claude", "codex"]) {
        if (statuses[host].configured) this.refreshFailures.add(host);
      }
      return this.getIntegrations();
    }
    for (const host of ["claude", "codex"]) {
      if (!statuses[host].configured) continue;
      const binary = await this.findHost(host);
      if (binary === null) continue;
      try {
        await this.ensureMarketplace(host, binary);
        if (host === "claude") {
          await this.run(binary, ["plugin", "marketplace", "update", MARKETPLACE]);
        } else {
          await this.run(binary, ["plugin", "add", SELECTOR, "--json"]);
        }
        this.refreshFailures.delete(host);
      } catch {
        // Settings are already saved by the owner runtime. Mark Update as
        // available so the owner has a truthful retry instead of false Current.
        this.refreshFailures.add(host);
      }
    }
    return this.getIntegrations();
  }
}

export function createIntegrationManager(options) {
  return new IntegrationManager(options);
}
