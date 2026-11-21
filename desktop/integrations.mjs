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

const BUNDLED_VERSION = "0.6.2";
const MARKETPLACE = "blinddrop-desktop";
const PLUGIN = "blinddrop";
const SELECTOR = `${PLUGIN}@${MARKETPLACE}`;
// The skill's `run --app` line for a CLI on PATH; staging names the bundled runtime.
const RUN_APP_LINE = "blinddrop run --app CONNECTION -- COMMAND";
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
      ? "Install BlindDrop for Claude Code to add its skill, guard hook, and authenticated MCP connection."
      : "Install BlindDrop for Codex to add its skill, guard hook, and authenticated MCP connection.";
  }
  if (host === "claude") {
    return state === "update-available"
      ? "Update, then start a new Claude Code session or run /reload-plugins once."
      : "Start a new Claude Code session or run /reload-plugins once, and allow BlindDrop's tools when Claude Code asks.";
  }
  return state === "update-available"
    ? "Update, then start a new Codex session and review the plugin if Codex asks."
    : "Start a new Codex session, then review the plugin and allow BlindDrop's tools if Codex asks.";
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
    trustRequired: false,
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
    agentScript,
    homeDir = homedir(),
    environment = process.env,
    binaryOverrides = {},
  }) {
    this.configDir = configDir;
    this.pluginRoot = pluginRoot;
    this.executablePath = executablePath;
    this.agentScript = agentScript;
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
    try {
      return await this.stageInto(temporary, previous);
    } catch (error) {
      // A failed stage deletes its staging copy, which a retried refresh would otherwise repeat.
      await rm(temporary, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  }

  /** Builds the staged marketplace in `temporary` and publishes it. */
  async stageInto(temporary, previous) {
    await cp(this.pluginRoot, join(temporary, "plugins", PLUGIN), { recursive: true });

    const stagedPlugin = join(temporary, "plugins", PLUGIN);
    // Both host catalogues keep this app-owned marketplace path. Write the
    // stable post-rename path, which both hosts can run without a plugin-root
    // environment variable.
    const publishedPlugin = join(this.marketplaceRoot, "plugins", PLUGIN);
    const mcpPath = join(stagedPlugin, ".mcp.json");
    const mcp = parseJson(await readFile(mcpPath, "utf8"));
    const server = mcp?.mcpServers?.[PLUGIN];
    if (server === null || typeof server !== "object") throw new HostFailure();
    // The host launches the bundled runtime's stdio server with the app's own
    // executable, so the configuration holds no URL, port or credential.
    mcp.mcpServers[PLUGIN] = {
      type: "stdio",
      command: this.executablePath,
      args: [this.agentScript, "agent"],
      env: { ELECTRON_RUN_AS_NODE: "1" },
    };
    await writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`, { mode: 0o600 });

    const hooksPath = join(stagedPlugin, "hooks", "hooks.json");
    const hooks = parseJson(await readFile(hooksPath, "utf8"));
    for (const entries of Object.values(hooks?.hooks ?? {})) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        for (const hook of Array.isArray(entry?.hooks) ? entry.hooks : []) {
          if (typeof hook?.command !== "string") continue;
          if (/scripts\/guard\.mjs/u.test(hook.command)) {
            hook.command = bundledCommand(
              this.executablePath,
              join(publishedPlugin, "scripts", "guard.mjs"),
            );
          }
        }
      }
    }
    await writeFile(hooksPath, `${JSON.stringify(hooks, null, 2)}\n`, { mode: 0o600 });

    // App-only installs have no CLI on PATH: name the bundled runtime instead.
    const skillPath = join(stagedPlugin, "skills", PLUGIN, "SKILL.md");
    const skill = await readFile(skillPath, "utf8");
    if (!skill.includes(RUN_APP_LINE)) throw new HostFailure();
    const bundledRunLine =
      `ELECTRON_RUN_AS_NODE=1 ${shellQuote(this.executablePath)} ` +
      `${shellQuote(this.agentScript)} run --app CONNECTION -- COMMAND`;
    await writeFile(skillPath, skill.replaceAll(RUN_APP_LINE, () => bundledRunLine));

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
    // An unscoped Codex `plugin list` re-syncs its remote plugin catalog when the
    // cache is stale (36 s measured); listing only BlindDrop's marketplace never does.
    const args = host === "codex"
      ? ["plugin", "list", "--marketplace", MARKETPLACE, "--json"]
      : ["plugin", "list", "--json"];
    const { stdout } = await this.run(binary, args);
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
        // Update is always available for a configured host. Besides a version
        // change, it repairs a moved or replaced app through the host's own
        // supported update command, as the launch refresh does.
        update: configured,
        remove: configured,
      },
      connected: null,
      activation: "new-session",
      trustRequired: host === "codex" && configured,
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

  /**
   * Run Update for every host that already has the integration installed, so
   * a moved, replaced or upgraded app keeps working. Called at app launch with
   * no argument, then with the hosts it returned until it returns none. A
   * returned host that Settings has since updated or removed is no longer
   * marked failed, so the retry skips it. A failure of a host whose CLI was
   * found logs the host and the failed step, never command output; Settings then
   * shows Update available when it can read the installed version.
   *
   * @param {string[]} [retry] Hosts returned by the previous call.
   * @returns {Promise<string[]>} Hosts whose CLI was found but whose refresh failed.
   */
  async refresh(retry) {
    const hosts = retry === undefined
      ? Object.keys(HOSTS)
      : retry.filter(host => this.refreshFailures.has(host));
    const failed = [];
    for (const host of hosts) {
      let step = "finding the host";
      try {
        const binary = await this.findHost(host);
        if (binary === null) throw new HostFailure();
        step = "reading the installed version";
        if ((await this.installedVersion(host, binary)) !== null) {
          step = "updating";
          await this.installOrUpdate(host, binary, "update");
        }
        this.refreshFailures.delete(host);
      } catch {
        // `status` shows this only once the host reports the integration
        // installed, so a host found or readable later is not marked Current.
        this.refreshFailures.add(host);
        // A host with no CLI has nothing to refresh: no log and no retry.
        if (step === "finding the host") continue;
        console.error(
          `BlindDrop: the ${HOSTS[host].name} integration could not be refreshed (${step} failed).`,
        );
        failed.push(host);
      }
    }
    return failed;
  }
}

export function createIntegrationManager(options) {
  return new IntegrationManager(options);
}
