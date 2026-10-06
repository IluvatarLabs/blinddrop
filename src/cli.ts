#!/usr/bin/env node

import { migrateConnections } from "./connection-store.js";
import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { dirname } from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

import { Command, CommanderError } from "commander";

import {
  createVault,
  defaultVaultPath,
  validateConnection,
  validateName
} from "./vault.js";
import {
  changePassphrase,
  disableConnection,
  disableSecret,
  importConnection,
  listMetadata,
  removeSecret,
  setConnection,
  setSecret,
  type ConnectionSetOptions
} from "./vault-admin.js";
import { BlindDropError, publicError } from "./errors.js";
import { startHttpSession, type HttpSession } from "./http.js";
import { readOwnerInput } from "./input.js";
import { serveMcp } from "./mcp.js";
import { readSettings, writeSettings } from "./owner-files.js";
import {
  oauthLogin,
  openSystemBrowser,
  readOAuthLoginDefinition,
} from "./oauth-login.js";
import { deleteSessionFile, writeSessionFile } from "./session-file.js";
import { createBrokerSession, type BrokerSession } from "./session.js";
import type { Connection } from "./types.js";
import { startOwnerUi, VERSION } from "./ui.js";

const MAX_CONNECTION_DEFINITION_BYTES = 64 * 1024;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const CHILD_SHUTDOWN_MS = 5_000;

interface GlobalOptions {
  vault: string;
  passwordFd?: string;
}

interface RunOptions {
  baseUrlEnv?: string;
  apiKeyEnv?: string;
  port?: string;
  ttl: string;
}

interface ChildExit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

function readConnectionDefinition(path: string): Connection {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new BlindDropError("INVALID_INPUT");
  }

  let descriptor: number | undefined;
  let contents: Buffer;
  try {
    descriptor = openSync(path, "r");
    const size = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_CONNECTION_DEFINITION_BYTES) {
      throw new BlindDropError("INVALID_INPUT");
    }

    contents = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const read = readSync(descriptor, contents, offset, size - offset, null);
      if (read === 0) {
        throw new BlindDropError("STORAGE_ERROR");
      }
      offset += read;
    }
    if (readSync(descriptor, Buffer.allocUnsafe(1), 0, 1, null) !== 0) {
      throw new BlindDropError("STORAGE_ERROR");
    }
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("STORAGE_ERROR");
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Preserve the fixed read or validation result.
      }
    }
  }

  let decoded: unknown;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(contents);
    decoded = JSON.parse(json);
  } catch {
    throw new BlindDropError("INVALID_INPUT");
  }
  return validateConnection(decoded);
}

function parseTtl(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const ttl = Number(value);
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 86_400) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return ttl;
}

function parsePort(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new BlindDropError("INVALID_INPUT");
  }
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return port;
}

function validateRunEnvironment(options: RunOptions): void {
  const baseUrlNames = ["BLINDDROP_BASE_URL", options.baseUrlEnv]
    .filter((name): name is string => name !== undefined);
  const tokenNames = ["BLINDDROP_TOKEN", options.apiKeyEnv]
    .filter((name): name is string => name !== undefined);

  for (const name of [...baseUrlNames, ...tokenNames]) {
    if (!ENVIRONMENT_NAME.test(name)) {
      throw new BlindDropError("INVALID_INPUT");
    }
  }

  const normalizedBaseUrlNames = new Set(baseUrlNames.map((name) => name.toUpperCase()));
  if (tokenNames.some((name) => normalizedBaseUrlNames.has(name.toUpperCase()))) {
    throw new BlindDropError("INVALID_INPUT");
  }
}

function mappedEnvironment(
  http: HttpSession,
  connection: string,
  options: RunOptions,
): NodeJS.ProcessEnv {
  const baseUrl = http.connections[connection];
  if (baseUrl === undefined) {
    throw new BlindDropError("INTERNAL_ERROR");
  }

  const environment = Object.assign(
    Object.create(null) as NodeJS.ProcessEnv,
    process.env,
  );
  const setEnvironment = (name: string, value: string): void => {
    if (process.platform === "win32") {
      const normalized = name.toUpperCase();
      for (const existing of Object.keys(environment)) {
        if (existing.toUpperCase() === normalized) {
          delete environment[existing];
        }
      }
    }
    environment[name] = value;
  };

  setEnvironment("BLINDDROP_BASE_URL", baseUrl);
  setEnvironment("BLINDDROP_TOKEN", http.token);
  if (options.baseUrlEnv !== undefined) setEnvironment(options.baseUrlEnv, baseUrl);
  if (options.apiKeyEnv !== undefined) setEnvironment(options.apiKeyEnv, http.token);
  return environment;
}

function childExit(child: ChildProcess): Promise<ChildExit> {
  return new Promise((resolve, reject) => {
    child.once("error", () => reject(new BlindDropError("INTERNAL_ERROR")));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

async function terminateChild(child: ChildProcess, closed: Promise<ChildExit>): Promise<ChildExit> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return closed;
  }
  child.kill("SIGTERM");
  const timer = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }, CHILD_SHUTDOWN_MS);
  try {
    return await closed;
  } finally {
    clearTimeout(timer);
  }
}

async function startOwnedHttpSession(
  session: BrokerSession,
  explicitPort?: number,
): Promise<HttpSession> {
  let http: HttpSession | undefined;
  try {
    const configDir = dirname(defaultVaultPath());
    const port = explicitPort ?? readSettings(configDir).sessionPort;
    http = await startHttpSession(session.broker, session.expiresAt, { port });
    if (explicitPort !== 0) {
      writeSettings(configDir, { sessionPort: Number(new URL(http.mcpUrl).port) });
    }
    return http;
  } catch (error) {
    if (http !== undefined) await http.close();
    else session.broker.close();
    throw error;
  }
}

async function runChild(
  http: HttpSession,
  connection: string,
  executable: string,
  args: string[],
  options: RunOptions,
): Promise<number> {
  const stop = () => {
    void http.close();
  };
  let listeningForSignals = false;

  try {
    const environment = mappedEnvironment(http, connection, options);
    const child = spawn(executable, args, {
      env: environment,
      shell: false,
      stdio: "inherit",
    });
    const closed = childExit(child);
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    listeningForSignals = true;

    const outcome = await Promise.race([
      closed.then((result) => ({ kind: "child" as const, result })),
      http.closed.then(() => ({ kind: "session" as const })),
    ]);
    if (outcome.kind === "child") {
      await http.close();
      return outcome.result.code ?? 1;
    }
    const result = await terminateChild(child, closed);
    return result.code ?? 1;
  } finally {
    if (listeningForSignals) {
      process.removeListener("SIGINT", stop);
      process.removeListener("SIGTERM", stop);
    }
    await http.close();
  }
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function writeLine(value: string): void {
  process.stdout.write(`${value}\n`);
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name("blinddrop")
    .description("Local encrypted credentials for authorized agent HTTP requests")
    .version(VERSION)
    .option("--vault <path>", "encrypted vault archive path", defaultVaultPath())
    .option("--password-fd <fd>", "read the vault passphrase from an inherited descriptor")
    .showSuggestionAfterError(false)
    .configureOutput({
      outputError: (_message, write) => {
        write(`${new BlindDropError("INVALID_INPUT").message}\n`);
      }
    });

  const globalOptions = (): GlobalOptions => program.opts<GlobalOptions>();
  const readPassphrase = async (confirm = false) => {
    const options = globalOptions();
    return readOwnerInput({
      fd: options.passwordFd,
      message: "Vault passphrase:",
      confirmMessage: confirm && options.passwordFd === undefined ? "Confirm vault passphrase:" : undefined
    });
  };

  program
    .command("init")
    .description("create a new encrypted vault")
    .action(async () => {
      const passphrase = await readPassphrase(true);
      createVault(globalOptions().vault, passphrase);
      writeLine("Vault initialized.");
    });

  program
    .command("passwd")
    .description("change the encrypted vault passphrase")
    .option("--new-password-fd <fd>", "read the new vault passphrase from an inherited descriptor")
    .action(async (options: { newPasswordFd?: string }) => {
      const currentPassphrase = await readPassphrase();
      const newPassphrase = await readOwnerInput({
        fd: options.newPasswordFd,
        message: "New vault passphrase:",
        confirmMessage: options.newPasswordFd === undefined
          ? "Confirm new vault passphrase:"
          : undefined,
      });
      changePassphrase(globalOptions().vault, currentPassphrase, newPassphrase);
      writeLine("Vault passphrase changed.");
    });

  const secret = program.command("secret").description("manage owner secrets");
  secret
    .command("set")
    .description("add or replace a secret")
    .argument("<name>", "stable secret name")
    .option("--secret-fd <fd>", "read the secret value from an inherited descriptor")
    .action(async (name: string, options: { secretFd?: string }) => {
      validateName(name);
      const passphrase = await readPassphrase();
      const value = await readOwnerInput({
        fd: options.secretFd,
        message: "Secret value:"
      });
      setSecret(globalOptions().vault, passphrase, name, value);
      writeLine("Secret saved for the next session.");
    });

  secret
    .command("disable")
    .description("disable a secret for newly started sessions")
    .argument("<name>", "secret name")
    .action(async (name: string) => {
      validateName(name);
      const passphrase = await readPassphrase();
      disableSecret(globalOptions().vault, passphrase, name);
      writeLine("Secret disabled for the next session. Stop any active session to revoke it.");
    });

  secret
    .command("remove")
    .description("remove an unreferenced secret")
    .argument("<name>", "secret name")
    .action(async (name: string) => {
      validateName(name);
      const passphrase = await readPassphrase();
      removeSecret(globalOptions().vault, passphrase, name);
      writeLine("Secret removed from the next session snapshot.");
    });

  const connection = program.command("connection").description("manage API connections");
  connection
    .command("set")
    .description("add or replace a connection")
    .argument("<name>", "connection name")
    .requiredOption("--origin <url>", "exact HTTPS origin")
    .requiredOption("--auth <type>", "authentication type: bearer, basic, header, or query")
    .option("--secret <reference>", "secret reference for bearer, header, or query authentication")
    .option("--username-secret <reference>", "username secret reference for basic authentication")
    .option("--password-secret <reference>", "password secret reference for basic authentication")
    .option("--field <name>", "header or query parameter name")
    .option("--allow-private", "allow this exact private or localhost destination")
    .action(async (name: string, options: ConnectionSetOptions) => {
      validateName(name);
      const passphrase = await readPassphrase();
      setConnection(globalOptions().vault, passphrase, name, options);
      writeLine("Connection saved and enabled for the next session.");
    });

  connection
    .command("import")
    .description("add or replace a connection from a bounded JSON definition")
    .argument("<name>", "connection name")
    .argument("<file>", "JSON connection definition")
    .action(async (name: string, file: string) => {
      validateName(name);
      const imported = readConnectionDefinition(file);
      const passphrase = await readPassphrase();
      importConnection(globalOptions().vault, passphrase, name, imported);
      writeLine("Connection imported for the next session.");
    });

  connection
    .command("disable")
    .description("disable a connection for newly started sessions")
    .argument("<name>", "connection name")
    .action(async (name: string) => {
      validateName(name);
      const passphrase = await readPassphrase();
      disableConnection(globalOptions().vault, passphrase, name);
      writeLine("Connection disabled for the next session. Stop any active session to revoke it.");
    });

  const oauth = program.command("oauth").description("manage owner OAuth grants");
  oauth
    .command("login")
    .description("authorize and save an OAuth refresh grant")
    .argument("<name>", "connection name")
    .argument("<file>", "bounded OAuth login JSON definition")
    .option("--no-browser", "print the authorization URL instead of opening the system browser")
    .action(async (name: string, file: string, options: { browser: boolean }) => {
      validateName(name);
      const definition = readOAuthLoginDefinition(file);
      const passphrase = await readPassphrase();
      const controller = new AbortController();
      const cancel = () => controller.abort(new BlindDropError("SESSION_CLOSED"));
      process.once("SIGINT", cancel);
      process.once("SIGTERM", cancel);
      try {
        await oauthLogin({
          vaultPath: globalOptions().vault,
          passphrase,
          name,
          definition,
          signal: controller.signal,
          visitAuthorizationUrl: options.browser
            ? openSystemBrowser
            : async (url) => writeLine(`Authorization URL: ${url}`),
        });
      } finally {
        process.removeListener("SIGINT", cancel);
        process.removeListener("SIGTERM", cancel);
      }
      writeLine("OAuth grant and connection saved for the next session.");
    });

  program
    .command("list")
    .description("list owner-visible secret and connection metadata")
    .action(async () => {
      const passphrase = await readPassphrase();
      const { vault, connections } = migrateConnections(globalOptions().vault, passphrase);
      writeLine(JSON.stringify(listMetadata(vault, connections), null, 2));
    });

  program
    .command("serve")
    .description("serve one finite, scoped MCP session")
    .requiredOption("--allow <connection>", "authorize an exact connection name", collect, [])
    .option("--http", "serve MCP and SDK requests on an authenticated loopback endpoint")
    .option("--port <port>", "loopback port for HTTP mode")
    .option("--ttl <seconds>", "session lifetime in seconds (maximum 86400)", "3600")
    .option("--session-file <path>", "publish this HTTP session's local endpoint and token to a 0600 file")
    .action(async (options: {
      allow: string[];
      http?: boolean;
      port?: string;
      ttl: string;
      sessionFile?: string;
    }) => {
      if (options.allow.length === 0) {
        throw new BlindDropError("INVALID_INPUT");
      }
      const ttl = parseTtl(options.ttl);
      const port = options.port === undefined ? undefined : parsePort(options.port);
      if (options.http !== true && (port !== undefined || options.sessionFile !== undefined)) {
        throw new BlindDropError("INVALID_INPUT");
      }
      const passphrase = await readPassphrase();
      const managed = migrateConnections(globalOptions().vault, passphrase);
      const session = createBrokerSession(
        [{ name: managed.context.vaultName, path: globalOptions().vault, passphrase }],
        options.allow,
        ttl,
        { connections: managed.connections },
      );
      if (options.http !== true) {
        await serveMcp(session.broker, session.expiresAt);
        return;
      }

      const http = await startOwnedHttpSession(session, port);
      const stop = () => {
        void http.close();
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      try {
        // Publish the session file before the readiness line, so a reader that
        // acts on readiness finds the file already in place.
        if (options.sessionFile !== undefined) {
          writeSessionFile(options.sessionFile, {
            mcpUrl: http.mcpUrl,
            token: http.token,
            expiresAt: http.expiresAt,
            connections: http.connections,
          });
        }
        writeLine(JSON.stringify({
          mcpUrl: http.mcpUrl,
          connections: http.connections,
          token: http.token,
          expiresAt: http.expiresAt,
        }));
        await http.closed;
      } finally {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        await http.close();
        if (options.sessionFile !== undefined) {
          deleteSessionFile(options.sessionFile);
        }
      }
    });

  program
    .command("ui")
    .description("serve the owner UI on an authenticated loopback endpoint")
    .option("--port <port>", "loopback port for the owner UI", "0")
    .option("--no-browser", "print the owner UI address instead of opening the system browser")
    .action(async (options: { port: string; browser: boolean }) => {
      const port = parsePort(options.port);
      // v0.5.1: the owner UI is registry-driven; the default vault is managed at
      // defaultVaultPath(). The --vault global still selects the archive for the
      // other single-vault subcommands.
      const ui = await startOwnerUi({ port });
      const stop = () => {
        void ui.close();
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      try {
        // The owner's own terminal is the only place this token is printed.
        writeLine(JSON.stringify({
          url: ui.url,
          token: ui.token,
          port: Number(new URL(ui.url).port),
        }));
        if (options.browser) {
          await openSystemBrowser(ui.launchUrl, new AbortController().signal);
        }
        await ui.closed;
      } finally {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        await ui.close();
      }
    });

  program
    .command("run")
    .description("run one command inside an authenticated local BlindDrop session")
    .argument("<connection>", "authorize one exact connection name")
    .option("--base-url-env <name>", "also set this environment variable to the local base URL")
    .option("--api-key-env <name>", "also set this environment variable to the session token")
    .option("--port <port>", "loopback port for the local session")
    .option("--ttl <seconds>", "session lifetime in seconds (maximum 86400)", "3600")
    .argument("<command>", "client executable after --")
    .argument("[args...]", "client arguments after --")
    .action(async (
      connection: string,
      executable: string,
      args: string[],
      options: RunOptions,
    ) => {
      validateName(connection);
      const ttl = parseTtl(options.ttl);
      const port = options.port === undefined ? undefined : parsePort(options.port);
      validateRunEnvironment(options);
      const passphrase = await readPassphrase();
      const managed = migrateConnections(globalOptions().vault, passphrase);
      const session = createBrokerSession(
        [{ name: managed.context.vaultName, path: globalOptions().vault, passphrase }],
        [connection],
        ttl,
        { connections: managed.connections },
      );
      const http = await startOwnedHttpSession(session, port);
      process.exitCode = await runChild(http, connection, executable, args, options);
    });

  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    if (error instanceof CommanderError) {
      process.exitCode = error.exitCode;
      return;
    }
    const safe = publicError(error);
    process.stderr.write(`${safe.code}: ${safe.message}\n`);
    process.exitCode = 1;
  }
}

await main();
