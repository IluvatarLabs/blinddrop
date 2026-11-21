import {
  McpServer,
  type CallToolResult,
  type StandardSchemaWithJSON
} from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import process from "node:process";
import { z } from "zod";

import type { Broker } from "./broker.js";
import { publicError } from "./errors.js";
import type { ModalInvokeInput, RequestInput } from "./types.js";

export const MAX_MCP_MESSAGE_BYTES = 2 * 1024 * 1024;

const requestSchema = z
  .object({
    connection: z.string(),
    method: z.string().optional(),
    path: z.string(),
    query: z.record(z.string(), z.string()).optional(),
    headers: z.record(z.string(), z.string()).optional(),
    body: z.string().optional(),
    bodyBase64: z.string().optional(),
    multipart: z
      .object({
        fields: z.record(z.string(), z.string()).optional(),
        files: z.array(
          z
            .object({
              name: z.string(),
              filename: z.string(),
              contentType: z.string().optional(),
              dataBase64: z.string()
            })
            .strict()
        )
      })
      .strict()
      .optional(),
    responseEncoding: z.enum(["utf8", "base64"]).optional()
  })
  .strict()
  .refine(
    (input) =>
      [input.body, input.bodyBase64, input.multipart].filter(
        (value) => value !== undefined
      ).length <= 1,
    { message: "Invalid input." }
  );

const modalSchema = z
  .object({
    connection: z.string(),
    args: z.array(z.unknown()).optional(),
    kwargs: z.record(z.string(), z.unknown()).optional()
  })
  .strict();

const listSchema = z.object({}).strict();

function staticValidation<T>(schema: z.ZodType<T>): StandardSchemaWithJSON<unknown, T> {
  const standard = schema["~standard"];
  return {
    "~standard": {
      ...standard,
      async validate(value: unknown) {
        const result = await standard.validate(value);
        if (result.issues !== undefined) {
          return { issues: [{ message: "Invalid input." }] };
        }
        return result;
      }
    }
  };
}

export type ToolName = "list_connections" | "execute_http" | "invoke_modal_function";

/** Answers one tool call whose input already passed that tool's schema. */
export type ToolHandler = (
  name: ToolName,
  input: unknown,
  signal: AbortSignal
) => Promise<CallToolResult>;

export function toolResult(value: object): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value
  };
}

export function errorResult(error: unknown): CallToolResult {
  const safe = publicError(error);
  const structuredContent = { error: safe };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(structuredContent) }],
    structuredContent
  };
}

/**
 * The one definition of the three tools (names, schemas and descriptions).
 * The owner runtime's endpoint, CLI `serve` and `blinddrop agent` all serve it,
 * so every description holds for each of them.
 */
export function createToolServer(handler: ToolHandler, instructions?: string): McpServer {
  const server = new McpServer(
    { name: "blinddrop", version: "0.6.2" },
    { capabilities: { tools: {} }, ...(instructions === undefined ? {} : { instructions }) }
  );

  server.registerTool(
    "list_connections",
    {
      title: "List authorized connections",
      description: "List the connections this BlindDrop session can use, with each connection's tool and usage guidance: an input example, notes and, for Modal, the owner-selected Function. A connection marked `available: false` is locked. Calling it asks the owner to unlock it in BlindDrop and returns `VAULT_LOCKED`; continue other work and call it again later.",
      inputSchema: staticValidation(listSchema)
    },
    (input, context) => handler("list_connections", input, context.mcpReq.signal)
  );

  server.registerTool(
    "execute_http",
    {
      title: "Execute authorized HTTP request",
      description: "Execute an HTTPS request through an authorized BlindDrop connection.",
      inputSchema: staticValidation(requestSchema)
    },
    (input, context) => handler("execute_http", input, context.mcpReq.signal)
  );

  server.registerTool(
    "invoke_modal_function",
    {
      title: "Invoke an authorized Modal Function",
      description: "Invoke only the owner-selected deployed Function of an authorized Modal connection, with JSON positional `args` and keyword `kwargs`, and return its JSON result. Call list_connections first for the connection's target and argument usage; do not guess the Function's arguments. Each call submits one invocation, which BlindDrop never resubmits; an error can mean the Function still ran.",
      inputSchema: staticValidation(modalSchema)
    },
    (input, context) => handler("invoke_modal_function", input, context.mcpReq.signal)
  );
  return server;
}

/** The tools as one broker serves them, with every listed connection available. */
export function brokerTools(
  broker: Broker,
  extraPatterns: readonly string[] = []
): ToolHandler {
  return async (name, input, signal) => {
    try {
      switch (name) {
        case "list_connections":
          return toolResult({ connections: broker.listConnections() });
        case "execute_http":
          return toolResult(await broker.execute(input as RequestInput, { extraPatterns, signal }));
        case "invoke_modal_function":
          return toolResult(await broker.invokeModal(input as ModalInvokeInput, { extraPatterns, signal }));
      }
    } catch (error) {
      return errorResult(error);
    }
  };
}

export function createMcpServer(
  broker: Broker,
  extraPatterns: readonly string[] = []
): McpServer {
  return createToolServer(brokerTools(broker, extraPatterns));
}

export async function serveMcp(
  initialBroker: Broker,
  expiresAt: number
): Promise<void> {
  let broker: Broker | undefined = initialBroker;
  let shutdownStarted = false;
  let finish: (() => void) | undefined;
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const server = createMcpServer(initialBroker);

  const transport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: MAX_MCP_MESSAGE_BYTES
  });

  const shutdown = async () => {
    if (shutdownStarted) {
      return;
    }
    shutdownStarted = true;

    process.stdin.off("end", onInputEnd);
    process.stdin.off("close", onInputEnd);
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    clearTimeout(expiryTimer);

    const activeBroker = broker;
    broker = undefined;
    try {
      activeBroker?.close();
    } finally {
      await server.close().catch(() => undefined);
      process.stdin.destroy();
      finish?.();
    }
  };

  const onInputEnd = () => {
    void shutdown();
  };
  const onSignal = () => {
    void shutdown();
  };
  const expiryDelay = Math.max(0, expiresAt - Date.now());
  const expiryTimer = setTimeout(() => {
    void shutdown();
  }, expiryDelay);

  process.stdin.once("end", onInputEnd);
  process.stdin.once("close", onInputEnd);
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  server.server.onclose = () => {
    void shutdown();
  };
  server.server.onerror = () => {
    process.stderr.write("MCP transport error.\n");
  };

  try {
    await server.connect(transport);
    await finished;
  } catch (error) {
    await shutdown();
    throw error;
  }
}
