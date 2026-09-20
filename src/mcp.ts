import { McpServer, type StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import process from "node:process";
import { z } from "zod";

import type { Broker } from "./broker.js";
import { publicError } from "./errors.js";
import type { RequestInput } from "./types.js";

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

function errorResult(error: unknown) {
  const safe = publicError(error);
  const structuredContent = { error: safe };
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }],
    structuredContent
  };
}

export function createMcpServer(
  broker: Broker,
  extraPatterns: readonly string[] = []
): McpServer {
  const server = new McpServer(
    { name: "blinddrop", version: "0.5.1" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "list_connections",
    {
      title: "List authorized connections",
      description: "List metadata for connections authorized in this BlindDrop session.",
      inputSchema: staticValidation(listSchema)
    },
    async () => {
      try {
        const structuredContent = { connections: broker.listConnections() };
        return {
          content: [{ type: "text", text: JSON.stringify(structuredContent) }],
          structuredContent
        };
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "execute_http",
    {
      title: "Execute authorized HTTP request",
      description: "Execute an HTTPS request through an authorized BlindDrop connection.",
      inputSchema: staticValidation(requestSchema)
    },
    async (input, context) => {
      try {
        const result = await broker.execute(input as RequestInput, {
          extraPatterns, signal: context.mcpReq.signal
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result
        };
      } catch (error) {
        return errorResult(error);
      }
    }
  );
  return server;
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
