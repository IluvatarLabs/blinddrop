import password from "@inquirer/password";
import { closeSync, createReadStream, openSync } from "node:fs";
import process from "node:process";
import { ReadStream, WriteStream } from "node:tty";
import { TextDecoder } from "node:util";

import { BlindDropError } from "./errors.js";

const MAX_OWNER_INPUT_BYTES = 64 * 1024;

export interface OwnerInputOptions {
  fd?: string;
  message: string;
  confirmMessage?: string;
}

function parseInheritedFd(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new BlindDropError("INVALID_INPUT");
  }

  const fd = Number(value);
  if (!Number.isSafeInteger(fd) || fd < 3) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return fd;
}

function removeOneTrailingNewline(value: string): string {
  if (value.endsWith("\r\n")) {
    return value.slice(0, -2);
  }
  if (value.endsWith("\n") || value.endsWith("\r")) {
    return value.slice(0, -1);
  }
  return value;
}

async function readInheritedInput(fdText: string): Promise<string> {
  const fd = parseInheritedFd(fdText);
  const stream = createReadStream("", { fd, autoClose: true });
  const chunks: Buffer[] = [];
  let size = 0;

  try {
    for await (const chunk of stream) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_OWNER_INPUT_BYTES + 2) {
        throw new BlindDropError("INVALID_INPUT");
      }
      chunks.push(bytes);
    }

    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    const value = removeOneTrailingNewline(decoded);
    if (Buffer.byteLength(value, "utf8") > MAX_OWNER_INPUT_BYTES) {
      throw new BlindDropError("INVALID_INPUT");
    }
    return value;
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("INPUT_UNAVAILABLE");
  } finally {
    stream.destroy();
  }
}

interface ControllingTerminal {
  input: ReadStream;
  output: WriteStream;
  close(): void;
}

function openControllingTerminal(): ControllingTerminal {
  const inputPath = process.platform === "win32" ? "CONIN$" : "/dev/tty";
  const outputPath = process.platform === "win32" ? "CONOUT$" : "/dev/tty";
  let inputFd: number | undefined;
  let outputFd: number | undefined;

  try {
    inputFd = openSync(inputPath, "r");
    outputFd = openSync(outputPath, "w");
    const input = new ReadStream(inputFd);
    const output = new WriteStream(outputFd);

    return {
      input,
      output,
      close() {
        input.destroy();
        output.destroy();
      }
    };
  } catch {
    if (inputFd !== undefined) {
      try {
        closeSync(inputFd);
      } catch {
        // Preserve the static public error below.
      }
    }
    if (outputFd !== undefined) {
      try {
        closeSync(outputFd);
      } catch {
        // Preserve the static public error below.
      }
    }
    throw new BlindDropError("INPUT_UNAVAILABLE");
  }
}

async function promptOnControllingTerminal(message: string): Promise<string> {
  const terminal = openControllingTerminal();
  try {
    return await password(
      {
        message,
        mask: "*",
        toggleMask: false
      },
      {
        input: terminal.input,
        output: terminal.output,
        clearPromptOnDone: true
      }
    );
  } catch {
    throw new BlindDropError("INPUT_UNAVAILABLE");
  } finally {
    terminal.close();
  }
}

export async function readOwnerInput(options: OwnerInputOptions): Promise<string> {
  if (options.fd !== undefined) {
    return readInheritedInput(options.fd);
  }

  const value = await promptOnControllingTerminal(options.message);
  if (options.confirmMessage === undefined) {
    return value;
  }

  const confirmation = await promptOnControllingTerminal(options.confirmMessage);
  if (confirmation !== value) {
    throw new BlindDropError("INVALID_INPUT");
  }
  return value;
}
