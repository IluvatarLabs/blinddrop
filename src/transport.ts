import type { IncomingMessage } from "node:http";
import { validateHeaderName, validateHeaderValue } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { PassThrough, Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import {
  brotliDecompress,
  createBrotliDecompress,
  createGunzip,
  createInflate,
  gunzip,
  inflate,
  type BrotliOptions,
  type ZlibOptions,
} from "node:zlib";

import { BlindDropError } from "./errors.js";
import { resolveValidatedAddress, type ValidatedAddress } from "./netguard.js";
import type {
  ConsumeHttpsStream,
  Limits,
  SendHttps,
  SendHttpsStreaming,
  TransportRequest,
  TransportResponse,
} from "./types.js";

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function abortError(signal: AbortSignal): BlindDropError {
  return signal.reason instanceof BlindDropError
    ? signal.reason
    : new BlindDropError("SESSION_CLOSED");
}

function rawFieldsByteLength(fields: readonly string[]): number {
  return fields.reduce((total, field) => total + byteLength(field) + 2, 0);
}

function assertRequestLimits(request: TransportRequest): void {
  let headerBytes = 2;
  for (const [name, value] of Object.entries(request.headers)) {
    try {
      validateHeaderName(name);
      validateHeaderValue(name, value);
    } catch {
      throw new BlindDropError("INVALID_INPUT");
    }
    headerBytes += byteLength(name) + byteLength(value) + 4;
  }
  if (headerBytes > request.limits.headerBytes) {
    throw new BlindDropError("REQUEST_TOO_LARGE");
  }

  const total =
    byteLength(request.method) +
    byteLength(request.url.href) +
    headerBytes +
    (request.body?.length ?? 0);
  if (total > request.limits.requestBytes) {
    throw new BlindDropError("REQUEST_TOO_LARGE");
  }
}

async function resolveForRequest(
  request: TransportRequest,
): Promise<ValidatedAddress> {
  if (request.signal.aborted) {
    throw abortError(request.signal);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (
      error?: BlindDropError,
      address?: ValidatedAddress,
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      request.signal.removeEventListener("abort", onAbort);
      if (error) {
        reject(error);
      } else {
        resolve(address as ValidatedAddress);
      }
    };
    const onAbort = () => finish(abortError(request.signal));
    request.signal.addEventListener("abort", onAbort, { once: true });

    void resolveValidatedAddress(request.url.hostname, request.allowPrivate).then(
      (address) => {
        if (request.signal.aborted) {
          finish(abortError(request.signal));
          return;
        }
        finish(undefined, address);
      },
      (error: unknown) => finish(
        error instanceof BlindDropError
          ? error
          : new BlindDropError("DESTINATION_DENIED"),
      ),
    );
  });
}

function decodeWith(
  decoder: (
    data: NodeJS.ArrayBufferView,
    options: ZlibOptions | BrotliOptions,
    callback: (error: Error | null, result: Buffer) => void,
  ) => void,
  input: Buffer,
  limit: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    decoder(input, { maxOutputLength: limit + 1 }, (error, result) => {
      if (error) {
        const code = (error as NodeJS.ErrnoException).code;
        reject(new BlindDropError(
          code === "ERR_BUFFER_TOO_LARGE"
            ? "RESPONSE_TOO_LARGE"
            : "UNSUPPORTED_RESPONSE",
        ));
        return;
      }
      if (result.length > limit) {
        reject(new BlindDropError("RESPONSE_TOO_LARGE"));
        return;
      }
      resolve(result);
    });
  });
}

async function decodeBody(
  raw: Buffer,
  encoding: string | undefined,
  limit: number,
): Promise<Buffer> {
  switch (encoding?.trim().toLowerCase() || "identity") {
    case "identity":
      return raw;
    case "gzip":
      return decodeWith(gunzip, raw, limit);
    case "deflate":
      return decodeWith(inflate, raw, limit);
    case "br":
      return decodeWith(brotliDecompress, raw, limit);
    default:
      throw new BlindDropError("UNSUPPORTED_RESPONSE");
  }
}

function responseHeaders(response: IncomingMessage): Record<string, string> {
  const headers = Object.create(null) as Record<string, string>;
  for (const [name, value] of Object.entries(response.headers)) {
    if (value === undefined) {
      continue;
    }
    headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

function contentEncoding(rawHeaders: readonly string[]): string | undefined {
  const encodings = rawHeaders.flatMap((value, index) =>
    index % 2 === 0 && value.toLowerCase() === "content-encoding"
      ? [rawHeaders[index + 1]]
      : [],
  ).filter((value): value is string => typeof value === "string");
  if (encodings.length > 1 || encodings[0]?.includes(",")) {
    throw new BlindDropError("UNSUPPORTED_RESPONSE");
  }
  return encodings[0];
}

class ByteLimitTransform extends Transform {
  private total = 0;

  constructor(private readonly limit: number) {
    super();
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.total += data.length;
    if (this.total > this.limit) {
      callback(new BlindDropError("RESPONSE_TOO_LARGE"));
      return;
    }
    callback(null, data);
  }
}

function streamingDecoder(
  encoding: string | undefined,
): Transform | undefined {
  switch (encoding?.trim().toLowerCase() || "identity") {
    case "identity":
      return undefined;
    case "gzip":
      return createGunzip();
    case "deflate":
      return createInflate();
    case "br":
      return createBrotliDecompress();
    default:
      throw new BlindDropError("UNSUPPORTED_RESPONSE");
  }
}

function streamingError(
  error: unknown,
  signal: AbortSignal,
): BlindDropError {
  if (signal.aborted) {
    return abortError(signal);
  }
  if (error instanceof BlindDropError) {
    return error;
  }
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (typeof code === "string" && code.startsWith("Z_")) {
    return new BlindDropError("UNSUPPORTED_RESPONSE");
  }
  return new BlindDropError("UPSTREAM_ERROR");
}

function consumeResponse(
  response: IncomingMessage,
  method: string,
  signal: AbortSignal,
  limits: Limits,
): Promise<TransportResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let total = 0;
    const chunks: Buffer[] = [];
    const clearChunks = (): void => {
      for (const chunk of chunks) {
        chunk.fill(0);
      }
      chunks.length = 0;
    };
    const fail = (error: BlindDropError, destroy = false): void => {
      if (settled) {
        return;
      }
      settled = true;
      signal.removeEventListener("abort", onAbort);
      clearChunks();
      reject(error);
      if (destroy) {
        response.destroy();
      }
    };
    const onAbort = () => fail(abortError(signal), true);
    signal.addEventListener("abort", onAbort, { once: true });

    const rawHeaderBytes = rawFieldsByteLength(response.rawHeaders);
    if (rawHeaderBytes > limits.headerBytes) {
      fail(new BlindDropError("RESPONSE_TOO_LARGE"), true);
      return;
    }

    response.on("data", (chunk: Buffer) => {
      if (settled) {
        return;
      }
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += data.length;
      if (total > limits.responseBytes) {
        fail(new BlindDropError("RESPONSE_TOO_LARGE"), true);
        return;
      }
      chunks.push(data);
    });
    response.once("aborted", () => fail(new BlindDropError("UPSTREAM_ERROR")));
    response.once("error", () => fail(new BlindDropError("UPSTREAM_ERROR")));
    response.once("end", () => {
      if (settled) {
        return;
      }
      void (async () => {
        if (!response.complete) {
          throw new BlindDropError("UPSTREAM_ERROR");
        }
        if (
          rawHeaderBytes + rawFieldsByteLength(response.rawTrailers) >
          limits.headerBytes
        ) {
          throw new BlindDropError("RESPONSE_TOO_LARGE");
        }

        const rawBody = Buffer.concat(chunks, total);
        clearChunks();
        const bodylessByProtocol =
          method === "HEAD" ||
          response.statusCode === 204 ||
          response.statusCode === 304;
        const decoded = bodylessByProtocol && rawBody.length === 0
          ? rawBody
          : await decodeBody(
            rawBody,
            contentEncoding(response.rawHeaders),
            limits.responseBytes,
          );
        if (decoded !== rawBody) {
          rawBody.fill(0);
        }
        if (signal.aborted) {
          decoded.fill(0);
          throw abortError(signal);
        }

        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve({
          status: response.statusCode ?? 502,
          statusText: response.statusMessage ?? "",
          headers: responseHeaders(response),
          rawHeaders: [...response.rawHeaders],
          rawTrailers: [...response.rawTrailers],
          body: decoded,
        });
      })().catch((error: unknown) => fail(
        error instanceof BlindDropError
          ? error
          : new BlindDropError("UNSUPPORTED_RESPONSE"),
      ));
    });
  });
}

async function consumeStreamingResponse(
  response: IncomingMessage,
  method: string,
  signal: AbortSignal,
  limits: Limits,
  consume: ConsumeHttpsStream,
): Promise<void> {
  const rawHeaderBytes = rawFieldsByteLength(response.rawHeaders);
  if (rawHeaderBytes > limits.headerBytes) {
    throw new BlindDropError("RESPONSE_TOO_LARGE");
  }

  const bodylessByProtocol =
    method === "HEAD" || response.statusCode === 204 || response.statusCode === 304;
  const encodedLimit = new ByteLimitTransform(limits.responseBytes);
  const decodedLimit = new ByteLimitTransform(limits.responseBytes);
  const output = new PassThrough();
  const decoder = bodylessByProtocol
    ? undefined
    : streamingDecoder(contentEncoding(response.rawHeaders));
  const streams = decoder === undefined
    ? [response, encodedLimit, decodedLimit, output]
    : [response, encodedLimit, decoder, decodedLimit, output];
  let pipelineFailure: BlindDropError | undefined;
  const completed = pipeline(streams, { signal }).then(
    () => undefined,
    (error: unknown) => {
      pipelineFailure = streamingError(error, signal);
    },
  );

  try {
    await consume({
      status: response.statusCode ?? 502,
      statusText: response.statusMessage ?? "",
      rawHeaders: [...response.rawHeaders],
      body: output,
    });
    await completed;
    if (pipelineFailure !== undefined) {
      throw pipelineFailure;
    }
    if (signal.aborted) {
      throw abortError(signal);
    }
    if (!response.complete) {
      throw new BlindDropError("UPSTREAM_ERROR");
    }
    if (
      rawHeaderBytes + rawFieldsByteLength(response.rawTrailers) >
      limits.headerBytes
    ) {
      throw new BlindDropError("RESPONSE_TOO_LARGE");
    }
  } catch (error) {
    output.destroy();
    response.destroy();
    await completed;
    const consumerFailure = streamingError(error, signal);
    throw consumerFailure.code === "UPSTREAM_ERROR" && pipelineFailure
      ? pipelineFailure
      : consumerFailure;
  }
}

async function prepareTransportRequest(
  request: TransportRequest,
): Promise<{
  request: TransportRequest;
  address: ValidatedAddress;
  requestHostname: string;
}> {
  if (
    request.url.protocol !== "https:" ||
    request.url.username !== "" ||
    request.url.password !== "" ||
    request.method.length === 0
  ) {
    throw new BlindDropError("DESTINATION_DENIED");
  }
  const hostFields = Object.entries(request.headers).filter(([name]) => name.toLowerCase() === "host");
  if (hostFields.length > 1 || (hostFields.length === 1 && hostFields[0]?.[1] !== request.url.host)) {
    throw new BlindDropError("DESTINATION_DENIED");
  }
  const headers = Object.assign(Object.create(null), request.headers) as Record<string, string>;
  if (hostFields.length === 0) headers.host = request.url.host;
  request = { ...request, headers };
  assertRequestLimits(request);
  const address = await resolveForRequest(request);
  if (request.signal.aborted) {
    throw abortError(request.signal);
  }

  const requestHostname = request.url.hostname.startsWith("[") &&
    request.url.hostname.endsWith("]")
    ? request.url.hostname.slice(1, -1)
    : request.url.hostname;

  return { request, address, requestHostname };
}

async function sendWith<T>(
  input: TransportRequest,
  consume: (response: IncomingMessage, request: TransportRequest) => Promise<T>,
): Promise<T> {
  const { request, address, requestHostname } =
    await prepareTransportRequest(input);

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (
      error?: BlindDropError,
      response?: T,
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (error) {
        reject(error);
      } else {
        resolve(response as T);
      }
    };

    try {
      const outgoing = httpsRequest(
        {
          protocol: "https:",
          hostname: requestHostname,
          port: request.url.port || 443,
          servername: isIP(requestHostname) === 0 ? requestHostname : undefined,
          rejectUnauthorized: true,
          cert: request.tls?.cert,
          key: request.tls?.key,
          passphrase: request.tls?.passphrase,
          method: request.method,
          path: `${request.url.pathname}${request.url.search}`,
          headers: Object.entries(request.headers).flatMap(
            ([name, value]) => [name, value],
          ),
          agent: false,
          maxHeaderSize: request.limits.headerBytes,
          insecureHTTPParser: false,
          joinDuplicateHeaders: false,
          signal: request.signal,
          family: address.family,
          lookup: (_hostname, options, callback) => {
            if (options.all) {
              callback(null, [address]);
            } else {
              callback(null, address.address, address.family);
            }
          },
        },
        (response) => {
          void consume(response, request).then(
            (result) => finish(undefined, result),
            (error: unknown) => {
              response.destroy();
              finish(
                error instanceof BlindDropError
                  ? error
                  : new BlindDropError("UPSTREAM_ERROR"),
              );
            },
          );
        },
      );

      outgoing.once("error", (error: NodeJS.ErrnoException) => {
        if (request.signal.aborted) {
          finish(abortError(request.signal));
        } else if (error.code === "HPE_HEADER_OVERFLOW") {
          finish(new BlindDropError("RESPONSE_TOO_LARGE"));
        } else {
          finish(new BlindDropError("UPSTREAM_ERROR"));
        }
      });
      outgoing.end(request.body);
    } catch {
      finish(request.signal.aborted
        ? abortError(request.signal)
        : new BlindDropError("UPSTREAM_ERROR"));
    }
  });
}

export const sendHttps: SendHttps = async (
  request: TransportRequest,
): Promise<TransportResponse> => sendWith(
  request,
  (response, current) => consumeResponse(
    response,
    current.method,
    current.signal,
    current.limits,
  ),
);

export const sendHttpsStreaming: SendHttpsStreaming = async (
  request: TransportRequest,
  consume: ConsumeHttpsStream,
): Promise<void> => sendWith(
  request,
  (response, current) => consumeStreamingResponse(
    response,
    current.method,
    current.signal,
    current.limits,
    consume,
  ),
);
