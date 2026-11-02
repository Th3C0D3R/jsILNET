import { parseAssembly } from "jsilnet";

export const maxAssemblyBytes = 3 * 1024 * 1024;

export class DemoRequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function errorResponse(error) {
  if (error instanceof DemoRequestError) {
    return jsonResponse({ error: error.message }, error.status);
  }

  console.error("Live demo request failed:", error);
  return jsonResponse({ error: "The demo could not process this request." }, 500);
}

export async function readAssemblyRequest(request) {
  const contentType = request.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
  if (contentType !== "application/octet-stream") {
    throw new DemoRequestError(415, "Send the assembly as application/octet-stream.");
  }

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maxAssemblyBytes) {
    throw new DemoRequestError(413, "Assemblies must be 3 MiB or smaller.");
  }

  const reader = request.body?.getReader();
  if (!reader) throw new DemoRequestError(400, "The request did not contain an assembly.");

  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxAssemblyBytes) {
        await reader.cancel();
        throw new DemoRequestError(413, "Assemblies must be 3 MiB or smaller.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (total === 0) throw new DemoRequestError(400, "Choose a non-empty assembly file.");

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function parseUploadedAssembly(bytes) {
  try {
    return parseAssembly(bytes);
  } catch (error) {
    if (error instanceof Error) {
      throw new DemoRequestError(422, `Could not parse this assembly: ${error.message}`);
    }
    throw error;
  }
}
