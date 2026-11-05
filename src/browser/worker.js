import { createWorkerController } from "./worker-runtime.js";

const handle = createWorkerController();
const pendingResolvers = new Map();

function collectTransferables(value, transferables = new Set(), seen = new WeakSet()) {
  if (value === null || typeof value !== "object" || seen.has(value)) return transferables;
  seen.add(value);
  if (value instanceof ArrayBuffer) {
    transferables.add(value);
  } else if (ArrayBuffer.isView(value)) {
    if (value.buffer instanceof ArrayBuffer) transferables.add(value.buffer);
  } else if (value instanceof Map) {
    for (const [key, item] of value) {
      collectTransferables(key, transferables, seen);
      collectTransferables(item, transferables, seen);
    }
  } else if (value instanceof Set || Array.isArray(value)) {
    for (const item of value) collectTransferables(item, transferables, seen);
  } else {
    for (const item of Object.values(value)) collectTransferables(item, transferables, seen);
  }
  return transferables;
}

function requestResolver(id, resolverRequestId, callbackId, args, resolve) {
  const key = `${id}:${resolverRequestId}`;
  pendingResolvers.set(key, resolve);
  const request = { type: "resolver", id, resolverRequestId, callbackId, args };
  self.postMessage(request, [...collectTransferables(request)]);
}

self.addEventListener("message", async (event) => {
  const message = event.data;
  if (message?.type === "resolverResult") {
    const key = `${message.id}:${message.resolverRequestId}`;
    const resolve = pendingResolvers.get(key);
    if (!resolve) return;
    pendingResolvers.delete(key);
    resolve(message);
    return;
  }
  const response = await handle(message, (id, resolverRequestId, callbackId, args, resolve) => {
    requestResolver(id, resolverRequestId, callbackId, args, resolve);
  });
  self.postMessage(response, [...collectTransferables(response)]);
});
