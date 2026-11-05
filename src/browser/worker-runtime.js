import * as core from "../index.js";
import { Assembly, parseAssembly } from "../index.js";

const assemblyMethods = new Set(
  Object.getOwnPropertyNames(Assembly.prototype).filter((name) => name !== "constructor")
);

function cloneValue(value, assembly, seen = new WeakMap(), functionMode = "omit") {
  if (assembly !== null && value === assembly) return { __jsilnetAssembly: true };
  if (value === null || typeof value !== "object") {
    if (typeof value !== "function") return value;
    if (functionMode === "omit") return undefined;
    if (value.name === "rvaToOffset") return { __jsilnetFunction: "pe.rvaToOffset" };
    throw new TypeError("Browser utility returned an unsupported function-valued property");
  }
  if (seen.has(value)) return seen.get(value);
  if (value instanceof ArrayBuffer) return value.slice(0);
  if (ArrayBuffer.isView(value)) {
    if (value instanceof DataView) {
      return new DataView(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (value instanceof Uint8Array) return Uint8Array.from(value);
    return new value.constructor(value);
  }
  if (value instanceof Map) {
    const output = new Map();
    seen.set(value, output);
    for (const [key, item] of value) {
      output.set(
        cloneValue(key, assembly, seen, functionMode),
        cloneValue(item, assembly, seen, functionMode)
      );
    }
    return output;
  }
  if (value instanceof Set) {
    const output = new Set();
    seen.set(value, output);
    for (const item of value) output.add(cloneValue(item, assembly, seen, functionMode));
    return output;
  }
  if (Array.isArray(value)) {
    const output = [];
    seen.set(value, output);
    for (const item of value) output.push(cloneValue(item, assembly, seen, functionMode));
    return output;
  }
  const output = {};
  seen.set(value, output);
  for (const key of Object.keys(value)) {
    const item = cloneValue(value[key], assembly, seen, functionMode);
    if (item !== undefined) output[key] = item;
  }
  return output;
}

class ResolverRequest extends Error {
  constructor(callbackId, args) {
    super("Browser resolver callback required");
    this.callbackId = callbackId;
    this.args = args;
  }
}

function stableValue(value, assembly, seen = new WeakSet()) {
  if (assembly !== null && value === assembly) return { assembly: true };
  if (value === null || typeof value !== "object") {
    if (typeof value === "bigint") return `${value}n`;
    if (typeof value === "undefined") return "__undefined";
    return value;
  }
  if (seen.has(value)) return "__cycle";
  seen.add(value);
  if (value instanceof ArrayBuffer) return [...new Uint8Array(value)];
  if (ArrayBuffer.isView(value)) {
    return {
      type: value.constructor.name,
      values: [...new Uint8Array(value.buffer, value.byteOffset, value.byteLength)]
    };
  }
  if (value instanceof Map) {
    return [...value].map(([key, item]) => [
      stableValue(key, assembly, seen),
      stableValue(item, assembly, seen)
    ]);
  }
  if (value instanceof Set) return [...value].map((item) => stableValue(item, assembly, seen));
  if (Array.isArray(value)) return value.map((item) => stableValue(item, assembly, seen));
  return Object.fromEntries(Object.keys(value).sort().map((key) => [
    key,
    stableValue(value[key], assembly, seen)
  ]));
}

function decodeResolverResult(value, assembly, seen = new WeakMap()) {
  if (value === null || typeof value !== "object") return value;
  if (value.__jsilnetAssemblyReference === true) return assembly;
  if (value.__jsilnetSerializedAssembly instanceof Uint8Array) {
    return parseAssembly(value.__jsilnetSerializedAssembly);
  }
  if (seen.has(value)) return seen.get(value);
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value;
  const output = value instanceof Map
    ? new Map()
    : value instanceof Set
      ? new Set()
      : Array.isArray(value)
        ? []
        : {};
  seen.set(value, output);
  if (value instanceof Map) {
    for (const [key, item] of value) {
      output.set(
        decodeResolverResult(key, assembly, seen),
        decodeResolverResult(item, assembly, seen)
      );
    }
  } else if (value instanceof Set) {
    for (const item of value) output.add(decodeResolverResult(item, assembly, seen));
  } else if (Array.isArray(value)) {
    for (const item of value) output.push(decodeResolverResult(item, assembly, seen));
  } else {
    for (const key of Object.keys(value)) {
      output[key] = decodeResolverResult(value[key], assembly, seen);
    }
  }
  return output;
}

function restoreCallbacks(value, cache, assembly, seen = new WeakMap()) {
  if (value === null || typeof value !== "object") return value;
  if (Number.isInteger(value.__jsilnetCallback)) {
    const callbackId = value.__jsilnetCallback;
    return (...args) => {
      const key = `${callbackId}:${JSON.stringify(stableValue(args, assembly))}`;
      if (cache.has(key)) return cache.get(key);
      throw new ResolverRequest(callbackId, args);
    };
  }
  if (seen.has(value)) return seen.get(value);
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value;
  const output = value instanceof Map
    ? new Map()
    : value instanceof Set
      ? new Set()
      : Array.isArray(value)
        ? []
        : {};
  seen.set(value, output);
  if (value instanceof Map) {
    for (const [key, item] of value) {
      output.set(
        restoreCallbacks(key, cache, assembly, seen),
        restoreCallbacks(item, cache, assembly, seen)
      );
    }
  } else if (value instanceof Set) {
    for (const item of value) output.add(restoreCallbacks(item, cache, assembly, seen));
  } else if (Array.isArray(value)) {
    for (const item of value) output.push(restoreCallbacks(item, cache, assembly, seen));
  } else {
    for (const key of Object.keys(value)) {
      output[key] = restoreCallbacks(value[key], cache, assembly, seen);
    }
  }
  return output;
}

function getState(assembly) {
  const state = {};
  for (const key of Object.keys(assembly)) {
    if (!key.startsWith("_")) state[key] = cloneValue(assembly[key], assembly);
  }
  state.bytes = cloneValue(assembly.bytes, assembly);
  state.modified = assembly.modified;
  return state;
}

function serializeError(error) {
  return {
    name: error?.name ?? "Error",
    message: error?.message ?? String(error),
    offset: error?.offset,
    context: error?.context
  };
}

export function createWorkerController({ requestResolver } = {}) {
  let assembly = null;
  let nextResolverRequestId = 0;
  async function invokeWithResolvers(message, operation, input, activeAssembly, resolveCallback) {
    const resolverCache = new Map();
    while (true) {
      try {
        return operation(...restoreCallbacks(input, resolverCache, activeAssembly));
      } catch (error) {
        if (!(error instanceof ResolverRequest)) throw error;
        if (typeof resolveCallback !== "function") {
          throw new Error("Browser resolver callback channel is unavailable");
        }
        const resolverRequestId = ++nextResolverRequestId;
        const value = await new Promise((resolve, reject) => {
          resolveCallback(
            message.id,
            resolverRequestId,
            error.callbackId,
            cloneValue(error.args, activeAssembly),
            (response) => {
              if (response.ok) resolve(response.value);
              else {
                const failure = new Error(
                  response.error?.message ?? "Resolver callback failed"
                );
                failure.name = response.error?.name ?? "Error";
                reject(failure);
              }
            }
          );
        });
        const key = `${error.callbackId}:${JSON.stringify(
          stableValue(error.args, activeAssembly)
        )}`;
        resolverCache.set(key, decodeResolverResult(value, activeAssembly));
      }
    }
  }
  return async function handle(message, resolveCallback = requestResolver) {
    try {
      if (message?.type === "parse") {
        const input = typeof Blob !== "undefined" && message.input instanceof Blob
          ? await message.input.arrayBuffer()
          : message.input;
        assembly = parseAssembly(input);
        return { id: message.id, ok: true, value: null };
      }
      if (message?.type === "dispose") {
        assembly = null;
        return { id: message.id, ok: true, value: null };
      }
      if (message?.type === "state") {
        if (!assembly) throw new Error("No assembly has been loaded");
        return { id: message.id, ok: true, value: getState(assembly) };
      }
      if (message?.type === "call") {
        if (!assembly) throw new Error("No assembly has been loaded");
        if (!assemblyMethods.has(message.name)) {
          throw new TypeError(`Assembly method ${String(message.name)} is not available`);
        }
        const result = await invokeWithResolvers(
          message,
          (...args) => assembly[message.name](...args),
          message.args,
          assembly,
          resolveCallback
        );
        return {
          id: message.id,
          ok: true,
          value: result === assembly
            ? { __jsilnetAssembly: true }
            : cloneValue(result, assembly)
        };
      }
      if (message?.type === "utility") {
        const operation = core[message.name];
        if (typeof operation !== "function" || message.name === "parseAssembly") {
          throw new TypeError(`Library utility ${String(message.name)} is not available`);
        }
        const result = await invokeWithResolvers(
          message,
          operation,
          message.args,
          assembly,
          resolveCallback
        );
        return {
          id: message.id,
          ok: true,
          value: cloneValue(result, assembly, new WeakMap(), "encode")
        };
      }
      throw new TypeError("Unknown browser worker request");
    } catch (error) {
      return { id: message?.id, ok: false, error: serializeError(error) };
    }
  };
}
