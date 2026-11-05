import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

let nextRequestId = 0;

function createWorker(workerFactory) {
  if (workerFactory) return workerFactory();
  if (typeof Worker === "undefined") {
    throw new Error("jsILNET browser APIs require Web Worker support");
  }
  return new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
}

function normalizeInput(input, transferInput) {
  if (typeof Blob !== "undefined" && input instanceof Blob) {
    return { input, transfer: [] };
  }
  if (input instanceof ArrayBuffer) {
    const buffer = transferInput ? input : input.slice(0);
    return { input: buffer, transfer: [buffer] };
  }
  if (input instanceof Uint8Array) {
    if (transferInput && input.buffer instanceof ArrayBuffer &&
        input.byteOffset === 0 && input.byteLength === input.buffer.byteLength) {
      return { input: input.buffer, transfer: [input.buffer] };
    }
    const bytes = Uint8Array.from(input);
    return { input: bytes.buffer, transfer: [bytes.buffer] };
  }
  throw new TypeError("Assembly input must be a Uint8Array, ArrayBuffer, or Blob");
}

function encodeCallbacks(value, callbacks, seen = new WeakMap()) {
  if (typeof value === "function") {
    const id = callbacks.size + 1;
    callbacks.set(id, value);
    return { __jsilnetCallback: id };
  }
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);
  if (typeof Blob !== "undefined" && value instanceof Blob) return value;
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
      output.set(encodeCallbacks(key, callbacks, seen), encodeCallbacks(item, callbacks, seen));
    }
  } else if (value instanceof Set) {
    for (const item of value) output.add(encodeCallbacks(item, callbacks, seen));
  } else if (Array.isArray(value)) {
    for (const item of value) output.push(encodeCallbacks(item, callbacks, seen));
  } else {
    for (const key of Object.keys(value)) {
      output[key] = encodeCallbacks(value[key], callbacks, seen);
    }
  }
  return output;
}

function decodeAssemblyReferences(value, assembly, seen = new WeakMap()) {
  if (value === null || typeof value !== "object") return value;
  if (value.__jsilnetAssembly === true) return assembly;
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
        decodeAssemblyReferences(key, assembly, seen),
        decodeAssemblyReferences(item, assembly, seen)
      );
    }
  } else if (value instanceof Set) {
    for (const item of value) output.add(decodeAssemblyReferences(item, assembly, seen));
  } else if (Array.isArray(value)) {
    for (const item of value) output.push(decodeAssemblyReferences(item, assembly, seen));
  } else {
    for (const key of Object.keys(value)) {
      output[key] = decodeAssemblyReferences(value[key], assembly, seen);
    }
  }
  return output;
}

async function encodeResolverResult(value, currentAssembly, seen = new WeakMap()) {
  if (value instanceof BrowserAssembly) {
    return value === currentAssembly
      ? { __jsilnetAssemblyReference: true }
      : { __jsilnetSerializedAssembly: await value.serialize() };
  }
  if (value === null || typeof value !== "object") {
    if (typeof value === "function" || typeof value === "symbol") {
      throw new TypeError("Resolver results must be structured-cloneable values");
    }
    return value;
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
        await encodeResolverResult(key, currentAssembly, seen),
        await encodeResolverResult(item, currentAssembly, seen)
      );
    }
  } else if (value instanceof Set) {
    for (const item of value) {
      output.add(await encodeResolverResult(item, currentAssembly, seen));
    }
  } else if (Array.isArray(value)) {
    for (const item of value) output.push(await encodeResolverResult(item, currentAssembly, seen));
  } else {
    for (const key of Object.keys(value)) {
      output[key] = await encodeResolverResult(value[key], currentAssembly, seen);
    }
  }
  return output;
}

function makeError(data) {
  const error = data?.name === "FormatError"
    ? new FormatError(data.message)
    : data?.name === "UnsupportedFormatError"
      ? new UnsupportedFormatError(data.message)
      : new Error(data?.message ?? "Browser worker request failed");
  if (data?.name && data.name !== "FormatError" && data.name !== "UnsupportedFormatError") {
    error.name = data.name;
  }
  if (data && "offset" in data) error.offset = data.offset;
  if (data && "context" in data) error.context = data.context;
  return error;
}

function addRvaMapper(pe) {
  if (!pe || !Array.isArray(pe.sections) || !Number.isInteger(pe.sectionOffset)) return pe;
  pe.rvaToOffset = (rva, size = 1) => {
    if (!Number.isInteger(rva) || !Number.isInteger(size) || rva < 0 || size < 0) {
      throw new FormatError("Invalid RVA range (RVA mapping)");
    }
    if (rva === 0 && size === 0) return 0;
    for (const section of pe.sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva < section.virtualAddress || rva - section.virtualAddress >= span) continue;
      const delta = rva - section.virtualAddress;
      if (delta + size > section.rawSize || section.rawPointer + delta + size > pe.bytes.length) {
        throw new FormatError(
          "RVA range is not backed by file data",
          { offset: section.rawPointer + delta, context: `section ${section.name}` }
        );
      }
      return section.rawPointer + delta;
    }
    if (rva < pe.sectionOffset && rva + size <= pe.bytes.length) return rva;
    throw new FormatError(`RVA 0x${rva.toString(16)} is not mapped by a PE section (RVA mapping)`);
  };
  return pe;
}

class WorkerClient {
  #worker;
  #pending = new Map();
  #onMessage;
  #onError;
  #onMessageError;
  #closed = false;

  constructor(worker) {
    this.#worker = worker;
    this.#onMessage = (event) => {
      const response = event.data;
      const pending = this.#pending.get(response?.id);
      if (!pending) return;
      if (response.type === "resolver") {
        void this.#resolveCallback(response, pending);
        return;
      }
      this.#pending.delete(response.id);
      if (response.ok) pending.resolve(response.value);
      else pending.reject(makeError(response.error));
    };
    this.#onError = (event) => {
      const error = event.error ?? new Error(event.message || "Browser worker failed");
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
      this.#close();
    };
    this.#onMessageError = () => {
      const error = new Error("Browser worker sent an uncloneable response");
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
      this.#close();
    };
    worker.addEventListener("message", this.#onMessage);
    worker.addEventListener("error", this.#onError);
    worker.addEventListener("messageerror", this.#onMessageError);
  }

  request(type, payload = {}, transfer = [], resolverOptions = {}) {
    if (this.#closed) {
      return Promise.reject(new Error("Browser worker is closed"));
    }
    const id = ++nextRequestId;
    return new Promise((resolve, reject) => {
      const callbacks = new Map();
      const encodedPayload = encodeCallbacks(payload, callbacks);
      this.#pending.set(id, { resolve, reject, callbacks, resolverOptions });
      try {
        this.#worker.postMessage({ id, type, ...encodedPayload }, transfer);
      } catch (error) {
        this.#pending.delete(id);
        if (error?.name === "DataCloneError") {
          reject(new TypeError("Browser Worker request contains a non-cloneable value"));
        } else {
          reject(error);
        }
      }
    });
  }

  async #resolveCallback(response, pending) {
    const callback = pending.callbacks.get(response.callbackId);
    try {
      if (!callback) throw new TypeError("Worker requested an unknown resolver callback");
      const args = pending.resolverOptions.decodeArguments
        ? pending.resolverOptions.decodeArguments(response.args)
        : response.args;
      const result = await callback(...args);
      if (this.#closed || !this.#pending.has(response.id)) return;
      const value = pending.resolverOptions.encodeResult
        ? await pending.resolverOptions.encodeResult(result)
        : result;
      if (this.#closed || !this.#pending.has(response.id)) return;
      this.#worker.postMessage({
        type: "resolverResult",
        id: response.id,
        resolverRequestId: response.resolverRequestId,
        ok: true,
        value
      });
    } catch (error) {
      if (this.#closed || !this.#pending.has(response.id)) return;
      this.#worker.postMessage({
        type: "resolverResult",
        id: response.id,
        resolverRequestId: response.resolverRequestId,
        ok: false,
        error: {
          name: error?.name ?? "Error",
          message: error?.message ?? String(error)
        }
      });
    }
  }

  dispose() {
    if (this.#closed) return;
    for (const pending of this.#pending.values()) {
      pending.reject(new Error("Browser worker was disposed"));
    }
    this.#pending.clear();
    this.#close();
  }

  #close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#worker.removeEventListener("message", this.#onMessage);
    this.#worker.removeEventListener("error", this.#onError);
    this.#worker.removeEventListener("messageerror", this.#onMessageError);
    this.#worker.terminate();
  }
}

export class BrowserAssembly {
  #client;
  #proxy;

  constructor(client) {
    this.#client = client;
  }

  static async from(input, { workerFactory, transferInput = false } = {}) {
    const normalizedInput = normalizeInput(input, transferInput);
    const worker = createWorker(workerFactory);
    const client = new WorkerClient(worker);
    const { input: inputValue, transfer } = normalizedInput;
    try {
      await client.request("parse", { input: inputValue }, transfer);
      const instance = new BrowserAssembly(client);
      instance.#proxy = new Proxy(instance, {
        get(target, property, receiver) {
          if (property === "then") return undefined;
          if (Reflect.has(target, property)) {
            const value = Reflect.get(target, property, target);
            return typeof value === "function" ? value.bind(target) : value;
          }
          if (typeof property === "string") {
            return (...args) => target.#call(property, args);
          }
          return undefined;
        }
      });
      return instance.#proxy;
    } catch (error) {
      client.dispose();
      throw error;
    }
  }

  async getState() {
    return this.#client.request("state");
  }

  async callUtility(name, ...args) {
    const result = await this.#client.request("utility", { name, args });
    return name === "parsePE" ? addRvaMapper(result) : result;
  }

  async #call(name, args) {
    const result = await this.#client.request(
      "call",
      { name, args },
      [],
      {
        decodeArguments: (value) => decodeAssemblyReferences(value, this.#proxy),
        encodeResult: (value) => encodeResolverResult(value, this.#proxy)
      }
    );
    return result?.__jsilnetAssembly === true ? this.#proxy : result;
  }

  dispose() {
    this.#client.dispose();
  }
}

export async function parseAssembly(input, options) {
  return BrowserAssembly.from(input, options);
}

export async function callUtility(name, ...args) {
  const worker = createWorker();
  const client = new WorkerClient(worker);
  try {
    const result = await client.request("utility", { name, args });
    return name === "parsePE" ? addRvaMapper(result) : result;
  } finally {
    client.dispose();
  }
}

export { BrowserAssembly as Assembly, FormatError, UnsupportedFormatError };
