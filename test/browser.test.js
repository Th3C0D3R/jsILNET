import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parseAssembly as parseBrowserAssembly } from "../src/browser/index.js";
import { createWorkerController } from "../src/browser/worker-runtime.js";

const fixture = readFileSync(new URL("./fixtures/Fixture.dll", import.meta.url));

class WorkerHarness {
  #handle = createWorkerController();
  #listeners = new Map();
  #pendingResolvers = new Map();
  terminated = false;

  addEventListener(type, listener) {
    this.#listeners.set(type, listener);
  }

  removeEventListener(type) {
    this.#listeners.delete(type);
  }

  postMessage(message) {
    if (message.type === "resolverResult") {
      const key = `${message.id}:${message.resolverRequestId}`;
      const resolve = this.#pendingResolvers.get(key);
      if (resolve) {
        this.#pendingResolvers.delete(key);
        resolve(message);
      }
      return;
    }
    const requestResolver = (id, resolverRequestId, callbackId, args, resolve) => {
      const key = `${id}:${resolverRequestId}`;
      this.#pendingResolvers.set(key, resolve);
      queueMicrotask(() => this.#listeners.get("message")?.({
        data: { type: "resolver", id, resolverRequestId, callbackId, args }
      }));
    };
    void this.#handle(message, requestResolver)
      .then((data) => this.#listeners.get("message")?.({ data }));
  }

  terminate() {
    this.terminated = true;
  }
}

test("browser worker controller parses, edits, and serializes an Assembly", async () => {
  const handle = createWorkerController();
  const parsed = await handle({ id: 1, type: "parse", input: fixture });
  assert.equal(parsed.ok, true);

  const state = await handle({ id: 2, type: "state" });
  assert.equal(state.ok, true);
  const answer = state.value.methods.find((method) => method.name === "Answer");
  assert.ok(answer);
  const instruction = state.value.methods.length > 0
    ? (await handle({ id: 3, type: "call", name: "getInstructions", args: [answer.rid] })).value
      .find((item) => item.opcode.name === "ldc.i4.s")
    : null;
  assert.ok(instruction);

  const edited = await handle({
    id: 4,
    type: "call",
    name: "setInstructionOperand",
    args: [answer.rid, instruction.offset, 43]
  });
  assert.deepEqual(edited.value, { __jsilnetAssembly: true });

  const output = await handle({ id: 5, type: "call", name: "serialize", args: [] });
  assert.equal(output.ok, true);
  assert.ok(output.value instanceof Uint8Array);
  const reparsed = await handle({ id: 6, type: "parse", input: output.value });
  assert.equal(reparsed.ok, true);
  const reparsedState = await handle({ id: 7, type: "state" });
  const reparsedAnswer = reparsedState.value.methods.find((method) => method.name === "Answer");
  const reparsedInstructions = await handle({
    id: 8,
    type: "call",
    name: "getInstructions",
    args: [reparsedAnswer.rid]
  });
  assert.equal(
    reparsedInstructions.value.find((item) => item.opcode.name === "ldc.i4.s").operand.value,
    43
  );
});

test("browser API exposes Assembly operations asynchronously through a worker", async () => {
  const worker = new WorkerHarness();
  const assembly = await parseBrowserAssembly(fixture, { workerFactory: () => worker });
  const state = await assembly.getState();
  const answer = state.methods.find((method) => method.name === "Answer");
  assert.equal(state.pe.rvaToOffset, undefined);
  const parsedPe = await assembly.callUtility("parsePE", fixture);
  assert.equal(typeof parsedPe.rvaToOffset, "function");
  const permissionSetBytes = Uint8Array.from([
    0x2e, 1, 1, 0x41, 15,
    1, 0, 0x53, 0x55, 4, 0x4d, 0x6f, 0x64, 0x65,
    1, 0x4d, 2, 0, 0, 0
  ]);
  const utilityPermissionSet = await assembly.callUtility(
    "parsePermissionSet",
    permissionSetBytes,
    async () => 0x08
  );
  assert.equal(utilityPermissionSet.attributes[0].namedArguments[0].value, 2);
  const resolvedEnums = [];
  const externalAttribute = await assembly.parseCustomAttribute(7, {
    resolveEnum: async (name) => {
      resolvedEnums.push(name);
      return 0x08;
    }
  });
  assert.match(resolvedEnums[0], /DebuggingModes/);
  assert.deepEqual(externalAttribute.fixedArguments, [2]);
  let resolvedTypes = 0;
  await assert.rejects(assembly.parseCustomAttribute(7, {
    resolveType: async (name, context) => {
      resolvedTypes++;
      assert.match(name, /DebuggableAttribute/);
      assert.equal(context.assembly, assembly);
      await context.assembly.getState();
      return undefined;
    }
  }), /not defined/);
  assert.ok(resolvedTypes >= 1);
  await assert.rejects(assembly.replaceCustomAttribute(7, externalAttribute, {
    resolveEnum: async () => {
      throw new Error("resolver failed");
    }
  }), /resolver failed/);
  assert.equal((await assembly.getState()).modified, false);
  let replacementResolverCalls = 0;
  assert.equal(await assembly.replaceCustomAttribute(7, externalAttribute, {
    resolveEnum: async () => {
      replacementResolverCalls++;
      return 0x08;
    }
  }), assembly);
  assert.equal(replacementResolverCalls, 1);
  const instructions = await assembly.getInstructions(answer.rid);
  const instruction = instructions.find((item) => item.opcode.name === "ldc.i4.s");
  const edited = await assembly.setInstructionOperand(answer.rid, instruction.offset, 43);
  assert.equal(edited, assembly);
  const output = await assembly.serialize();
  assert.ok(output instanceof Uint8Array);
  assembly.dispose();
  assert.equal(worker.terminated, true);
});

test("browser API accepts Blob input without copying its bytes on the page thread", async () => {
  const worker = new WorkerHarness();
  const assembly = await parseBrowserAssembly(new Blob([fixture]), {
    workerFactory: () => worker
  });
  const state = await assembly.getState();
  assert.equal(state.methods.some((method) => method.name === "Answer"), true);
  assembly.dispose();
});
