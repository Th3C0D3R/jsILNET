import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";

const privateKeyPem = generateKeyPairSync("rsa", { modulusLength: 1024 })
  .privateKey.export({ format: "pem", type: "pkcs8" });
const listeners = new Map();
let resolveResponse;
globalThis.self = {
  addEventListener(type, listener) {
    listeners.set(type, listener);
  },
  postMessage(value) {
    resolveResponse(value);
  }
};
globalThis.Buffer = undefined;
globalThis.process = undefined;

await import(new URL("../dist/browser/worker.js?smoke", import.meta.url));

async function request(data) {
  const response = new Promise((resolve) => {
    resolveResponse = resolve;
  });
  await listeners.get("message")({ data });
  return response;
}

const input = Uint8Array.from(readFileSync(new URL("../test/fixtures/Fixture.dll", import.meta.url)));
let response = await request({ id: 1, type: "parse", input });
assert.equal(response.ok, true, response.error?.message);
response = await request({ id: 2, type: "state" });
assert.equal(response.ok, true, response.error?.message);
const answer = response.value.methods.find((method) => method.name === "Answer");
const instructionResponse = await request({
  id: 3,
  type: "call",
  name: "getInstructions",
  args: [answer.rid]
});
const instruction = instructionResponse.value.find((item) => item.opcode.name === "ldc.i4.s");
response = await request({
  id: 4,
  type: "call",
  name: "setInstructionOperand",
  args: [answer.rid, instruction.offset, 43]
});
assert.equal(response.ok, true, response.error?.message);
response = await request({ id: 5, type: "call", name: "serialize", args: [] });
assert.equal(response.ok, true, response.error?.message);
assert.ok(response.value instanceof Uint8Array);
response = await request({ id: 6, type: "call", name: "replaceStrongNamePublicKey", args: [privateKeyPem] });
assert.equal(response.ok, true, response.error?.message);
response = await request({ id: 7, type: "call", name: "serialize", args: [] });
assert.equal(response.ok, true, response.error?.message);
response = await request({ id: 8, type: "parse", input: response.value });
assert.equal(response.ok, true, response.error?.message);
response = await request({ id: 9, type: "call", name: "verifyStrongNameSignature", args: [] });
assert.equal(response.value, true);
console.log("Browser worker bundle passed its no-Node-globals smoke test.");
