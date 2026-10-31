import test from "node:test";
import assert from "node:assert/strict";
import { decodeInstructions, encodeOperand, parseMethodBody } from "../src/index.js";
import { getOpcode } from "../src/il/opcodes.js";
import { createStructuralState, encodeMethodBody, insertInstruction } from "../src/il/rewrite.js";

test("decoder handles operands, branch offsets, switch, and FE-prefixed opcodes", () => {
  const code = Uint8Array.from([
    0x1f, 0x2a,             // ldc.i4.s 42
    0x2b, 0x00,             // br.s to the next instruction
    0x45, 0x01, 0, 0, 0,   // switch (one target)
    0x00, 0, 0, 0,          // target displacement: IL_000d
    0xfe, 0x01,             // ceq
    0x2a                    // ret
  ]);
  const instructions = decodeInstructions(code);
  assert.equal(instructions[0].operand.value, 42);
  assert.equal(instructions[1].operand.targetOffset, 4);
  assert.deepEqual(instructions[2].operand.targetOffsets, [13]);
  assert.equal(instructions[3].opcode.name, "ceq");
  assert.equal(instructions[4].opcode.name, "ret");
  assert.deepEqual([...encodeOperand(instructions[0], 41)], [41]);
  assert.deepEqual([...encodeOperand(instructions[2], [13])], [0, 0, 0, 0]);
  assert.throws(() => encodeOperand(instructions[2], [2 ** 40]), /32-bit displacement/);
});

test("tiny method body is decoded and fixed-width integer operands can be patched", () => {
  const body = parseMethodBody(Uint8Array.from([0x0e, 0x1f, 42, 0x2a]), 0);
  assert.equal(body.format, "tiny");
  assert.equal(body.codeSize, 3);
  assert.equal(body.instructions[0].operand.value, 42);
  assert.deepEqual([...encodeOperand(body.instructions[0], -4)], [0xfc]);
  assert.throws(() => encodeOperand(body.instructions[0], 128), /does not fit i1/);
});

test("fat method bodies parse aligned exception sections and validate regions", () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x300b, true);
  view.setUint16(2, 8, true);
  view.setUint32(4, 2, true);
  view.setUint32(8, 0, true);
  bytes.set([0x00, 0x2a], 12);
  bytes[16] = 0x01;
  bytes[17] = 16;
  view.setUint16(20, 2, true);
  view.setUint16(22, 0, true);
  bytes[24] = 1;
  view.setUint16(25, 1, true);
  bytes[27] = 1;
  view.setUint32(28, 0, true);
  const body = parseMethodBody(bytes, 0, 0x2000);
  assert.equal(body.format, "fat");
  assert.equal(body.sections[0].clauses[0].flags, 2);
  assert.equal(body.sections[0].clauses[0].handlerOffset, 1);
});

test("short branch edits refuse out-of-range displacements", () => {
  const instruction = decodeInstructions(Uint8Array.from([0x2b, 0x00, 0x2a]))[0];
  assert.throws(() => encodeOperand(instruction, 200), /short-branch/);
});

test("structural edits recalculate switch targets and promote a 64-byte body to fat format", () => {
  const switchBody = parseMethodBody(Uint8Array.from([
    0x2a, 0x45, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a
  ]), 0);
  const switchState = createStructuralState(switchBody);
  insertInstruction(switchState, 9, getOpcode(0x00));
  const rewrittenSwitch = parseMethodBody(encodeMethodBody(switchState, 0), 0);
  assert.deepEqual(rewrittenSwitch.instructions[0].operand.targetOffsets, [10]);

  const code = Uint8Array.from([...Array(62).fill(0), 0x2a]);
  const tinyBody = parseMethodBody(Uint8Array.from([(code.length << 2) | 2, ...code]), 0);
  const state = createStructuralState(tinyBody);
  insertInstruction(state, 62, getOpcode(0x00));
  const rewritten = parseMethodBody(encodeMethodBody(state, 0), 0);
  assert.equal(rewritten.codeSize, 64);
  assert.equal(rewritten.format, "fat");
});
