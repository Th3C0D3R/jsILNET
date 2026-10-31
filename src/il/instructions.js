import { BinaryReader } from "../binary/reader.js";
import { FormatError } from "../binary/errors.js";
import { getOpcode } from "./opcodes.js";

const operandReaders = {
  none: () => undefined,
  u1: (reader) => reader.u1(),
  i1: (reader) => reader.i1(),
  u2: (reader) => reader.u2(),
  i4: (reader) => reader.i4(),
  i8: (reader) => reader.u8(),
  f4: (reader) => reader.f4(),
  f8: (reader) => reader.f8(),
  token: (reader) => reader.u4()
};

export function decodeInstructions(input, { baseOffset = 0, ilOffset = 0 } = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new BinaryReader(bytes, { baseOffset, context: "CIL instructions" });
  const instructions = [];
  while (reader.remaining > 0) {
    const start = reader.position;
    const first = reader.u1();
    const code = first === 0xfe ? 0xfe00 | reader.u1() : first;
    const opcode = getOpcode(code);
    if (!opcode) {
      throw new FormatError(`Unknown CIL opcode 0x${code.toString(16)}`, {
        offset: baseOffset + start,
        context: "CIL instructions"
      });
    }
    const operandOffset = baseOffset + reader.position;
    let operand;
    let patchOffsets = [];
    if (opcode.operand === "branch1" || opcode.operand === "branch4") {
      const displacement = opcode.operand === "branch1" ? reader.i1() : reader.i4();
      operand = { kind: "branch", targetOffset: reader.position + displacement + ilOffset };
      patchOffsets = [operandOffset];
    } else if (opcode.operand === "switch") {
      const count = reader.u4();
      if (count > Math.floor(reader.remaining / 4)) {
        throw new FormatError("Switch target count exceeds remaining method body", {
          offset: baseOffset + start,
          context: "CIL switch operand"
        });
      }
      const offsetsStart = reader.position;
      const displacements = Array.from({ length: count }, () => reader.i4());
      const base = reader.position + ilOffset;
      operand = {
        kind: "switch",
        targetOffsets: displacements.map((value) => base + value)
      };
      patchOffsets = displacements.map((_, index) => baseOffset + offsetsStart + index * 4);
    } else {
      const read = operandReaders[opcode.operand];
      if (!read) throw new FormatError(`Unsupported operand kind ${opcode.operand}`, { offset: baseOffset + start });
      const value = read(reader);
      operand = value === undefined ? null : { kind: opcode.operand, value };
      if (opcode.operand !== "none") patchOffsets = [operandOffset];
    }
    instructions.push({
      opcode,
      offset: start + ilOffset,
      size: reader.position - start,
      opcodeOffset: baseOffset + start,
      opcodeSize: first === 0xfe ? 2 : 1,
      operandOffset,
      patchOffsets,
      operand
    });
  }
  const boundaries = new Set(instructions.map((instruction) => instruction.offset));
  for (const instruction of instructions) {
    const targets = instruction.operand?.kind === "branch"
      ? [instruction.operand.targetOffset]
      : instruction.operand?.kind === "switch"
        ? instruction.operand.targetOffsets
        : [];
    for (const target of targets) {
      if (!boundaries.has(target)) {
        throw new FormatError(`Branch target IL_${target.toString(16)} is not an instruction boundary`, {
          offset: instruction.operandOffset,
          context: "CIL branch operand"
        });
      }
    }
  }
  return instructions;
}

export function encodeOpcode(opcode) {
  if (!opcode || !Number.isInteger(opcode.code) || opcode.code < 0 || opcode.code > 0xffff) {
    throw new TypeError("Invalid CIL opcode");
  }
  return opcode.code > 0xff
    ? Uint8Array.from([0xfe, opcode.code & 0xff])
    : Uint8Array.from([opcode.code]);
}

export function getInstructionSize(opcode, operand) {
  const opcodeSize = opcode.code > 0xff ? 2 : 1;
  const operandSize = {
    none: 0,
    u1: 1,
    i1: 1,
    u2: 2,
    i4: 4,
    i8: 8,
    f4: 4,
    f8: 8,
    token: 4,
    branch1: 1,
    branch4: 4,
    switch: 4 + 4 * (operand?.targetOffsets?.length ?? 0)
  }[opcode.operand];
  if (operandSize === undefined) throw new FormatError(`Unsupported operand kind ${opcode.operand}`);
  return opcodeSize + operandSize;
}

export function encodeInstruction(instruction) {
  const opcodeBytes = encodeOpcode(instruction.opcode);
  let operandBytes = new Uint8Array();
  if (instruction.operand) {
    const value = instruction.operand.kind === "branch"
      ? instruction.operand.targetOffset
      : instruction.operand.kind === "switch"
        ? instruction.operand.targetOffsets
        : instruction.operand.value;
    operandBytes = encodeOperand(instruction, value);
    if (instruction.operand.kind === "switch") {
      const count = new Uint8Array(4);
      new DataView(count.buffer).setUint32(0, instruction.operand.targetOffsets.length, true);
      const combined = new Uint8Array(count.length + operandBytes.length);
      combined.set(count);
      combined.set(operandBytes, count.length);
      operandBytes = combined;
    }
  }
  if (opcodeBytes.length + operandBytes.length !== instruction.size) {
    throw new FormatError("Encoded instruction size does not match the layout");
  }
  const result = new Uint8Array(instruction.size);
  result.set(opcodeBytes);
  result.set(operandBytes, opcodeBytes.length);
  return result;
}

export function formatInstruction(instruction) {
  const operand = instruction.operand;
  if (!operand) return `${instruction.opcode.name}`;
  if (operand.kind === "branch") return `${instruction.opcode.name} IL_${operand.targetOffset.toString(16).padStart(4, "0")}`;
  if (operand.kind === "switch") {
    return `${instruction.opcode.name} (${operand.targetOffsets.map((target) => `IL_${target.toString(16).padStart(4, "0")}`).join(", ")})`;
  }
  const value = typeof operand.value === "bigint" ? `${operand.value}n` : String(operand.value);
  return `${instruction.opcode.name} ${value}`;
}

export function encodeOperand(instruction, value) {
  const kind = instruction.operand?.kind;
  const buffer = new ArrayBuffer(instruction.size);
  const view = new DataView(buffer);
  if (kind === "branch") {
    const width = instruction.opcode.operand === "branch1" ? 1 : 4;
    const displacement = value - (instruction.offset + instruction.size);
    if (width === 1) {
      if (!Number.isInteger(displacement) || displacement < -128 || displacement > 127) {
        throw new RangeError("Branch target does not fit the existing short-branch operand");
      }
      view.setInt8(0, displacement);
      return new Uint8Array(buffer, 0, 1);
    }
    if (!Number.isInteger(displacement) || displacement < -0x80000000 || displacement > 0x7fffffff) {
      throw new RangeError("Branch target does not fit the existing branch operand");
    }
    view.setInt32(0, displacement, true);
    return new Uint8Array(buffer, 0, 4);
  }
  if (kind === "switch") {
    if (!Array.isArray(value) || value.length !== instruction.operand.targetOffsets.length) {
      throw new RangeError("A fixed-size edit must preserve the switch target count");
    }
    const baseOffset = instruction.offset + instruction.size;
    const result = new Uint8Array(value.length * 4);
    const switchView = new DataView(result.buffer);
    value.forEach((target, index) => {
      const displacement = target - baseOffset;
      if (!Number.isInteger(target) || displacement < -0x80000000 || displacement > 0x7fffffff) {
        throw new RangeError("Switch target does not fit its 32-bit displacement");
      }
      switchView.setInt32(index * 4, displacement, true);
    });
    return result;
  }
  const operandInfo = {
    u1: ["setUint8", 1], i1: ["setInt8", 1], u2: ["setUint16", 2], i4: ["setInt32", 4],
    i8: ["setBigInt64", 8], f4: ["setFloat32", 4], f8: ["setFloat64", 8], token: ["setUint32", 4]
  }[kind];
  if (!operandInfo) throw new TypeError("Instruction does not have a patchable fixed-size operand");
  const [setter, width] = operandInfo;
  if (kind === "token" || kind === "u1" || kind === "u2") {
    const max = width === 1 ? 0xff : width === 2 ? 0xffff : 0xffffffff;
    if (!Number.isInteger(value) || value < 0 || value > max) throw new RangeError(`Value does not fit ${kind}`);
  } else if (kind === "i1" && (!Number.isInteger(value) || value < -128 || value > 127)) {
    throw new RangeError("Value does not fit i1");
  } else if (kind === "i4" && (!Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff)) {
    throw new RangeError("Value does not fit i4");
  } else if (kind === "i8" && (typeof value !== "bigint" || value < -(1n << 63n) || value > (1n << 63n) - 1n)) {
    throw new RangeError("Value does not fit i8");
  } else if ((kind === "f4" || kind === "f8") && typeof value !== "number") {
    throw new TypeError("Floating-point operands must be numbers");
  }
  const result = new Uint8Array(width);
  new DataView(result.buffer)[setter](0, value, true);
  return result;
}
