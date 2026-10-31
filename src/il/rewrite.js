import { FormatError } from "../binary/errors.js";
import { encodeInstruction, encodeOperand, getInstructionSize } from "./instructions.js";
import { getOpcode } from "./opcodes.js";

function findInstruction(instructions, offset) {
  const instruction = instructions.find((candidate) => candidate.offset === offset);
  if (!instruction) throw new RangeError(`No instruction begins at IL_${offset.toString(16)}`);
  return instruction;
}

function findBoundary(instructions, offset, codeSize, allowEnd = false) {
  if (allowEnd && offset === codeSize) return null;
  return findInstruction(instructions, offset);
}

function toClauseState(body, instructions) {
  const clauses = [];
  for (const section of body.sections) {
    for (const clause of section.clauses) {
      clauses.push({
        ...clause,
        tryStart: findBoundary(instructions, clause.tryOffset, body.codeSize),
        tryEnd: findBoundary(instructions, clause.tryOffset + clause.tryLength, body.codeSize, true),
        handlerStart: findBoundary(instructions, clause.handlerOffset, body.codeSize),
        handlerEnd: findBoundary(instructions, clause.handlerOffset + clause.handlerLength, body.codeSize, true),
        filterStart: (clause.flags & 1) !== 0
          ? findBoundary(instructions, clause.classTokenOrFilterOffset, body.codeSize)
          : null
      });
    }
  }
  return clauses;
}

function updateRegionOffsets(state) {
  const end = (instruction) => instruction?.offset ?? state.body.codeSize;
  for (const clause of state.clauses) {
    clause.tryOffset = clause.tryStart.offset;
    clause.tryLength = end(clause.tryEnd) - clause.tryOffset;
    clause.handlerOffset = clause.handlerStart.offset;
    clause.handlerLength = end(clause.handlerEnd) - clause.handlerOffset;
    if (clause.filterStart) clause.classTokenOrFilterOffset = clause.filterStart.offset;
  }
  state.body.sections = state.clauses.length > 0
    ? [{ clauses: state.clauses }]
    : [];
}

export function createStructuralState(body) {
  const instructions = body.instructions.map((instruction) => ({
    ...instruction,
    originalOffset: Object.hasOwn(instruction, "originalOffset")
      ? instruction.originalOffset
      : instruction.offset,
    operand: instruction.operand
      ? instruction.operand.kind === "switch"
        ? { kind: "switch", targetOffsets: [...instruction.operand.targetOffsets] }
        : { ...instruction.operand }
      : null,
    isNew: false
  }));
  const byOffset = new Map(instructions.map((instruction) => [instruction.offset, instruction]));
  const branchTargets = new Map();
  for (const instruction of instructions) {
    if (instruction.operand?.kind === "branch") {
      const target = byOffset.get(instruction.operand.targetOffset);
      if (!target) throw new FormatError("Branch target cannot be represented during structural editing");
      branchTargets.set(instruction, target);
    } else if (instruction.operand?.kind === "switch") {
      const targets = instruction.operand.targetOffsets.map((offset) => {
        const target = byOffset.get(offset);
        if (!target) throw new FormatError("Switch target cannot be represented during structural editing");
        return target;
      });
      branchTargets.set(instruction, targets);
    }
  }
  const state = {
    body: { ...body, instructions },
    instructions,
    branchTargets,
    clauses: toClauseState(body, instructions),
    maxStack: body.maxStack
  };
  layoutStructuralState(state);
  return state;
}

export function layoutStructuralState(state) {
  const maxPasses = state.instructions.length + 1;
  for (let pass = 0; pass < maxPasses; pass++) {
    let offset = 0;
    for (const instruction of state.instructions) {
      instruction.offset = offset;
      instruction.size = getInstructionSize(instruction.opcode, instruction.operand);
      instruction.opcodeSize = instruction.opcode.code > 0xff ? 2 : 1;
      offset += instruction.size;
    }
    state.body.codeSize = offset;

    let promoted = false;
    for (const instruction of state.instructions) {
      if (instruction.operand?.kind !== "branch") continue;
      const target = state.branchTargets.get(instruction);
      if (!target) throw new FormatError("Branch instruction has no resolved target");
      const displacement = target.offset - (instruction.offset + instruction.size);
      if (instruction.opcode.operand === "branch1" && (displacement < -128 || displacement > 127)) {
        if (instruction.opcode.longBranch === null || instruction.opcode.longBranch === undefined) {
          throw new FormatError(`Short branch ${instruction.opcode.name} has no long form`);
        }
        instruction.opcode = getOpcode(instruction.opcode.longBranch);
        promoted = true;
      } else if (instruction.opcode.operand === "branch4" &&
                 (displacement < -0x80000000 || displacement > 0x7fffffff)) {
        throw new RangeError("Branch target exceeds the 32-bit displacement range");
      }
    }
    if (!promoted) {
      for (const instruction of state.instructions) {
        if (instruction.operand?.kind === "branch") {
          instruction.operand.targetOffset = state.branchTargets.get(instruction).offset;
        } else if (instruction.operand?.kind === "switch") {
          instruction.operand.targetOffsets = state.branchTargets.get(instruction).map((target) => target.offset);
        }
      }
      updateRegionOffsets(state);
      return state;
    }
  }
  throw new FormatError("Branch layout did not converge");
}

function resolveTargets(state, opcode, value) {
  if (opcode.operand === "branch1" || opcode.operand === "branch4") {
    if (!Number.isInteger(value)) throw new TypeError("Branch operand must be an IL offset");
    const target = state.instructions.find((instruction) => instruction.offset === value);
    if (!target) throw new RangeError(`Branch target IL_${value.toString(16)} is not an instruction boundary`);
    return { operand: { kind: "branch", targetOffset: value }, targets: target };
  }
  if (opcode.operand === "switch") {
    if (!Array.isArray(value)) throw new TypeError("Switch operand must be an array of IL target offsets");
    const targets = value.map((targetOffset) => {
      const target = state.instructions.find((instruction) => instruction.offset === targetOffset);
      if (!target) throw new RangeError(`Switch target IL_${targetOffset.toString(16)} is not an instruction boundary`);
      return target;
    });
    return { operand: { kind: "switch", targetOffsets: [...value] }, targets };
  }
  if (opcode.operand === "none") {
    if (value !== undefined) throw new TypeError(`${opcode.name} does not accept an operand`);
    return { operand: null, targets: null };
  }
  return { operand: { kind: opcode.operand, value }, targets: null };
}

function makeInstruction(state, opcode, value) {
  const { operand, targets } = resolveTargets(state, opcode, value);
  const instruction = {
    opcode,
    operand,
    offset: 0,
    size: getInstructionSize(opcode, operand),
    opcodeSize: opcode.code > 0xff ? 2 : 1,
    opcodeOffset: null,
    operandOffset: null,
    patchOffsets: [],
    originalOffset: null,
    isNew: true
  };
  if (targets !== null) state.branchTargets.set(instruction, targets);
  if (operand && operand.kind !== "branch" && operand.kind !== "switch") {
    encodeOperand(instruction, operand.value);
  }
  return instruction;
}

function isExceptionBoundary(state, instruction, isEnd = false) {
  if (isEnd && instruction === null) return state.clauses.some((clause) =>
    clause.tryEnd === null || clause.handlerEnd === null
  );
  return state.clauses.some((clause) =>
    clause.tryStart === instruction || clause.tryEnd === instruction ||
    clause.handlerStart === instruction || clause.handlerEnd === instruction ||
    clause.filterStart === instruction
  );
}

export function insertInstruction(state, beforeOffset, opcode, value) {
  const codeSize = state.body.codeSize;
  let index;
  let before;
  if (beforeOffset === codeSize) {
    index = state.instructions.length;
    before = null;
  } else {
    before = findInstruction(state.instructions, beforeOffset);
    index = state.instructions.indexOf(before);
  }
  if (isExceptionBoundary(state, before, before === null)) {
    throw new FormatError("Insertions at exception-handler boundaries are ambiguous");
  }
  const instruction = makeInstruction(state, opcode, value);
  state.instructions.splice(index, 0, instruction);
  layoutStructuralState(state);
  return instruction;
}

export function removeInstruction(state, offset) {
  const instruction = findInstruction(state.instructions, offset);
  if (isExceptionBoundary(state, instruction)) {
    throw new FormatError("Cannot remove an exception-handler boundary instruction");
  }
  for (const targets of state.branchTargets.values()) {
    if (Array.isArray(targets) ? targets.includes(instruction) : targets === instruction) {
      throw new FormatError("Cannot remove an instruction targeted by a branch");
    }
  }
  state.instructions.splice(state.instructions.indexOf(instruction), 1);
  state.branchTargets.delete(instruction);
  layoutStructuralState(state);
  return instruction;
}

export function updateStructuralOperand(state, instruction, value) {
  if (instruction.operand?.kind === "branch") {
    const targets = resolveTargets(state, instruction.opcode, value);
    state.branchTargets.set(instruction, targets.targets);
    instruction.operand = targets.operand;
  } else if (instruction.operand?.kind === "switch") {
    const targets = resolveTargets(state, instruction.opcode, value);
    state.branchTargets.set(instruction, targets.targets);
    instruction.operand = targets.operand;
  } else {
    const operand = instruction.operand;
    if (!operand) throw new TypeError("Instruction has no operand");
    const candidate = { ...instruction, operand: { ...operand, value } };
    encodeOperand(candidate, value);
    instruction.operand = candidate.operand;
  }
  layoutStructuralState(state);
}

function appendU1(bytes, value) {
  bytes.push(value & 0xff);
}

function appendU2(bytes, value) {
  bytes.push(value & 0xff, (value >>> 8) & 0xff);
}

function appendU4(bytes, value) {
  bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function alignBytes(bytes, alignment, rva = 0) {
  while (((rva + bytes.length) & (alignment - 1)) !== 0) bytes.push(0);
}

function encodeExceptionSection(clauses, bodyBytes, methodRva) {
  if (clauses.length === 0) return;
  alignBytes(bodyBytes, 4, methodRva);
  const small = clauses.length <= 20 && clauses.every((clause) =>
    clause.flags <= 0xffff &&
    clause.tryOffset <= 0xffff &&
    clause.tryLength <= 0xff &&
    clause.handlerOffset <= 0xffff &&
    clause.handlerLength <= 0xff
  );
  const clauseSize = small ? 12 : 24;
  const dataSize = 4 + clauses.length * clauseSize;
  if (dataSize > 0xffffff) throw new RangeError("Exception-handler section exceeds the CLI size limit");
  appendU1(bodyBytes, 0x01 | (small ? 0 : 0x40));
  if (small) {
    appendU1(bodyBytes, dataSize);
    appendU2(bodyBytes, 0);
    for (const clause of clauses) {
      appendU2(bodyBytes, clause.flags);
      appendU2(bodyBytes, clause.tryOffset);
      appendU1(bodyBytes, clause.tryLength);
      appendU2(bodyBytes, clause.handlerOffset);
      appendU1(bodyBytes, clause.handlerLength);
      appendU4(bodyBytes, clause.classTokenOrFilterOffset);
    }
  } else {
    appendU1(bodyBytes, dataSize & 0xff);
    appendU1(bodyBytes, (dataSize >>> 8) & 0xff);
    appendU1(bodyBytes, (dataSize >>> 16) & 0xff);
    for (const clause of clauses) {
      appendU4(bodyBytes, clause.flags);
      appendU4(bodyBytes, clause.tryOffset);
      appendU4(bodyBytes, clause.tryLength);
      appendU4(bodyBytes, clause.handlerOffset);
      appendU4(bodyBytes, clause.handlerLength);
      appendU4(bodyBytes, clause.classTokenOrFilterOffset);
    }
  }
}

export function encodeMethodBody(state, methodRva) {
  layoutStructuralState(state);
  const encodedInstructions = state.instructions.map(encodeInstruction);
  const codeSize = encodedInstructions.reduce((size, instruction) => size + instruction.length, 0);
  const code = new Uint8Array(codeSize);
  let codeOffset = 0;
  for (const instruction of encodedInstructions) {
    code.set(instruction, codeOffset);
    codeOffset += instruction.length;
  }
  const clauses = state.clauses;
  const hasSections = clauses.length > 0;
  const initLocals = (state.body.flags & 0x10) !== 0;
  const localVarSigToken = state.body.localVarSigToken;
  const maxStack = Math.max(state.maxStack, hasSections ? 1 : 0);
  const unknownFlags = state.body.flags & ~(0x03 | 0x08 | 0x10);
  const tiny = codeSize < 64 && maxStack <= 8 && localVarSigToken === 0 &&
    !hasSections && !initLocals && unknownFlags === 0;
  const output = [];
  if (tiny) {
    appendU1(output, (codeSize << 2) | 0x02);
  } else {
    if (codeSize > 0xffffffff || maxStack > 0xffff) throw new RangeError("Method body exceeds CLI header limits");
    const flagsAndSize = 0x3003 | (hasSections ? 0x08 : 0) | (initLocals ? 0x10 : 0);
    appendU2(output, flagsAndSize);
    appendU2(output, maxStack);
    appendU4(output, codeSize);
    appendU4(output, localVarSigToken);
  }
  for (const byte of code) output.push(byte);
  if (hasSections) encodeExceptionSection(clauses, output, methodRva);
  return Uint8Array.from(output);
}
