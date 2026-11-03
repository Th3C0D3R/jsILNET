import { FormatError } from "../binary/errors.js";
import { encodeOpcode } from "../il/instructions.js";
import { listOpcodes } from "../il/opcodes.js";
import {
  insertInstruction,
  layoutStructuralState,
  removeInstruction,
  updateStructuralOperand
} from "../il/rewrite.js";
import { createOperandPatches } from "../writer/patch.js";
import { metadataTableNames } from "../metadata/tables.js";

export function createInstructionEditor(assembly, hooks) {
  return {
    setInstructionOperand(methodRid, instructionOffset, value) {
      hooks.ensureEditable();
      const body = assembly.getMethodBody(methodRid);
      if (!body) throw new FormatError("Method has no CIL body");
      const instruction = body.instructions.find((candidate) => candidate.offset === instructionOffset);
      if (!instruction) throw new RangeError(`No instruction begins at IL_${instructionOffset.toString(16)}`);
      if (!instruction.operand) throw new TypeError("Instruction has no operand");

      if (instruction.operand.kind === "branch") {
        hooks.validateBranchTarget(body, value);
      } else if (instruction.operand.kind === "switch") {
        if (!Array.isArray(value)) throw new TypeError("Switch operand must be an array of IL target offsets");
        for (const target of value) hooks.validateBranchTarget(body, target);
      } else if (instruction.opcode.name === "ldstr") {
        if (!Number.isInteger(value) || (value >>> 24) !== 0x70) {
          throw new TypeError("ldstr operand must be a 0x70-prefixed user-string token");
        }
        assembly.heaps.getUserString(value);
      } else if (instruction.operand.kind === "token") {
        if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
          throw new RangeError("Metadata token must be an unsigned 32-bit integer");
        }
        const table = value >>> 24;
        const rid = value & 0x00ffffff;
        if (!hooks.allowedTokenTables(instruction.opcode.name).includes(table)) {
          throw new FormatError(`Metadata table ${table} is not valid for ${instruction.opcode.name}`);
        }
        if (rid === 0 || rid > (assembly.tables.counts[table] ?? 0)) {
          throw new RangeError(
            `${instruction.opcode.name} references missing ${metadataTableNames[table]} row ${rid}`
          );
        }
        hooks.validateInstructionGenericContext(assembly, methodRid, instruction, value);
      }

      if (instruction.operand.kind === "branch" && instruction.operand.targetOffset === value) return assembly;
      if (instruction.operand.kind === "switch" &&
          instruction.operand.targetOffsets.length === value.length &&
          instruction.operand.targetOffsets.every((target, index) => target === value[index])) return assembly;
      if (instruction.operand.kind !== "branch" && instruction.operand.kind !== "switch" &&
          instruction.operand.value === value) return assembly;

      if (assembly._structuralBodies.has(methodRid) || assembly._addedMethodBodies.has(methodRid)) {
        const state = hooks.createStructuralState(methodRid);
        const editableInstruction = state.instructions.find((candidate) => candidate.offset === instructionOffset);
        updateStructuralOperand(state, editableInstruction, value);
        hooks.commitStructuralState(methodRid, state);
      } else {
        const patches = createOperandPatches(instruction, value);
        for (const patch of patches) assembly._patches.push(patch);
        instruction.operand = instruction.operand.kind === "branch"
          ? { kind: "branch", targetOffset: value }
          : instruction.operand.kind === "switch"
            ? { kind: "switch", targetOffsets: [...value] }
            : { ...instruction.operand, value };
      }
      return assembly;
    },

    setInstructionOpcode(methodRid, instructionOffset, opcodeNameOrCode) {
      hooks.ensureEditable();
      const body = assembly.getMethodBody(methodRid);
      if (!body) throw new FormatError("Method has no CIL body");
      const instruction = body.instructions.find((candidate) => candidate.offset === instructionOffset);
      if (!instruction) throw new RangeError(`No instruction begins at IL_${instructionOffset.toString(16)}`);
      const opcode = listOpcodes().find((candidate) =>
        candidate.name === opcodeNameOrCode || candidate.code === opcodeNameOrCode
      );
      if (!opcode) throw new RangeError(`Unknown CIL opcode ${opcodeNameOrCode}`);
      const encoded = encodeOpcode(opcode);
      if (encoded.length !== instruction.opcodeSize || opcode.operand !== instruction.opcode.operand) {
        throw new FormatError("Opcode edit must preserve the opcode and operand widths");
      }
      if (opcode.code === instruction.opcode.code) return assembly;
      if (instruction.operand?.kind === "token") {
        if (opcode.name !== "ldstr") {
          const table = instruction.operand.value >>> 24;
          const rid = instruction.operand.value & 0x00ffffff;
          if (!hooks.allowedTokenTables(opcode.name).includes(table)) {
            throw new FormatError(`Metadata table ${table} is not valid for ${opcode.name}`);
          }
          if (rid === 0 || rid > (assembly.tables.counts[table] ?? 0)) {
            throw new RangeError(
              `${opcode.name} references missing ${metadataTableNames[table]} row ${rid}`
            );
          }
          hooks.validateInstructionGenericContext(
            assembly, methodRid, { ...instruction, opcode }, instruction.operand.value
          );
        }
      }
      if (assembly._structuralBodies.has(methodRid) || assembly._addedMethodBodies.has(methodRid)) {
        const state = hooks.createStructuralState(methodRid);
        const editableInstruction = state.instructions.find((candidate) => candidate.offset === instructionOffset);
        editableInstruction.opcode = opcode;
        layoutStructuralState(state);
        hooks.commitStructuralState(methodRid, state);
      } else {
        assembly._patches.push({ offset: instruction.opcodeOffset, bytes: encoded });
        instruction.opcode = opcode;
      }
      return assembly;
    },

    insertInstruction(methodRid, beforeOffset, opcodeNameOrCode, operand) {
      hooks.ensureEditable();
      const opcode = listOpcodes().find((candidate) =>
        candidate.name === opcodeNameOrCode || candidate.code === opcodeNameOrCode
      );
      if (!opcode) throw new RangeError(`Unknown CIL opcode ${opcodeNameOrCode}`);
      const state = hooks.createStructuralState(methodRid);
      const instruction = insertInstruction(state, beforeOffset, opcode, operand);
      if (instruction.operand?.kind === "token" && opcode.name !== "ldstr") {
        const token = instruction.operand.value;
        const table = token >>> 24;
        const rid = token & 0x00ffffff;
        if (!hooks.allowedTokenTables(opcode.name).includes(table)) {
          throw new FormatError(`Metadata table ${table} is not valid for ${opcode.name}`);
        }
        if (rid === 0 || rid > (assembly.tables.counts[table] ?? 0)) {
          throw new RangeError(
            `${opcode.name} references missing ${metadataTableNames[table]} row ${rid}`
          );
        }
        hooks.validateInstructionGenericContext(assembly, methodRid, instruction, token);
      }
      hooks.commitStructuralState(methodRid, state);
      return instruction;
    },

    removeInstruction(methodRid, instructionOffset) {
      hooks.ensureEditable();
      const state = hooks.createStructuralState(methodRid);
      const instruction = removeInstruction(state, instructionOffset);
      hooks.commitStructuralState(methodRid, state);
      return instruction;
    },

    setMethodMaxStack(methodRid, maxStack) {
      hooks.ensureEditable();
      if (!Number.isInteger(maxStack) || maxStack < 0 || maxStack > 0xffff) {
        throw new RangeError("maxStack must be an unsigned 16-bit integer");
      }
      const state = hooks.createStructuralState(methodRid);
      state.maxStack = maxStack;
      layoutStructuralState(state);
      hooks.commitStructuralState(methodRid, state);
      return assembly;
    }
  };
}
