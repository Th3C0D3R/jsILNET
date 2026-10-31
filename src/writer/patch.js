import { FormatError } from "../binary/errors.js";
import { encodeOperand } from "../il/instructions.js";

export function applyPatches(bytes, patches, cliHeader, pe, { preserveStrongName = false } = {}) {
  const output = Uint8Array.from(bytes);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  for (const patch of patches) {
    if (patch.offset < 0 || patch.offset + patch.bytes.length > output.length) {
      throw new FormatError("Operand patch is outside the original file", { offset: patch.offset });
    }
    output.set(patch.bytes, patch.offset);
  }

  if (!preserveStrongName && patches.length > 0 && (cliHeader.flags & 0x08) !== 0) {
    const signature = cliHeader.strongNameSignature;
    if (signature.rva !== 0 && signature.size !== 0) {
      const signatureOffset = pe.rvaToOffset(signature.rva, signature.size);
      output.fill(0, signatureOffset, signatureOffset + signature.size);
    }
    view.setUint32(cliHeader.strongNameFlagOffset, cliHeader.flags & ~0x08, true);
    view.setUint32(cliHeader.strongNameDirectoryOffset, 0, true);
    view.setUint32(cliHeader.strongNameDirectoryOffset + 4, 0, true);
  }
  return output;
}

export function createOperandPatches(instruction, value) {
  const encoded = encodeOperand(instruction, value);
  const kind = instruction.operand.kind;
  if (kind === "switch") {
    const expected = instruction.operand.targetOffsets.length * 4;
    if (encoded.length !== expected || instruction.patchOffsets.length !== instruction.operand.targetOffsets.length) {
      throw new FormatError("Switch edit changed its encoded size");
    }
    return instruction.patchOffsets.map((offset, index) => ({
      offset,
      bytes: encoded.slice(index * 4, index * 4 + 4)
    }));
  }
  if (instruction.patchOffsets.length !== 1) throw new FormatError("Operand does not map to one fixed-size patch");
  return [{ offset: instruction.patchOffsets[0], bytes: encoded }];
}
