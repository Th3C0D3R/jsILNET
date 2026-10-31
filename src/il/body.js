import { BinaryReader } from "../binary/reader.js";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { decodeInstructions } from "./instructions.js";

function parseExceptionSection(bytes, fileOffset, sectionRva) {
  const reader = new BinaryReader(bytes, {
    start: fileOffset,
    baseOffset: fileOffset,
    context: "method data section"
  });
  const kind = reader.u1();
  const fat = (kind & 0x40) !== 0;
  const moreSections = (kind & 0x80) !== 0;
  if ((kind & 0x3f) !== 0x01) {
    throw new UnsupportedFormatError(`Unsupported method data section kind 0x${kind.toString(16)}`, {
      offset: fileOffset,
      context: "method body"
    });
  }
  let dataSize;
  if (fat) {
    dataSize = reader.u1() | (reader.u1() << 8) | (reader.u1() << 16);
  } else {
    dataSize = reader.u1();
    reader.u2();
  }
  const clauseSize = fat ? 24 : 12;
  if (dataSize < 4 || (dataSize - 4) % clauseSize !== 0 || dataSize > bytes.length - fileOffset) {
    throw new FormatError("Invalid exception-handler section size", { offset: fileOffset, context: "method body" });
  }
  const clauses = [];
  const clauseReader = new BinaryReader(bytes, {
    start: fileOffset + 4,
    length: dataSize - 4,
    baseOffset: fileOffset + 4,
    context: "exception clauses"
  });
  while (clauseReader.remaining > 0) {
    if (fat) {
      const flags = clauseReader.u4();
      const tryOffset = clauseReader.u4();
      const tryLength = clauseReader.u4();
      const handlerOffset = clauseReader.u4();
      const handlerLength = clauseReader.u4();
      const classTokenOrFilterOffset = clauseReader.u4();
      clauses.push({ flags, tryOffset, tryLength, handlerOffset, handlerLength, classTokenOrFilterOffset });
    } else {
      const flags = clauseReader.u2();
      const tryOffset = clauseReader.u2();
      const tryLength = clauseReader.u1();
      const handlerOffset = clauseReader.u2();
      const handlerLength = clauseReader.u1();
      const classTokenOrFilterOffset = clauseReader.u4();
      clauses.push({ flags, tryOffset, tryLength, handlerOffset, handlerLength, classTokenOrFilterOffset });
    }
  }
  return {
    offset: fileOffset,
    rva: sectionRva,
    size: dataSize,
    fat,
    moreSections,
    clauses
  };
}

export function parseMethodBody(input, fileOffset, methodRva = fileOffset) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (fileOffset < 0 || fileOffset >= bytes.length) {
    throw new FormatError("Method body offset is outside the file", { offset: fileOffset, context: "method body" });
  }
  const first = bytes[fileOffset];
  let headerSize;
  let codeSize;
  let maxStack;
  let localVarSigToken;
  let flags;
  let format;
  if ((first & 0x03) === 0x02) {
    format = "tiny";
    headerSize = 1;
    codeSize = first >>> 2;
    maxStack = 8;
    localVarSigToken = 0;
    flags = 0x02;
  } else if ((first & 0x03) === 0x03) {
    format = "fat";
    const header = new BinaryReader(bytes, { start: fileOffset, baseOffset: fileOffset, context: "fat method header" });
    const flagsAndSize = header.u2();
    const headerDwords = flagsAndSize >>> 12;
    headerSize = headerDwords * 4;
    if (headerSize < 12 || fileOffset + headerSize > bytes.length) {
      throw new FormatError(`Invalid fat method header size ${headerSize}`, { offset: fileOffset, context: "method body" });
    }
    flags = flagsAndSize & 0x0fff;
    maxStack = header.u2();
    codeSize = header.u4();
    localVarSigToken = header.u4();
  } else {
    throw new FormatError(`Invalid method header format 0x${(first & 0x03).toString(16)}`, {
      offset: fileOffset,
      context: "method body"
    });
  }

  const codeOffset = fileOffset + headerSize;
  if (!Number.isSafeInteger(codeSize) || codeOffset + codeSize > bytes.length) {
    throw new FormatError("Method code exceeds the file", { offset: codeOffset, context: "method body" });
  }
  const instructions = decodeInstructions(bytes.subarray(codeOffset, codeOffset + codeSize), {
    baseOffset: codeOffset
  });
  let sections = [];
  let endOffset = codeOffset + codeSize;
  const hasSections = format === "fat" && (flags & 0x08) !== 0;
  if (hasSections) {
    let sectionRva = (methodRva + headerSize + codeSize + 3) & ~3;
    let sectionOffset = fileOffset + (sectionRva - methodRva);
    let more = true;
    while (more) {
      if (sectionOffset >= bytes.length) {
        throw new FormatError("Method data section exceeds the file", { offset: sectionOffset, context: "method body" });
      }
      const section = parseExceptionSection(bytes, sectionOffset, sectionRva);
      sections.push(section);
      endOffset = sectionOffset + section.size;
      more = section.moreSections;
      if (more) {
        sectionRva = (sectionRva + section.size + 3) & ~3;
        sectionOffset = fileOffset + (sectionRva - methodRva);
      }
    }
  }
  for (const section of sections) {
    for (const clause of section.clauses) {
      if (clause.tryOffset + clause.tryLength > codeSize ||
          clause.handlerOffset + clause.handlerLength > codeSize) {
        throw new FormatError("Exception-handler region exceeds the method code", {
          offset: section.offset,
          context: "method body"
        });
      }
      if ((clause.flags & 1) !== 0 && clause.classTokenOrFilterOffset >= codeSize) {
        throw new FormatError("Exception filter offset exceeds the method code", {
          offset: section.offset,
          context: "method body"
        });
      }
    }
  }

  return {
    format,
    flags,
    maxStack,
    codeSize,
    localVarSigToken,
    headerOffset: fileOffset,
    headerSize,
    codeOffset,
    endOffset,
    instructions,
    sections
  };
}
