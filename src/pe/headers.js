import { BinaryReader } from "../binary/reader.js";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

function requireSignature(actual, expected, offset, name) {
  if (actual !== expected) throw new FormatError(`Invalid ${name} signature`, { offset });
}

function isPowerOfTwo(value) {
  return value !== 0 && (value & (value - 1)) === 0;
}

function parseCodeViewData(bytes, offset, size) {
  if (size < 4) {
    throw new FormatError("CodeView debug record is shorter than its signature", {
      offset,
      context: "PE CodeView data"
    });
  }
  const signature = new TextDecoder("ascii").decode(bytes.subarray(offset, offset + 4));
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, size);
  let format;
  let pathOffset;
  let identity;
  if (signature === "RSDS") {
    if (size < 25) {
      throw new FormatError("RSDS CodeView debug record is truncated", {
        offset,
        context: "PE CodeView data"
      });
    }
    const data1 = view.getUint32(4, true).toString(16).padStart(8, "0");
    const data2 = view.getUint16(8, true).toString(16).padStart(4, "0");
    const data3 = view.getUint16(10, true).toString(16).padStart(4, "0");
    const data4 = [...bytes.subarray(offset + 12, offset + 20)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    identity = {
      guid: `${data1}-${data2}-${data3}-${data4.slice(0, 4)}-${data4.slice(4)}`,
      age: view.getUint32(20, true)
    };
    format = "RSDS";
    pathOffset = 24;
  } else if (signature === "NB10") {
    if (size < 17) {
      throw new FormatError("NB10 CodeView debug record is truncated", {
        offset,
        context: "PE CodeView data"
      });
    }
    identity = {
      offset: view.getUint32(4, true),
      timeDateStamp: view.getUint32(8, true),
      age: view.getUint32(12, true)
    };
    format = "NB10";
    pathOffset = 16;
  } else {
    return { format: "unknown", signature };
  }

  const pathBytes = bytes.subarray(offset + pathOffset, offset + size);
  const terminator = pathBytes.indexOf(0);
  if (terminator < 0 || pathBytes.subarray(terminator + 1).some((byte) => byte !== 0)) {
    throw new FormatError("CodeView PDB path is not null-terminated or has nonzero trailing data", {
      offset: offset + pathOffset,
      context: "PE CodeView data"
    });
  }
  return {
    format,
    ...identity,
    path: new TextDecoder().decode(pathBytes.subarray(0, terminator)),
    pathOffset,
    pathByteLength: terminator
  };
}

export function parsePE(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new BinaryReader(bytes, { context: "PE headers" });
  requireSignature(reader.u2(), 0x5a4d, 0, "DOS");
  reader.seek(0x3c);
  const peOffset = reader.u4();
  if (peOffset > bytes.length - 24) {
    throw new FormatError("PE header offset is outside the file", { offset: 0x3c, context: "DOS header" });
  }

  reader.seek(peOffset);
  requireSignature(reader.u4(), 0x00004550, peOffset, "PE");
  const machine = reader.u2();
  const sectionCount = reader.u2();
  reader.u4();
  const symbolTablePointer = reader.u4();
  const symbolCount = reader.u4();
  const optionalHeaderSize = reader.u2();
  const characteristics = reader.u2();
  const optionalOffset = reader.position;
  const optional = reader.slice(optionalHeaderSize, "PE optional header");
  const magic = optional.u2();
  let directoryCountOffset;
  let directoryOffset;
  if (magic === 0x10b) {
    directoryCountOffset = 92;
    directoryOffset = 96;
  } else if (magic === 0x20b) {
    directoryCountOffset = 108;
    directoryOffset = 112;
  } else {
    throw new UnsupportedFormatError(`Unsupported PE optional-header magic 0x${magic.toString(16)}`, {
      offset: optionalOffset
    });
  }
  if (optionalHeaderSize < directoryCountOffset + 4) {
    throw new FormatError("Optional header is too short to contain data directories", { offset: optionalOffset });
  }
  optional.seek(directoryCountOffset);
  const declaredDirectories = optional.u4();
  const availableDirectories = Math.floor((optionalHeaderSize - directoryOffset) / 8);
  if (declaredDirectories > availableDirectories) {
    throw new FormatError("Optional header declares data directories that do not fit in the header", {
      offset: optionalOffset + directoryCountOffset,
      context: "PE optional header"
    });
  }
  const directoryCount = declaredDirectories;
  optional.seek(directoryOffset);
  const directories = Array.from({ length: directoryCount }, () => ({
    rva: optional.u4(),
    size: optional.u4()
  }));
  const sectionOffset = optionalOffset + optionalHeaderSize;
  const sectionsReader = new BinaryReader(bytes, {
    start: sectionOffset,
    length: bytes.length - sectionOffset,
    baseOffset: sectionOffset,
    context: "PE section table"
  });
  const sections = [];
  for (let i = 0; i < sectionCount; i++) {
    const nameBytes = sectionsReader.take(8);
    const nul = nameBytes.indexOf(0);
    const name = new TextDecoder().decode(nul < 0 ? nameBytes : nameBytes.subarray(0, nul));
    const virtualSize = sectionsReader.u4();
    const virtualAddress = sectionsReader.u4();
    const rawSize = sectionsReader.u4();
    const rawPointer = sectionsReader.u4();
    sectionsReader.skip(16);
    sections.push({ name, virtualSize, virtualAddress, rawSize, rawPointer });
  }
  optional.seek(4);
  const sizeOfCode = optional.u4();
  const sizeOfInitializedData = optional.u4();
  optional.seek(32);
  const sectionAlignment = optional.u4();
  const fileAlignment = optional.u4();
  if (!isPowerOfTwo(sectionAlignment) || !isPowerOfTwo(fileAlignment)) {
    throw new FormatError("PE section and file alignments must be nonzero powers of two", {
      offset: optionalOffset + 32,
      context: "PE optional header"
    });
  }
  if ((sectionAlignment < 0x1000 && sectionAlignment !== fileAlignment) ||
      (sectionAlignment >= 0x1000 && sectionAlignment < fileAlignment)) {
    throw new FormatError("PE section and file alignments are inconsistent", {
      offset: optionalOffset + 32,
      context: "PE optional header"
    });
  }
  if (sectionAlignment >= 0x1000 && (fileAlignment < 0x200 || fileAlignment > 0x10000)) {
    throw new FormatError("PE file alignment is outside the supported range", {
      offset: optionalOffset + 36,
      context: "PE optional header"
    });
  }
  optional.seek(56);
  const sizeOfImage = optional.u4();
  const sizeOfHeaders = optional.u4();
  const checksumOffset = optionalOffset + 64;
  const sectionTableEnd = sectionOffset + sectionCount * 40;
  if (sizeOfHeaders < sectionTableEnd || sizeOfHeaders > bytes.length) {
    throw new FormatError("PE SizeOfHeaders does not cover the PE headers", {
      offset: optionalOffset + 60,
      context: "PE optional header"
    });
  }
  if (sizeOfHeaders % fileAlignment !== 0 || sizeOfImage === 0 ||
      sizeOfImage % sectionAlignment !== 0) {
    throw new FormatError("PE header and image sizes do not follow the declared alignments", {
      offset: optionalOffset + 56,
      context: "PE optional header"
    });
  }

  const rawRanges = [];
  const virtualRanges = [];
  for (const section of sections) {
    if (section.virtualAddress % sectionAlignment !== 0) {
      throw new FormatError(`Section ${section.name} virtual address is not section-aligned`);
    }
    const virtualSize = Math.max(section.virtualSize, section.rawSize);
    if (virtualSize > 0) {
      const end = section.virtualAddress + virtualSize;
      if (end > 0x100000000) {
        throw new FormatError(`Section ${section.name} virtual range overflows the RVA space`);
      }
      virtualRanges.push({ start: section.virtualAddress, end, name: section.name });
    }
    if (section.rawSize > 0) {
      if (section.rawPointer % fileAlignment !== 0 || section.rawSize % fileAlignment !== 0) {
        throw new FormatError(`Section ${section.name} raw range is not file-aligned`);
      }
      const end = section.rawPointer + section.rawSize;
      if (section.rawPointer < sizeOfHeaders || end > bytes.length) {
        throw new FormatError(`Section ${section.name} raw range is outside file data`);
      }
      rawRanges.push({ start: section.rawPointer, end, name: section.name });
    }
  }
  for (const [ranges, label] of [[rawRanges, "raw"], [virtualRanges, "virtual"]]) {
    ranges.sort((left, right) => left.start - right.start || left.end - right.end);
    for (let index = 1; index < ranges.length; index++) {
      if (ranges[index - 1].end > ranges[index].start) {
        throw new FormatError(`PE sections ${ranges[index - 1].name} and ${ranges[index].name} have overlapping ${label} ranges`);
      }
    }
  }

  function rvaToOffset(rva, size = 1) {
    if (!Number.isInteger(rva) || !Number.isInteger(size) || rva < 0 || size < 0) {
      throw new FormatError("Invalid RVA range", { context: "RVA mapping" });
    }
    if (rva === 0 && size === 0) return 0;
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva < section.virtualAddress || rva - section.virtualAddress >= span) continue;
      const delta = rva - section.virtualAddress;
      if (delta + size > section.rawSize || section.rawPointer + delta + size > bytes.length) {
        throw new FormatError("RVA range is not backed by file data", {
          offset: section.rawPointer + delta,
          context: `section ${section.name}`
        });
      }
      return section.rawPointer + delta;
    }
    if (rva < sectionOffset && rva + size <= bytes.length) return rva;
    throw new FormatError(`RVA 0x${rva.toString(16)} is not mapped by a PE section`, { context: "RVA mapping" });
  }

  const debugDirectory = directories[6] ?? { rva: 0, size: 0 };
  if ((debugDirectory.rva === 0) !== (debugDirectory.size === 0)) {
    throw new FormatError("PE debug directory must have both an RVA and a size", {
      context: "PE debug directory"
    });
  }
  const debugDirectoryEntries = [];
  if (debugDirectory.size > 0) {
    if (debugDirectory.size % 28 !== 0) {
      throw new FormatError("Debug directory size is not a multiple of IMAGE_DEBUG_DIRECTORY", {
        context: "PE debug directory"
      });
    }
    const debugOffset = rvaToOffset(debugDirectory.rva, debugDirectory.size);
    const debugReader = new BinaryReader(bytes, {
      start: debugOffset,
      length: debugDirectory.size,
      baseOffset: debugOffset,
      context: "PE debug directory"
    });
    while (debugReader.remaining > 0) {
      const entryOffset = debugReader.position;
      const characteristics = debugReader.u4();
      const timeDateStamp = debugReader.u4();
      const majorVersion = debugReader.u2();
      const minorVersion = debugReader.u2();
      const type = debugReader.u4();
      const sizeOfData = debugReader.u4();
      const addressOfRawData = debugReader.u4();
      const pointerToRawData = debugReader.u4();
      if (sizeOfData > 0) {
        if (addressOfRawData !== 0) rvaToOffset(addressOfRawData, sizeOfData);
        if (pointerToRawData !== 0 && pointerToRawData + sizeOfData > bytes.length) {
          throw new FormatError("Debug data raw range is outside file data", {
            offset: pointerToRawData,
            context: "PE debug directory"
          });
        }
        if (addressOfRawData === 0 && pointerToRawData === 0) {
          throw new FormatError("Debug entry has data size but no data location", {
            offset: entryOffset,
            context: "PE debug directory"
          });
        }
      }
      const codeView = type === 2 && sizeOfData > 0
        ? parseCodeViewData(
          bytes,
          pointerToRawData !== 0
            ? pointerToRawData
            : rvaToOffset(addressOfRawData, sizeOfData),
          sizeOfData
        )
        : null;
      debugDirectoryEntries.push({
        characteristics,
        timeDateStamp,
        majorVersion,
        minorVersion,
        type,
        sizeOfData,
        addressOfRawData,
        pointerToRawData,
        codeView
      });
    }
  }

  return {
    bytes,
    peOffset,
    machine,
    sectionCount,
    symbolTablePointer,
    symbolCount,
    characteristics,
    optionalHeaderOffset: optionalOffset,
    optionalHeaderSize,
    optionalHeaderMagic: magic,
    sectionOffset,
    sizeOfCode,
    sizeOfInitializedData,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    checksumOffset,
    directories,
    debugDirectoryEntries,
    sections,
    rvaToOffset
  };
}

export function parseCliHeader(pe) {
  const directory = pe.directories[14];
  if (!directory || directory.rva === 0 || directory.size < 72) {
    throw new FormatError("PE does not contain a complete CLI data directory", { context: "CLI header" });
  }
  const offset = pe.rvaToOffset(directory.rva, Math.min(directory.size, 72));
  const reader = new BinaryReader(pe.bytes, { start: offset, length: 72, baseOffset: offset, context: "CLI header" });
  const headerSize = reader.u4();
  if (headerSize < 72) throw new FormatError("CLI header is smaller than 72 bytes", { offset, context: "CLI header" });
  if (headerSize > directory.size) throw new FormatError("CLI header exceeds its data directory", { offset, context: "CLI header" });
  const majorRuntimeVersion = reader.u2();
  const minorRuntimeVersion = reader.u2();
  const metadataRva = reader.u4();
  const metadataSize = reader.u4();
  const flags = reader.u4();
  const entryPointToken = reader.u4();
  const resources = { rva: reader.u4(), size: reader.u4() };
  const strongNameSignature = { rva: reader.u4(), size: reader.u4() };
  return {
    offset,
    headerSize,
    majorRuntimeVersion,
    minorRuntimeVersion,
    metadataRva,
    metadataSize,
    flags,
    entryPointToken,
    resources,
    strongNameSignature,
    strongNameFlagOffset: offset + 16,
    strongNameDirectoryOffset: offset + 32
  };
}
