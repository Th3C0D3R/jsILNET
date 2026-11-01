import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

const msfMagic = new TextEncoder().encode("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0");
const absentStream = 0xffffffff;
const codeViewScopeSymbolKinds = new Set([
  0x1102, 0x1103, 0x1104, 0x110f, 0x1110, 0x112a, 0x112b,
  0x1132, 0x1146, 0x1147, 0x114d, 0x115d
]);
const codeViewNumericFormats = new Map([
  [0x8000, [1, (view, offset) => view.getInt8(offset)]],
  [0x8001, [2, (view, offset) => view.getInt16(offset, true)]],
  [0x8002, [2, (view, offset) => view.getUint16(offset, true)]],
  [0x8003, [4, (view, offset) => view.getInt32(offset, true)]],
  [0x8004, [4, (view, offset) => view.getUint32(offset, true)]],
  [0x8005, [4, (view, offset) => view.getFloat32(offset, true)]],
  [0x8006, [8, (view, offset) => view.getFloat64(offset, true)]],
  [0x8009, [8, (view, offset) => view.getBigInt64(offset, true)]],
  [0x800a, [8, (view, offset) => view.getBigUint64(offset, true)]]
]);

function formatGuid(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const first = view.getUint32(0, true).toString(16).padStart(8, "0");
  const second = view.getUint16(4, true).toString(16).padStart(4, "0");
  const third = view.getUint16(6, true).toString(16).padStart(4, "0");
  const tail = [...bytes.subarray(8)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${first}-${second}-${third}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}

function parsePdbNamedStreams(infoStream, streams) {
  let offset = 28;
  const readU32 = (context) => {
    if (offset > infoStream.length - 4) {
      throw new FormatError(`Classic PDB information stream is truncated at ${context}`);
    }
    const value = new DataView(infoStream.buffer, infoStream.byteOffset + offset, 4)
      .getUint32(0, true);
    offset += 4;
    return value;
  };
  const stringBufferSize = readU32("named-stream string buffer size");
  if (stringBufferSize > infoStream.length - offset) {
    throw new FormatError("Classic PDB named-stream string buffer exceeds its information stream");
  }
  const stringBuffer = infoStream.subarray(offset, offset + stringBufferSize);
  offset += stringBufferSize;
  const size = readU32("named-stream hash size");
  const capacity = readU32("named-stream hash capacity");
  if (capacity === 0 || size > Math.floor(capacity * 2 / 3) + 1) {
    throw new FormatError("Classic PDB named-stream hash table size or capacity is invalid");
  }
  const readBitVector = (label) => {
    const wordCount = readU32(`${label} word count`);
    if (wordCount > Math.ceil(capacity / 32)) {
      throw new FormatError(`Classic PDB named-stream ${label} bit vector exceeds its capacity`);
    }
    const indices = [];
    for (let wordIndex = 0; wordIndex < wordCount; wordIndex++) {
      const word = readU32(`${label} bit vector`);
      for (let bit = 0; bit < 32; bit++) {
        if ((word & (1 << bit)) === 0) continue;
        const index = wordIndex * 32 + bit;
        if (index >= capacity) {
          throw new FormatError(`Classic PDB named-stream ${label} bit vector sets an out-of-range slot`);
        }
        indices.push(index);
      }
    }
    return indices;
  };
  const present = readBitVector("present");
  const deleted = readBitVector("deleted");
  const deletedSlots = new Set(deleted);
  if (present.length !== size || present.some((index) => deletedSlots.has(index))) {
    throw new FormatError("Classic PDB named-stream hash bit vectors are inconsistent");
  }
  const namedStreams = new Map();
  for (let index = 0; index < present.length; index++) {
    const nameOffset = readU32("named-stream name offset");
    const streamIndex = readU32("named-stream index");
    if (nameOffset >= stringBuffer.length ||
        streamIndex >= streams.length || streams[streamIndex].bytes === null) {
      throw new FormatError("Classic PDB named-stream entry references missing data");
    }
    const terminator = stringBuffer.indexOf(0, nameOffset);
    if (terminator < 0) {
      throw new FormatError("Classic PDB named-stream name is not null-terminated");
    }
    let name;
    try {
      name = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
        .decode(stringBuffer.subarray(nameOffset, terminator));
    } catch (error) {
      throw new FormatError(`Classic PDB named-stream name is invalid UTF-8: ${error.message}`);
    }
    if (namedStreams.has(name)) throw new FormatError("Classic PDB named-stream map contains duplicate names");
    namedStreams.set(name, streamIndex);
  }
  readU32("named-stream map terminator");
  if ((infoStream.length - offset) % 4 !== 0) {
    throw new FormatError("Classic PDB information stream has a truncated feature signature");
  }
  const featureSignatures = [];
  while (offset < infoStream.length) featureSignatures.push(readU32("feature signature"));
  return { namedStreams, featureSignatures };
}

function parseDbiModules(dbiStream, moduleInfoSize, streams, pdbStrings) {
  const modules = [];
  let offset = 64;
  const end = offset + moduleInfoSize;
  const view = new DataView(dbiStream.buffer, dbiStream.byteOffset, dbiStream.byteLength);
  const readName = (context) => {
    const start = offset;
    while (offset < end && dbiStream[offset] !== 0) offset++;
    if (offset >= end) throw new FormatError(`Classic PDB DBI ${context} is not null-terminated`);
    const bytes = dbiStream.subarray(start, offset++);
    try {
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch (error) {
      throw new FormatError(`Classic PDB DBI ${context} is invalid UTF-8: ${error.message}`);
    }
  };
  while (offset < end) {
    if (end - offset < 64) {
      throw new FormatError("Classic PDB DBI module-info record is truncated");
    }
    const recordStart = offset;
    const streamIndex = view.getUint16(recordStart + 34, true);
    const symbolBytes = view.getUint32(recordStart + 36, true);
    const c11Bytes = view.getUint32(recordStart + 40, true);
    const c13Bytes = view.getUint32(recordStart + 44, true);
    const fileCount = view.getUint16(recordStart + 48, true);
    offset += 64;
    const moduleName = readName("module name");
    const objectName = readName("object name");
    const alignedOffset = (offset + 3) & ~3;
    if (alignedOffset > end) throw new FormatError("Classic PDB DBI module-info padding exceeds its substream");
    offset = alignedOffset;
    if (streamIndex !== 0xffff) {
      const moduleStream = streams[streamIndex]?.bytes;
      if (!moduleStream) {
        throw new FormatError("Classic PDB DBI module references a missing stream");
      }
      if (symbolBytes + c11Bytes + c13Bytes > moduleStream.length) {
        throw new FormatError("Classic PDB DBI module data lengths exceed its module stream");
      }
    } else if (symbolBytes !== 0 || c11Bytes !== 0 || c13Bytes !== 0) {
      throw new FormatError("Classic PDB DBI module has data lengths but no module stream");
    }
    const symbols = symbolBytes === 0
      ? null
      : parseCodeViewSymbolRecords(streams[streamIndex].bytes.subarray(0, symbolBytes));
    const c13Offset = symbolBytes + c11Bytes;
    const c13 = c13Bytes === 0
      ? null
      : parseCodeViewC13Subsections(
        streams[streamIndex].bytes.subarray(c13Offset, c13Offset + c13Bytes),
        pdbStrings
      );
    modules.push({
      moduleName,
      objectName,
      moduleInfoOffset: recordStart,
      streamIndex,
      symbolBytes,
      c11Bytes,
      c13Bytes,
      symbols,
      c13,
      fileCount
    });
  }
  return modules;
}

function parseDbiFileInfo(dbiStream, fileInfoOffset, fileInfoSize, modules) {
  if (fileInfoSize === 0) return modules.map((module) => ({ ...module, sourceFiles: [] }));
  if (fileInfoSize < 4) throw new FormatError("Classic PDB DBI file-info substream is truncated");
  const view = new DataView(dbiStream.buffer, dbiStream.byteOffset, dbiStream.byteLength);
  let offset = fileInfoOffset;
  const end = fileInfoOffset + fileInfoSize;
  const moduleCount = view.getUint16(offset, true);
  offset += 4;
  if (moduleCount !== modules.length) {
    throw new FormatError("Classic PDB DBI file-info module count does not match module descriptors");
  }
  if (moduleCount > Math.floor((end - offset) / 4)) {
    throw new FormatError("Classic PDB DBI file-info module arrays exceed their substream");
  }
  const moduleIndices = [];
  for (let index = 0; index < moduleCount; index++) {
    moduleIndices.push(view.getUint16(offset, true));
    offset += 2;
  }
  const fileCounts = [];
  let totalFiles = 0;
  for (let index = 0; index < moduleCount; index++) {
    const count = view.getUint16(offset, true);
    offset += 2;
    fileCounts.push(count);
    totalFiles += count;
  }
  if (totalFiles > Math.floor((end - offset) / 4)) {
    throw new FormatError("Classic PDB DBI file-name offsets exceed their substream");
  }
  const fileNameOffsets = [];
  for (let index = 0; index < totalFiles; index++) {
    fileNameOffsets.push(view.getUint32(offset, true));
    offset += 4;
  }
  const names = dbiStream.subarray(offset, end);
  const filesByModule = modules.map(() => []);
  let fileIndex = 0;
  for (let index = 0; index < moduleCount; index++) {
    if (modules[index].fileCount !== fileCounts[index]) {
      throw new FormatError("Classic PDB DBI module file count disagrees with file-info data");
    }
    for (let count = 0; count < fileCounts[index]; count++) {
      const nameOffset = fileNameOffsets[fileIndex++];
      if (nameOffset >= names.length) {
        throw new FormatError("Classic PDB DBI source-file name offset is out of range");
      }
      const terminator = names.indexOf(0, nameOffset);
      if (terminator < 0) {
        throw new FormatError("Classic PDB DBI source-file name is not null-terminated");
      }
      try {
        filesByModule[index].push(
          new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(names.subarray(nameOffset, terminator))
        );
      } catch (error) {
        throw new FormatError(`Classic PDB DBI source-file name is invalid UTF-8: ${error.message}`);
      }
    }
  }
  return modules.map((module, index) => ({
    ...module,
    fileInfoModuleIndex: moduleIndices[index],
    sourceFiles: filesByModule[index]
  }));
}

function readCodeViewName(bytes, offset, context, allowZeroPadding = false) {
  const end = bytes.indexOf(0, offset);
  if (end < 0) throw new FormatError(`Classic PDB ${context} name is not null-terminated`);
  const padding = bytes.subarray(end + 1);
  if (padding.length > 0) {
    const paddingLength = padding[0] - 0xf0;
    const validPadding = paddingLength === padding.length &&
      padding.every((byte, index) => byte === 0xf0 + padding.length - index);
    const zeroPadding = allowZeroPadding && padding.length <= 3 &&
      padding.every((byte) => byte === 0);
    if (!zeroPadding && !validPadding) {
      throw new FormatError(`Classic PDB ${context} name has invalid CodeView padding`);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(offset, end));
  } catch (error) {
    throw new FormatError(`Classic PDB ${context} name is invalid UTF-8: ${error.message}`);
  }
}

function decodeCodeViewNumeric(data, offset) {
  if (offset > data.length - 2) {
    throw new FormatError("Classic PDB constant symbol numeric value is truncated");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const leaf = view.getUint16(offset, true);
  if (leaf < 0x8000) return { value: leaf, size: 2 };
  const format = codeViewNumericFormats.get(leaf);
  if (!format) return null;
  const valueOffset = offset + 2;
  if (valueOffset > data.length - format[0]) {
    throw new FormatError("Classic PDB constant symbol numeric value is truncated");
  }
  return { value: format[1](view, valueOffset), size: 2 + format[0] };
}

function getCodeViewSymbolNameOffset(record) {
  if (record.kind === 0x1107) {
    const numeric = decodeCodeViewNumeric(record.data, 4);
    return numeric ? 4 + numeric.size : null;
  }
  return new Map([
    [0x1101, 4],
    [0x1102, 21],
    [0x1103, 18],
    [0x1104, 18],
    [0x1105, 7],
    [0x1106, 6],
    [0x1108, 4],
    [0x110b, 8],
    [0x110c, 10],
    [0x110d, 10],
    [0x110e, 10],
    [0x110f, 35],
    [0x1110, 35],
    [0x1111, 10],
    [0x1112, 10],
    [0x1113, 10],
    [0x111c, 10],
    [0x111d, 10],
    [0x1124, 0],
    [0x112a, 37],
    [0x112b, 37],
    [0x113e, 6],
    [0x1146, 35],
    [0x1147, 35]
  ]).get(record.kind) ?? null;
}

function decodeCodeViewSymbol(kind, data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if ((kind === 0x0006 || kind === 0x114e) && data.length === 0) {
    return { kind: "scopeEnd" };
  }
  if (kind === 0x1101) {
    if (data.length < 6) throw new FormatError("Classic PDB object-name symbol is truncated");
    return {
      kind: "objectName",
      signature: view.getUint32(0, true),
      name: readCodeViewName(data, 4, "object-name")
    };
  }
  if (kind === 0x1103) {
    if (data.length < 19) throw new FormatError("Classic PDB block symbol is truncated");
    return {
      kind: "block",
      parent: view.getUint32(0, true),
      end: view.getUint32(4, true),
      codeSize: view.getUint32(8, true),
      offset: view.getUint32(12, true),
      segment: view.getUint16(16, true),
      name: readCodeViewName(data, 18, "block", true)
    };
  }
  if (kind === 0x1104) {
    if (data.length < 19) throw new FormatError("Classic PDB with-scope symbol is truncated");
    return {
      kind: "withScope",
      parent: view.getUint32(0, true),
      end: view.getUint32(4, true),
      codeSize: view.getUint32(8, true),
      offset: view.getUint32(12, true),
      segment: view.getUint16(16, true),
      expression: readCodeViewName(data, 18, "with-scope")
    };
  }
  if (kind === 0x110e) {
    if (data.length < 11) throw new FormatError("Classic PDB S_PUB32 record is truncated");
    return {
      kind: "public",
      flags: view.getUint32(0, true),
      offset: view.getUint32(4, true),
      segment: view.getUint16(8, true),
      name: readCodeViewName(data, 10, "S_PUB32")
    };
  }
  if ([0x110c, 0x110d, 0x111c, 0x111d].includes(kind)) {
    if (data.length < 11) throw new FormatError("Classic PDB data symbol record is truncated");
    return {
      kind: "data",
      typeIndex: view.getUint32(0, true),
      offset: view.getUint32(4, true),
      segment: view.getUint16(8, true),
      name: readCodeViewName(data, 10, "data symbol")
    };
  }
  if (kind === 0x1107) {
    if (data.length < 6) throw new FormatError("Classic PDB constant symbol is truncated");
    const numeric = decodeCodeViewNumeric(data, 4);
    if (!numeric) return null;
    return {
      kind: "constant",
      typeIndex: view.getUint32(0, true),
      value: numeric.value,
      name: readCodeViewName(data, 4 + numeric.size, "constant symbol")
    };
  }
  if (kind === 0x1112 || kind === 0x1113) {
    if (data.length < 11) throw new FormatError("Classic PDB thread-data symbol is truncated");
    return {
      kind: "threadData",
      typeIndex: view.getUint32(0, true),
      offset: view.getUint32(4, true),
      segment: view.getUint16(8, true),
      name: readCodeViewName(data, 10, "thread-data symbol")
    };
  }
  if (kind === 0x1102) {
    if (data.length < 22) throw new FormatError("Classic PDB thunk symbol is truncated");
    return {
      kind: "thunk",
      parent: view.getUint32(0, true),
      end: view.getUint32(4, true),
      next: view.getUint32(8, true),
      offset: view.getUint32(12, true),
      segment: view.getUint16(16, true),
      length: view.getUint16(18, true),
      ordinal: data[20],
      name: readCodeViewName(data, 21, "thunk symbol")
    };
  }
  if (kind === 0x1012) {
    if (data.length < 26) throw new FormatError("Classic PDB frame-procedure symbol is truncated");
    return {
      kind: "frameProcedure",
      frameSize: view.getUint32(0, true),
      paddingSize: view.getUint32(4, true),
      paddingOffset: view.getUint32(8, true),
      savedRegisterSize: view.getUint32(12, true),
      exceptionHandlerOffset: view.getUint32(16, true),
      exceptionHandlerSegment: view.getUint16(20, true),
      flags: view.getUint32(22, true)
    };
  }
  if (kind === 0x1124) {
    return {
      kind: "namespace",
      name: readCodeViewName(data, 0, "namespace")
    };
  }
  if (kind === 0x113c) {
    if (data.length < 23) throw new FormatError("Classic PDB compile-info symbol is truncated");
    return {
      kind: "compileInfo",
      flags: view.getUint32(0, true),
      machine: view.getUint16(4, true),
      frontEndVersion: {
        major: view.getUint16(6, true),
        minor: view.getUint16(8, true),
        build: view.getUint16(10, true),
        qfe: view.getUint16(12, true)
      },
      backEndVersion: {
        major: view.getUint16(14, true),
        minor: view.getUint16(16, true),
        build: view.getUint16(18, true),
        qfe: view.getUint16(20, true)
      },
      version: readCodeViewName(data, 22, "compile-info", true)
    };
  }
  if ([0x110f, 0x1110, 0x1146, 0x1147].includes(kind)) {
    if (data.length < 36) throw new FormatError("Classic PDB procedure symbol record is truncated");
    return {
      kind: "procedure",
      parent: view.getUint32(0, true),
      end: view.getUint32(4, true),
      next: view.getUint32(8, true),
      codeSize: view.getUint32(12, true),
      debugStart: view.getUint32(16, true),
      debugEnd: view.getUint32(20, true),
      typeIndex: view.getUint32(24, true),
      offset: view.getUint32(28, true),
      segment: view.getUint16(32, true),
      flags: data[34],
      name: readCodeViewName(data, 35, "procedure")
    };
  }
  if (kind === 0x112a || kind === 0x112b) {
    if (data.length < 38) throw new FormatError("Classic PDB managed procedure symbol is truncated");
    return {
      kind: "managedProcedure",
      parent: view.getUint32(0, true),
      end: view.getUint32(4, true),
      next: view.getUint32(8, true),
      codeSize: view.getUint32(12, true),
      debugStart: view.getUint32(16, true),
      debugEnd: view.getUint32(20, true),
      methodToken: view.getUint32(24, true),
      offset: view.getUint32(28, true),
      segment: view.getUint16(32, true),
      flags: data[34],
      returnRegister: view.getUint16(35, true),
      name: readCodeViewName(data, 37, "managed procedure", true)
    };
  }
  if (kind === 0x113e) {
    if (data.length < 7) throw new FormatError("Classic PDB local symbol is truncated");
    return {
      kind: "local",
      typeIndex: view.getUint32(0, true),
      flags: view.getUint16(4, true),
      name: readCodeViewName(data, 6, "local")
    };
  }
  if (kind === 0x110b) {
    if (data.length < 9) throw new FormatError("Classic PDB BP-relative symbol is truncated");
    return {
      kind: "bpRelative",
      offset: view.getInt32(0, true),
      typeIndex: view.getUint32(4, true),
      name: readCodeViewName(data, 8, "BP-relative")
    };
  }
  if (kind === 0x1111) {
    if (data.length < 11) throw new FormatError("Classic PDB register-relative symbol is truncated");
    return {
      kind: "registerRelative",
      offset: view.getInt32(0, true),
      typeIndex: view.getUint32(4, true),
      register: view.getUint16(8, true),
      name: readCodeViewName(data, 10, "register-relative")
    };
  }
  if (kind === 0x1108) {
    if (data.length < 5) throw new FormatError("Classic PDB UDT symbol is truncated");
    return {
      kind: "userDefinedType",
      typeIndex: view.getUint32(0, true),
      name: readCodeViewName(data, 4, "UDT")
    };
  }
  if (kind === 0x1106) {
    if (data.length < 7) throw new FormatError("Classic PDB register symbol is truncated");
    return {
      kind: "register",
      typeIndex: view.getUint32(0, true),
      register: view.getUint16(4, true),
      name: readCodeViewName(data, 6, "register")
    };
  }
  if (kind === 0x1105) {
    if (data.length < 8) throw new FormatError("Classic PDB label symbol is truncated");
    return {
      kind: "label",
      offset: view.getUint32(0, true),
      segment: view.getUint16(4, true),
      flags: data[6],
      name: readCodeViewName(data, 7, "label")
    };
  }
  return null;
}

function parseCodeViewFileChecksums(data) {
  const checksums = new Map();
  let offset = 0;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  while (offset < data.length) {
    if (data.length - offset < 6) {
      throw new FormatError("Classic PDB file-checksum record is truncated");
    }
    const recordStart = offset;
    const fileNameOffset = view.getUint32(offset, true);
    const checksumSize = data[offset + 4];
    const checksumKind = data[offset + 5];
    const expectedSize = new Map([[0, 0], [1, 16], [2, 20], [3, 32]]).get(checksumKind);
    if (expectedSize === undefined || checksumSize !== expectedSize) {
      throw new FormatError("Classic PDB file-checksum kind or length is invalid");
    }
    offset += 6;
    if (checksumSize > data.length - offset) {
      throw new FormatError("Classic PDB file-checksum bytes exceed their subsection");
    }
    const checksum = data.slice(offset, offset + checksumSize);
    offset += checksumSize;
    const alignedOffset = (offset + 3) & ~3;
    if (alignedOffset > data.length || data.subarray(offset, alignedOffset).some((byte) => byte !== 0)) {
      throw new FormatError("Classic PDB file-checksum padding is invalid");
    }
    offset = alignedOffset;
    if (checksums.has(recordStart)) {
      throw new FormatError("Classic PDB file-checksum offsets are duplicated");
    }
    checksums.set(recordStart, { fileNameOffset, checksumKind, checksum });
  }
  return checksums;
}

function parseCodeViewLines(data, fileChecksums, pdbStrings) {
  if (data.length < 12) throw new FormatError("Classic PDB line subsection header is truncated");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const relocationOffset = view.getUint32(0, true);
  const segment = view.getUint16(4, true);
  const flags = view.getUint16(6, true);
  const codeSize = view.getUint32(8, true);
  if ((flags & ~1) !== 0) throw new UnsupportedFormatError("Classic PDB line subsection has unsupported flags");
  const hasColumns = (flags & 1) !== 0;
  const blocks = [];
  let offset = 12;
  while (offset < data.length) {
    if (data.length - offset < 12) {
      throw new FormatError("Classic PDB line block header is truncated");
    }
    const fileChecksumOffset = view.getUint32(offset, true);
    const lineCount = view.getUint32(offset + 4, true);
    const blockSize = view.getUint32(offset + 8, true);
    const minimumSize = 12 + lineCount * (hasColumns ? 12 : 8);
    if (blockSize < minimumSize || blockSize > data.length - offset) {
      throw new FormatError("Classic PDB line block size is invalid");
    }
    const checksum = fileChecksums.get(fileChecksumOffset);
    if (!checksum) {
      throw new FormatError("Classic PDB line block references a missing file-checksum record");
    }
    const fileName = pdbStrings?.get(checksum.fileNameOffset) ?? null;
    if (pdbStrings && fileName === null) {
      throw new FormatError("Classic PDB line checksum references a missing string-table name");
    }
    const lines = [];
    let lineOffset = offset + 12;
    for (let index = 0; index < lineCount; index++) {
      const codeOffset = view.getUint32(lineOffset, true);
      const lineFlags = view.getUint32(lineOffset + 4, true);
      if (codeOffset > codeSize) {
        throw new FormatError("Classic PDB line offset exceeds its code contribution");
      }
      lines.push({
        offset: codeOffset,
        startLine: lineFlags & 0x00ffffff,
        endLineDelta: (lineFlags >>> 24) & 0x7f,
        isStatement: (lineFlags & 0x80000000) !== 0
      });
      lineOffset += 8;
    }
    if (hasColumns) {
      for (const line of lines) {
        line.startColumn = view.getUint16(lineOffset, true);
        line.endColumn = view.getUint16(lineOffset + 2, true);
        lineOffset += 4;
      }
    }
    blocks.push({
      fileChecksumOffset,
      fileNameOffset: checksum.fileNameOffset,
      fileName,
      checksumKind: checksum.checksumKind,
      checksum: checksum.checksum,
      lines
    });
    offset += blockSize;
  }
  return { relocationOffset, segment, flags, codeSize, blocks };
}

export function parseCodeViewC13Subsections(input, pdbStrings = null) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const subsections = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < 8) {
      throw new FormatError("Classic PDB C13 subsection header is truncated");
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
    const kind = view.getUint32(0, true);
    const size = view.getUint32(4, true);
    const dataStart = offset + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) {
      throw new FormatError("Classic PDB C13 subsection exceeds its module stream");
    }
    subsections.push({ kind, data: bytes.slice(dataStart, dataEnd) });
    const alignedEnd = (dataEnd + 3) & ~3;
    if (alignedEnd > bytes.length) {
      throw new FormatError("Classic PDB C13 subsection alignment exceeds its module stream");
    }
    offset = alignedEnd;
  }
  const stringTables = subsections.filter((subsection) => subsection.kind === 0xf3);
  const checksumTables = subsections.filter((subsection) => subsection.kind === 0xf4);
  if (stringTables.length > 1 || checksumTables.length > 1) {
    throw new FormatError("Classic PDB C13 stream contains duplicate string or checksum subsections");
  }
  const fileChecksums = checksumTables.length > 0
    ? parseCodeViewFileChecksums(checksumTables[0].data)
    : new Map();
  const lines = subsections
    .filter((subsection) => subsection.kind === 0xf2)
    .map((subsection) => parseCodeViewLines(subsection.data, fileChecksums, pdbStrings));
  return { subsections, fileChecksums, lines };
}

export function parsePdbStringTable(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 16) throw new FormatError("Classic PDB /names stream is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const signature = view.getUint32(0, true);
  const hashVersion = view.getUint32(4, true);
  const byteSize = view.getUint32(8, true);
  if (signature !== 0xeffeeffe) {
    throw new FormatError("Classic PDB /names stream has an invalid signature");
  }
  if (hashVersion !== 1 && hashVersion !== 2) {
    throw new UnsupportedFormatError(`Unsupported classic PDB string-table hash version ${hashVersion}`);
  }
  if (byteSize > bytes.length - 16) {
    throw new FormatError("Classic PDB /names string bytes exceed the stream bounds");
  }
  const stringBytes = bytes.subarray(12, 12 + byteSize);
  const strings = new Map();
  let stringOffset = 0;
  while (stringOffset < stringBytes.length) {
    const terminator = stringBytes.indexOf(0, stringOffset);
    if (terminator < 0) throw new FormatError("Classic PDB /names string is not null-terminated");
    let value;
    try {
      value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
        .decode(stringBytes.subarray(stringOffset, terminator));
    } catch (error) {
      throw new FormatError(`Classic PDB /names string is invalid UTF-8: ${error.message}`);
    }
    strings.set(stringOffset, value);
    stringOffset = terminator + 1;
  }
  let offset = 12 + byteSize;
  if (bytes.length - offset < 8) throw new FormatError("Classic PDB /names hash data is truncated");
  const hashCount = view.getUint32(offset, true);
  offset += 4;
  if (hashCount > Math.floor((bytes.length - offset - 4) / 4)) {
    throw new FormatError("Classic PDB /names hash table exceeds the stream bounds");
  }
  const nameIds = [];
  for (let index = 0; index < hashCount; index++) {
    const id = view.getUint32(offset, true);
    offset += 4;
    if (id !== 0 && !strings.has(id)) {
      throw new FormatError("Classic PDB /names hash table references a missing string");
    }
    nameIds.push(id);
  }
  const nameCount = view.getUint32(offset, true);
  offset += 4;
  if (offset !== bytes.length) throw new FormatError("Trailing bytes after classic PDB /names stream");
  return { signature, hashVersion, byteSize, nameCount, strings, nameIds };
}

export function parseCodeViewSymbolRecords(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 4) throw new FormatError("Classic PDB module symbol data is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const signature = view.getUint32(0, true);
  if (![1, 2, 4].includes(signature)) {
    throw new UnsupportedFormatError(`Unsupported CodeView module symbol signature ${signature}`);
  }
  const records = [];
  let offset = 4;
  while (offset < bytes.length) {
    if (bytes.length - offset < 2) {
      throw new FormatError("Classic PDB module symbol-record length is truncated");
    }
    const length = view.getUint16(offset, true);
    if (length < 2 || length > bytes.length - offset - 2) {
      throw new FormatError("Classic PDB module symbol record exceeds its stream bounds");
    }
    const kind = view.getUint16(offset + 2, true);
    const data = bytes.slice(offset + 4, offset + 2 + length);
    const decoded = decodeCodeViewSymbol(kind, data);
    records.push({
      offset,
      kind,
      data,
      ...(decoded ? { decoded } : {})
    });
    offset += 2 + length;
  }
  return { signature, records };
}

export function parseClassicPdb(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 56) throw new FormatError("Classic PDB MSF superblock is truncated");
  if (!msfMagic.every((byte, index) => bytes[index] === byte)) {
    throw new FormatError("Classic PDB has an invalid MSF 7.0 signature");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const blockSize = view.getUint32(32, true);
  const freeBlockMapBlock = view.getUint32(36, true);
  const numBlocks = view.getUint32(40, true);
  const directoryByteLength = view.getUint32(44, true);
  const blockMapAddress = view.getUint32(52, true);
  if (blockSize < 512 || blockSize > 65536 || (blockSize & (blockSize - 1)) !== 0) {
    throw new UnsupportedFormatError(`Unsupported classic PDB MSF block size ${blockSize}`);
  }
  if (numBlocks < 4 || numBlocks > Math.floor(bytes.length / blockSize)) {
    throw new FormatError("Classic PDB MSF block count exceeds the file bounds");
  }
  if (freeBlockMapBlock !== 1 && freeBlockMapBlock !== 2) {
    throw new FormatError("Classic PDB MSF free-block map address is invalid");
  }
  if (directoryByteLength === 0 || blockMapAddress < 3 || blockMapAddress >= numBlocks) {
    throw new FormatError("Classic PDB MSF directory metadata is invalid");
  }

  const directoryBlockCount = Math.ceil(directoryByteLength / blockSize);
  if (directoryBlockCount > Math.floor(blockSize / 4)) {
    throw new UnsupportedFormatError("Classic PDB MSF directory block map exceeds one block");
  }
  const reservedBlocks = new Set([0, 1, 2, blockMapAddress]);
  const allocatedBlocks = new Set(reservedBlocks);
  const claimBlock = (block, context) => {
    if (!Number.isInteger(block) || block < 0 || block >= numBlocks) {
      throw new FormatError(`Classic PDB ${context} block index is out of range`);
    }
    if (allocatedBlocks.has(block)) {
      throw new FormatError(`Classic PDB ${context} overlaps another MSF structure`);
    }
    allocatedBlocks.add(block);
  };
  const readBlock = (block) => {
    const offset = block * blockSize;
    return bytes.subarray(offset, offset + blockSize);
  };

  const blockMapOffset = blockMapAddress * blockSize;
  const blockMapView = new DataView(bytes.buffer, bytes.byteOffset + blockMapOffset, blockSize);
  const directoryBlocks = [];
  for (let index = 0; index < directoryBlockCount; index++) {
    const block = blockMapView.getUint32(index * 4, true);
    claimBlock(block, "directory");
    directoryBlocks.push(block);
  }
  const directory = new Uint8Array(directoryByteLength);
  for (let index = 0; index < directoryBlocks.length; index++) {
    const start = index * blockSize;
    directory.set(
      readBlock(directoryBlocks[index]).subarray(0, Math.min(blockSize, directoryByteLength - start)),
      start
    );
  }

  if (directory.length < 4) throw new FormatError("Classic PDB MSF stream directory is truncated");
  const directoryView = new DataView(directory.buffer, directory.byteOffset, directory.byteLength);
  const streamCount = directoryView.getUint32(0, true);
  if (streamCount < 2 || streamCount > Math.floor((directory.length - 4) / 4)) {
    throw new FormatError("Classic PDB MSF stream count exceeds directory bounds");
  }
  let directoryOffset = 4;
  const streamSizes = [];
  for (let index = 0; index < streamCount; index++) {
    streamSizes.push(directoryView.getUint32(directoryOffset, true));
    directoryOffset += 4;
  }
  const streams = [];
  for (let index = 0; index < streamCount; index++) {
    const size = streamSizes[index];
    if (size === absentStream) {
      streams.push({ index, size: null, bytes: null, blockIndices: [] });
      continue;
    }
    const blockCount = Math.ceil(size / blockSize);
    if (blockCount > Math.floor((directory.length - directoryOffset) / 4)) {
      throw new FormatError(`Classic PDB MSF stream ${index} block list exceeds directory bounds`);
    }
    const streamBlocks = [];
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
      const block = directoryView.getUint32(directoryOffset, true);
      directoryOffset += 4;
      claimBlock(block, `stream ${index}`);
      streamBlocks.push(block);
    }
    const streamBytes = new Uint8Array(size);
    for (let blockIndex = 0; blockIndex < streamBlocks.length; blockIndex++) {
      const start = blockIndex * blockSize;
      streamBytes.set(
        readBlock(streamBlocks[blockIndex]).subarray(0, Math.min(blockSize, size - start)),
        start
      );
    }
    streams.push({ index, size, bytes: streamBytes, blockIndices: streamBlocks });
  }
  if (directoryOffset !== directory.length) {
    throw new FormatError("Trailing bytes after classic PDB MSF stream directory");
  }

  const infoStream = streams[1]?.bytes;
  if (!infoStream || infoStream.length < 28) {
    throw new FormatError("Classic PDB information stream is missing or truncated");
  }
  const infoView = new DataView(infoStream.buffer, infoStream.byteOffset, infoStream.byteLength);
  const id = infoStream.subarray(12, 28);
  const infoDetails = parsePdbNamedStreams(infoStream, streams);
  const namesStreamIndex = infoDetails.namedStreams.get("/names");
  const pdbStringTable = namesStreamIndex === undefined
    ? null
    : parsePdbStringTable(streams[namesStreamIndex].bytes);
  const info = {
    version: infoView.getUint32(0, true),
    signature: infoView.getUint32(4, true),
    age: infoView.getUint32(8, true),
    guid: formatGuid(id),
    stringTable: pdbStringTable,
    ...infoDetails
  };
  let dbi = null;
  const dbiStream = streams[3]?.bytes;
  if (dbiStream) {
    if (dbiStream.length < 64) throw new FormatError("Classic PDB DBI stream is truncated");
    const dbiView = new DataView(dbiStream.buffer, dbiStream.byteOffset, dbiStream.byteLength);
    if (dbiView.getInt32(0, true) !== -1) {
      throw new FormatError("Classic PDB DBI version signature is invalid");
    }
    const dbiVersion = dbiView.getUint32(4, true);
    if (dbiVersion < 19990903) {
      throw new UnsupportedFormatError("Classic PDB DBI version is older than version 7");
    }
    const dbiAge = dbiView.getUint32(8, true);
    if (dbiAge !== info.age) {
      throw new FormatError("Classic PDB DBI age does not match the information stream");
    }
    const substreamSizes = {
      moduleInfo: dbiView.getUint32(24, true),
      sectionContributions: dbiView.getUint32(28, true),
      sectionMap: dbiView.getUint32(32, true),
      fileInfo: dbiView.getUint32(36, true),
      typeServerMap: dbiView.getUint32(40, true),
      optionalDebugHeader: dbiView.getUint32(48, true),
      editAndContinue: dbiView.getUint32(52, true)
    };
    const requiredLength = 64 + Object.values(substreamSizes)
      .reduce((sum, size) => sum + size, 0);
    if (requiredLength !== dbiStream.length) {
      throw new FormatError("Classic PDB DBI stream length does not match its substream sizes");
    }
    for (const name of ["moduleInfo", "sectionContributions", "sectionMap", "fileInfo", "typeServerMap"]) {
      if (substreamSizes[name] % 4 !== 0) {
        throw new FormatError(`Classic PDB DBI ${name} substream is misaligned`);
      }
    }
    if (substreamSizes.optionalDebugHeader % 2 !== 0) {
      throw new FormatError("Classic PDB DBI optional debug header is misaligned");
    }
    const streamReferences = {
      globalSymbols: dbiView.getUint16(12, true),
      publicSymbols: dbiView.getUint16(16, true),
      symbolRecords: dbiView.getUint16(20, true)
    };
    for (const [name, streamIndex] of Object.entries(streamReferences)) {
      if (streamIndex !== 0xffff &&
          (streamIndex >= streams.length || streams[streamIndex].bytes === null)) {
        throw new FormatError(`Classic PDB DBI ${name} reference targets a missing stream`);
      }
    }
    const modules = parseDbiModules(
      dbiStream,
      substreamSizes.moduleInfo,
      streams,
      pdbStringTable?.strings ?? null
    );
    const fileInfoOffset = 64 + substreamSizes.moduleInfo +
      substreamSizes.sectionContributions + substreamSizes.sectionMap;
    dbi = {
      version: dbiVersion,
      age: dbiAge,
      buildNumber: dbiView.getUint16(14, true),
      pdbDllVersion: dbiView.getUint16(18, true),
      pdbDllRebuild: dbiView.getUint16(22, true),
      machine: dbiView.getUint16(58, true),
      flags: dbiView.getUint16(56, true),
      streamReferences,
      substreamSizes,
      modules: parseDbiFileInfo(
        dbiStream, fileInfoOffset, substreamSizes.fileInfo, modules
      )
    };
  }

  return {
    format: "MSF 7.0",
    blockSize,
    numBlocks,
    msf: {
      directoryByteLength,
      directoryBlocks,
      blockMapAddress
    },
    info,
    dbi,
    streams
  };
}

function replaceClassicPdbStreamBytes(bytes, pdb, streamIndex, streamOffset, replacement) {
  const stream = pdb.streams[streamIndex];
  if (!stream?.blockIndices?.length) {
    throw new FormatError("Classic PDB replacement stream has no allocated MSF blocks");
  }
  if (!Number.isInteger(streamOffset) || streamOffset < 0 ||
      streamOffset > stream.size - replacement.length) {
    throw new FormatError("Classic PDB replacement exceeds its stream bounds");
  }
  const output = Uint8Array.from(bytes);
  for (let index = 0; index < replacement.length; index++) {
    const position = streamOffset + index;
    const blockIndex = Math.floor(position / pdb.blockSize);
    const block = stream.blockIndices[blockIndex];
    if (block === undefined) throw new FormatError("Classic PDB replacement exceeds its MSF block list");
    output[block * pdb.blockSize + position % pdb.blockSize] = replacement[index];
  }
  return output;
}

function writeClassicPdbStream(bytes, pdb, streamIndex, streamBytes) {
  const stream = pdb.streams[streamIndex];
  if (!stream?.blockIndices?.length ||
      Math.ceil(streamBytes.length / pdb.blockSize) !== stream.blockIndices.length) {
    throw new UnsupportedFormatError(
      "Classic PDB replacement must preserve the stream's allocated MSF block count"
    );
  }
  const output = Uint8Array.from(bytes);
  for (let index = 0; index < stream.blockIndices.length; index++) {
    const block = stream.blockIndices[index];
    const sourceOffset = index * pdb.blockSize;
    const copyLength = Math.min(pdb.blockSize, streamBytes.length - sourceOffset);
    const targetOffset = block * pdb.blockSize;
    if (copyLength > 0) output.set(streamBytes.subarray(sourceOffset, sourceOffset + copyLength), targetOffset);
    output.fill(0, targetOffset + Math.max(copyLength, 0), targetOffset + pdb.blockSize);
  }
  return output;
}

function rebuildClassicPdbStreams(pdb, streamReplacements) {
  const blockSize = pdb.blockSize;
  const streams = pdb.streams.map((stream) => ({
    bytes: stream.bytes === null
      ? null
      : Uint8Array.from(streamReplacements.get(stream.index) ?? stream.bytes)
  }));
  const streamBlockCounts = streams.map(({ bytes }) =>
    bytes === null ? 0 : Math.ceil(bytes.length / blockSize)
  );
  const directoryByteLength = 4 + streams.length * 4 +
    streamBlockCounts.reduce((sum, count) => sum + count * 4, 0);
  const directoryBlockCount = Math.ceil(directoryByteLength / blockSize);
  if (directoryBlockCount > Math.floor(blockSize / 4)) {
    throw new UnsupportedFormatError("Classic PDB MSF directory block map exceeds one block");
  }
  const directoryBlockIndices = Array.from(
    { length: directoryBlockCount },
    (_, index) => 4 + index
  );
  let nextBlock = 4 + directoryBlockCount;
  const streamBlockIndices = streamBlockCounts.map((count) => {
    const indices = Array.from({ length: count }, (_, index) => nextBlock + index);
    nextBlock += count;
    return indices;
  });
  if (nextBlock > blockSize * 8 ||
      nextBlock * blockSize > 0x7fffffff) {
    throw new UnsupportedFormatError(
      "Classic PDB MSF rebuild exceeds supported allocation limits"
    );
  }
  const output = new Uint8Array(nextBlock * blockSize);
  output.set(msfMagic);
  const superblock = new DataView(output.buffer);
  superblock.setUint32(32, blockSize, true);
  superblock.setUint32(36, 1, true);
  superblock.setUint32(40, nextBlock, true);
  superblock.setUint32(44, directoryByteLength, true);
  superblock.setUint32(48, 0, true);
  superblock.setUint32(52, 3, true);

  const directory = new Uint8Array(directoryByteLength);
  const directoryView = new DataView(directory.buffer);
  directoryView.setUint32(0, streams.length, true);
  let directoryOffset = 4;
  for (const { bytes } of streams) {
    directoryView.setUint32(
      directoryOffset,
      bytes === null ? absentStream : bytes.length,
      true
    );
    directoryOffset += 4;
  }
  for (const indices of streamBlockIndices) {
    for (const block of indices) {
      directoryView.setUint32(directoryOffset, block, true);
      directoryOffset += 4;
    }
  }
  const blockMapOffset = 3 * blockSize;
  const blockMapView = new DataView(output.buffer, blockMapOffset, blockSize);
  for (let index = 0; index < directoryBlockIndices.length; index++) {
    blockMapView.setUint32(index * 4, directoryBlockIndices[index], true);
  }
  for (let index = 0; index < directoryBlockIndices.length; index++) {
    const start = index * blockSize;
    output.set(
      directory.subarray(start, Math.min(start + blockSize, directory.length)),
      directoryBlockIndices[index] * blockSize
    );
  }
  streams.forEach(({ bytes }, streamIndex) => {
    if (bytes === null) return;
    streamBlockIndices[streamIndex].forEach((block, blockIndex) => {
      const start = blockIndex * blockSize;
      output.set(bytes.subarray(start, Math.min(start + blockSize, bytes.length)), block * blockSize);
    });
  });
  for (const freeMapBlock of [1, 2]) {
    const offset = freeMapBlock * blockSize;
    output.fill(0xff, offset, offset + blockSize);
    const markAllocated = (block) => {
      output[offset + Math.floor(block / 8)] &= ~(1 << (block % 8));
    };
    for (let block = 0; block < 4; block++) markAllocated(block);
    for (const block of directoryBlockIndices) markAllocated(block);
    for (const indices of streamBlockIndices) {
      for (const block of indices) markAllocated(block);
    }
  }
  return output;
}

function replaceClassicPdbDirectoryBytes(bytes, pdb, offset, replacement) {
  if (!Number.isInteger(offset) || offset < 0 ||
      offset > pdb.msf.directoryByteLength - replacement.length) {
    throw new FormatError("Classic PDB directory replacement exceeds its stream bounds");
  }
  const output = Uint8Array.from(bytes);
  for (let index = 0; index < replacement.length; index++) {
    const position = offset + index;
    const blockIndex = Math.floor(position / pdb.blockSize);
    const block = pdb.msf.directoryBlocks[blockIndex];
    if (block === undefined) throw new FormatError("Classic PDB directory replacement exceeds its MSF block list");
    output[block * pdb.blockSize + position % pdb.blockSize] = replacement[index];
  }
  return output;
}

function encodeClassicPdbReplacementText(value, context) {
  if (typeof value !== "string" || value.includes("\0")) {
    throw new TypeError(`${context} must be a string without null characters`);
  }
  const bytes = new TextEncoder().encode(value);
  if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) !== value) {
    throw new TypeError(`${context} must contain valid Unicode`);
  }
  return bytes;
}

export function replaceClassicPdbModuleNames(input, options = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Classic PDB module replacement must be an object");
  }
  const { moduleIndex, moduleName, objectName } = options;
  if (!Number.isInteger(moduleIndex) || moduleIndex < 0) {
    throw new RangeError("Classic PDB module index must be a non-negative integer");
  }
  const updatesModuleName = Object.hasOwn(options, "moduleName");
  const updatesObjectName = Object.hasOwn(options, "objectName");
  if ((!updatesModuleName && !updatesObjectName) ||
      Object.keys(options).some((field) =>
        !["moduleIndex", "moduleName", "objectName"].includes(field)
      )) {
    throw new TypeError("Classic PDB module replacement requires supported name fields");
  }

  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  if (!module) throw new RangeError("Classic PDB module index does not exist");
  const nextModuleName = updatesModuleName
    ? moduleName
    : module.moduleName;
  const nextObjectName = updatesObjectName
    ? objectName
    : module.objectName;
  const moduleNameBytes = encodeClassicPdbReplacementText(
    nextModuleName,
    "Classic PDB module name"
  );
  const objectNameBytes = encodeClassicPdbReplacementText(
    nextObjectName,
    "Classic PDB object name"
  );
  if (nextModuleName === module.moduleName && nextObjectName === module.objectName) {
    return Uint8Array.from(bytes);
  }

  const dbiStream = pdb.streams[3]?.bytes;
  const moduleInfoSize = pdb.dbi.substreamSizes.moduleInfo;
  const moduleInfoEnd = 64 + moduleInfoSize;
  const recordStart = module.moduleInfoOffset;
  const recordEnd = pdb.dbi.modules[moduleIndex + 1]?.moduleInfoOffset ?? moduleInfoEnd;
  if (!dbiStream || recordStart < 64 || recordEnd > moduleInfoEnd ||
      recordEnd < recordStart + 64) {
    throw new FormatError("Classic PDB DBI module-info record has invalid bounds");
  }
  const findTerminator = (start, context) => {
    const end = dbiStream.indexOf(0, start);
    if (end < start || end >= recordEnd) {
      throw new FormatError(`Classic PDB DBI ${context} is not null-terminated`);
    }
    return end;
  };
  const moduleNameEnd = findTerminator(recordStart + 64, "module name");
  const objectNameEnd = findTerminator(moduleNameEnd + 1, "object name");
  if (((objectNameEnd + 1 + 3) & ~3) !== recordEnd) {
    throw new FormatError("Classic PDB DBI module-info record has invalid padding");
  }

  const recordSize = (64 + moduleNameBytes.length + 1 +
    objectNameBytes.length + 1 + 3) & ~3;
  const replacementRecord = new Uint8Array(recordSize);
  replacementRecord.set(dbiStream.subarray(recordStart, recordStart + 64));
  let replacementOffset = 64;
  replacementRecord.set(moduleNameBytes, replacementOffset);
  replacementOffset += moduleNameBytes.length + 1;
  replacementRecord.set(objectNameBytes, replacementOffset);
  const oldRecordSize = recordEnd - recordStart;
  const sizeDelta = recordSize - oldRecordSize;
  const newModuleInfoSize = moduleInfoSize + sizeDelta;
  if (newModuleInfoSize < 0 || newModuleInfoSize > 0xffffffff ||
      dbiStream.length + sizeDelta > 0xffffffff) {
    throw new UnsupportedFormatError("Classic PDB DBI module names exceed supported size limits");
  }
  const rewrittenModuleInfo = new Uint8Array(newModuleInfoSize);
  rewrittenModuleInfo.set(dbiStream.subarray(64, recordStart));
  rewrittenModuleInfo.set(replacementRecord, recordStart - 64);
  rewrittenModuleInfo.set(
    dbiStream.subarray(recordEnd, moduleInfoEnd),
    recordStart - 64 + recordSize
  );
  const rewrittenDbi = new Uint8Array(dbiStream.length + sizeDelta);
  rewrittenDbi.set(dbiStream.subarray(0, 64));
  rewrittenDbi.set(rewrittenModuleInfo, 64);
  rewrittenDbi.set(dbiStream.subarray(moduleInfoEnd), 64 + newModuleInfoSize);
  new DataView(rewrittenDbi.buffer).setUint32(24, newModuleInfoSize, true);

  let output = rebuildClassicPdbStreams(pdb, new Map([[3, rewrittenDbi]]));
  const overlay = bytes.subarray(pdb.numBlocks * pdb.blockSize);
  if (overlay.length > 0) {
    const withOverlay = new Uint8Array(output.length + overlay.length);
    withOverlay.set(output);
    withOverlay.set(overlay, output.length);
    output = withOverlay;
  }
  parseClassicPdb(output);
  return output;
}

export function replaceClassicPdbLineInfo(
  input,
  { moduleIndex, lineSubsectionIndex, blockIndex, lineIndex, line } = {}
) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  for (const [value, label] of [
    [moduleIndex, "module"],
    [lineSubsectionIndex, "line subsection"],
    [blockIndex, "line block"],
    [lineIndex, "line"]
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      throw new RangeError(`Classic PDB ${label} index must be a non-negative integer`);
    }
  }
  if (!line || typeof line !== "object" || Array.isArray(line)) {
    throw new TypeError("Classic PDB line replacement must be an object");
  }
  const allowedFields = new Set([
    "offset", "startLine", "endLineDelta", "isStatement", "startColumn", "endColumn"
  ]);
  if (Object.keys(line).length === 0 ||
      Object.keys(line).some((field) => !allowedFields.has(field))) {
    throw new TypeError("Classic PDB line replacement has no supported fields");
  }

  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  const lineSubsection = module?.c13?.lines[lineSubsectionIndex];
  const block = lineSubsection?.blocks[blockIndex];
  const existingLine = block?.lines[lineIndex];
  if (!module || !lineSubsection || !block || !existingLine) {
    throw new RangeError("Classic PDB line location does not exist");
  }
  const startLine = line.startLine ?? existingLine.startLine;
  const endLineDelta = line.endLineDelta ?? existingLine.endLineDelta;
  const isStatement = line.isStatement ?? existingLine.isStatement;
  const startColumn = line.startColumn ?? existingLine.startColumn;
  const endColumn = line.endColumn ?? existingLine.endColumn;
  const offset = line.offset ?? existingLine.offset;
  if (!Number.isInteger(offset) || offset < 0 || offset > 0xffffffff ||
      !Number.isInteger(startLine) || startLine < 0 || startLine > 0x00ffffff ||
      !Number.isInteger(endLineDelta) || endLineDelta < 0 || endLineDelta > 0x7f ||
      startLine + endLineDelta > 0x00ffffff ||
      typeof isStatement !== "boolean") {
    throw new RangeError("Classic PDB line number fields are out of range");
  }
  if ("startColumn" in line || "endColumn" in line) {
    if ((lineSubsection.flags & 1) === 0) {
      throw new UnsupportedFormatError(
        "Classic PDB line subsection does not store column information"
      );
    }
    if (!Number.isInteger(startColumn) || startColumn < 0 || startColumn > 0xffff ||
        !Number.isInteger(endColumn) || endColumn < startColumn || endColumn > 0xffff) {
      throw new RangeError("Classic PDB line column fields are out of range");
    }
  }

  const c13SubsectionIndex = module.c13.subsections
    .map((subsection, index) => subsection.kind === 0xf2 ? index : -1)
    .filter((index) => index >= 0)[lineSubsectionIndex];
  let c13Offset = 0;
  for (let index = 0; index < c13SubsectionIndex; index++) {
    const subsection = module.c13.subsections[index];
    c13Offset += 8 + ((subsection.data.length + 3) & ~3);
  }
  const lineData = module.c13.subsections[c13SubsectionIndex].data;
  const lineView = new DataView(lineData.buffer, lineData.byteOffset, lineData.byteLength);
  let blockOffset = 12;
  for (let index = 0; index < blockIndex; index++) {
    blockOffset += lineView.getUint32(blockOffset + 8, true);
  }
  const lineCount = lineView.getUint32(blockOffset + 4, true);
  const hasColumns = (lineSubsection.flags & 1) !== 0;
  const lineRecordOffset = blockOffset + 12 + lineIndex * 8;
  const lineFlags = (
    startLine |
    (endLineDelta << 24) |
    (isStatement ? 0x80000000 : 0)
  ) >>> 0;
  const replacement = new Uint8Array(8);
  const replacementView = new DataView(replacement.buffer);
  replacementView.setUint32(0, offset, true);
  replacementView.setUint32(4, lineFlags, true);
  const columnReplacement = new Uint8Array(4);
  const columnView = new DataView(columnReplacement.buffer);
  if (hasColumns) {
    const columnOffset = blockOffset + 12 + lineCount * 8 + lineIndex * 4;
    columnView.setUint16(0, startColumn, true);
    columnView.setUint16(2, endColumn, true);
    if (columnOffset + 4 > lineData.length) {
      throw new FormatError("Classic PDB line column record exceeds its subsection");
    }
  }
  const streamOffset = module.symbolBytes + module.c11Bytes +
    c13Offset + 8 + lineRecordOffset;
  let output = replaceClassicPdbStreamBytes(
    bytes,
    pdb,
    module.streamIndex,
    streamOffset,
    replacement
  );
  if (hasColumns && ("startColumn" in line || "endColumn" in line)) {
    const columnOffset = module.symbolBytes + module.c11Bytes +
      c13Offset + 8 + blockOffset + 12 + lineCount * 8 + lineIndex * 4;
    output = replaceClassicPdbStreamBytes(
      output,
      pdb,
      module.streamIndex,
      columnOffset,
      columnReplacement
    );
  }
  parseClassicPdb(output);
  return output;
}

function rewriteClassicPdbLineBlock(
  input,
  { moduleIndex, lineSubsectionIndex, blockIndex, lines, fileChecksumOffset, operation }
) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  for (const [value, label] of [
    [moduleIndex, "module"],
    [lineSubsectionIndex, "line subsection"],
    [blockIndex, "line block"]
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      throw new RangeError(`Classic PDB ${label} index must be a non-negative integer`);
    }
  }
  if (!["replace", "insert", "remove"].includes(operation)) {
    throw new TypeError("Classic PDB line-block operation is invalid");
  }
  if (!Array.isArray(lines) ||
      (operation === "remove" ? lines.length !== 0 : lines.length === 0)) {
    throw new TypeError(
      operation === "remove"
        ? "Classic PDB line-block removal does not accept replacement lines"
        : "Classic PDB line-block replacement requires a non-empty lines array"
    );
  }

  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  const lineSubsection = module?.c13?.lines[lineSubsectionIndex];
  const block = lineSubsection?.blocks[blockIndex];
  if (!module || !lineSubsection ||
      (operation !== "insert" && !block) ||
      (operation === "insert" && blockIndex > lineSubsection.blocks.length)) {
    throw new RangeError("Classic PDB line-block location does not exist");
  }
  if (operation === "insert" &&
      (!Number.isInteger(fileChecksumOffset) || fileChecksumOffset < 0 ||
       !module.c13.fileChecksums.has(fileChecksumOffset))) {
    throw new RangeError("Classic PDB line-block checksum location does not exist");
  }
  const hasColumns = (lineSubsection.flags & 1) !== 0;
  const allowedFields = hasColumns
    ? new Set(["offset", "startLine", "endLineDelta", "isStatement", "startColumn", "endColumn"])
    : new Set(["offset", "startLine", "endLineDelta", "isStatement"]);
  const stride = hasColumns ? 12 : 8;
  const newBlockSize = operation === "remove" ? 0 : 12 + lines.length * stride;
  if (newBlockSize > 0xffffffff) {
    throw new RangeError("Classic PDB line block exceeds its 32-bit size limit");
  }
  const rewrittenBlock = new Uint8Array(newBlockSize);
  const rewrittenBlockView = new DataView(rewrittenBlock.buffer);
  if (operation !== "remove") {
    rewrittenBlockView.setUint32(
      0,
      operation === "insert" ? fileChecksumOffset : block.fileChecksumOffset,
      true
    );
    rewrittenBlockView.setUint32(4, lines.length, true);
    rewrittenBlockView.setUint32(8, newBlockSize, true);
  }
  let previousOffset = -1;
  for (const [index, line] of lines.entries()) {
    if (!line || typeof line !== "object" || Array.isArray(line) ||
        Object.keys(line).length !== allowedFields.size ||
        Object.keys(line).some((field) => !allowedFields.has(field)) ||
        [...allowedFields].some((field) => !Object.hasOwn(line, field))) {
      throw new TypeError(`Classic PDB replacement line ${index} has invalid fields`);
    }
    if (!Number.isInteger(line.offset) || line.offset < 0 ||
        line.offset > lineSubsection.codeSize ||
        !Number.isInteger(line.startLine) || line.startLine < 0 ||
        line.startLine > 0x00ffffff ||
        !Number.isInteger(line.endLineDelta) || line.endLineDelta < 0 ||
        line.endLineDelta > 0x7f ||
        line.startLine + line.endLineDelta > 0x00ffffff ||
        typeof line.isStatement !== "boolean") {
      throw new RangeError(`Classic PDB replacement line ${index} has out-of-range fields`);
    }
    if (line.offset < previousOffset) {
      throw new RangeError("Classic PDB replacement line offsets must be nondecreasing");
    }
    previousOffset = line.offset;
    const recordOffset = 12 + index * 8;
    rewrittenBlockView.setUint32(recordOffset, line.offset, true);
    rewrittenBlockView.setUint32(
      recordOffset + 4,
      (line.startLine | (line.endLineDelta << 24) |
        (line.isStatement ? 0x80000000 : 0)) >>> 0,
      true
    );
    if (hasColumns) {
      if (!Number.isInteger(line.startColumn) || line.startColumn < 0 ||
          line.startColumn > 0xffff ||
          !Number.isInteger(line.endColumn) ||
          line.endColumn < line.startColumn || line.endColumn > 0xffff) {
        throw new RangeError(`Classic PDB replacement line ${index} has invalid columns`);
      }
      const columnOffset = 12 + lines.length * 8 + index * 4;
      rewrittenBlockView.setUint16(columnOffset, line.startColumn, true);
      rewrittenBlockView.setUint16(columnOffset + 2, line.endColumn, true);
    }
  }

  const lineSubsectionIndexInC13 = module.c13.subsections
    .map((subsection, index) => subsection.kind === 0xf2 ? index : -1)
    .filter((index) => index >= 0)[lineSubsectionIndex];
  const lineSubsectionInC13 = module.c13.subsections[lineSubsectionIndexInC13];
  const lineData = lineSubsectionInC13.data;
  const lineView = new DataView(lineData.buffer, lineData.byteOffset, lineData.byteLength);
  let blockOffset = 12;
  for (let index = 0; index < blockIndex; index++) {
    blockOffset += lineView.getUint32(blockOffset + 8, true);
  }
  const oldBlockSize = operation === "insert"
    ? 0
    : lineView.getUint32(blockOffset + 8, true);
  if (operation !== "insert" &&
      oldBlockSize !== 12 + block.lines.length * stride) {
    throw new UnsupportedFormatError(
      "Classic PDB line-block replacement cannot discard unrecognized block data"
    );
  }
  const rewrittenLineDataLength = lineData.length - oldBlockSize + newBlockSize;
  if (rewrittenLineDataLength > 0xffffffff) {
    throw new RangeError("Classic PDB C13 line subsection exceeds its 32-bit size limit");
  }
  const rewrittenLineData = new Uint8Array(rewrittenLineDataLength);
  rewrittenLineData.set(lineData.subarray(0, blockOffset));
  rewrittenLineData.set(rewrittenBlock, blockOffset);
  rewrittenLineData.set(
    lineData.subarray(blockOffset + oldBlockSize),
    blockOffset + newBlockSize
  );
  const rewrittenSubsections = module.c13.subsections.map((subsection, index) =>
    index === lineSubsectionIndexInC13
      ? { ...subsection, data: rewrittenLineData, sourceIndex: index }
      : subsection
  );
  return rebuildClassicPdbC13Module(bytes, pdb, moduleIndex, rewrittenSubsections);
}

export function replaceClassicPdbLineBlock(input, options = {}) {
  const { moduleIndex, lineSubsectionIndex, blockIndex, lines } = options;
  return rewriteClassicPdbLineBlock(input, {
    moduleIndex,
    lineSubsectionIndex,
    blockIndex,
    lines,
    operation: "replace"
  });
}

export function insertClassicPdbLineBlock(input, options = {}) {
  const {
    moduleIndex,
    lineSubsectionIndex,
    beforeBlockIndex,
    fileChecksumOffset,
    lines
  } = options;
  return rewriteClassicPdbLineBlock(input, {
    moduleIndex,
    lineSubsectionIndex,
    blockIndex: beforeBlockIndex,
    fileChecksumOffset,
    lines,
    operation: "insert"
  });
}

export function removeClassicPdbLineBlock(input, options = {}) {
  const { moduleIndex, lineSubsectionIndex, blockIndex } = options;
  return rewriteClassicPdbLineBlock(input, {
    moduleIndex,
    lineSubsectionIndex,
    blockIndex,
    lines: [],
    operation: "remove"
  });
}

function getClassicPdbChecksumKind(checksum, checksumKind) {
  if (!(checksum instanceof Uint8Array)) {
    throw new TypeError("Classic PDB file checksum must be a Uint8Array");
  }
  const inferredKind = new Map([[0, 0], [16, 1], [20, 2], [32, 3]])
    .get(checksum.length);
  const resolvedKind = checksumKind ?? inferredKind;
  if (!Number.isInteger(resolvedKind) || resolvedKind < 0 || resolvedKind > 3) {
    throw new UnsupportedFormatError(
      `Classic PDB file-checksum length ${checksum.length} has no supported checksum kind`
    );
  }
  const expectedSize = new Map([[0, 0], [1, 16], [2, 20], [3, 32]])
    .get(resolvedKind);
  if (checksum.length !== expectedSize) {
    throw new RangeError(
      `Classic PDB checksum kind ${resolvedKind} requires ${expectedSize} bytes`
    );
  }
  return resolvedKind;
}

function rewriteClassicPdbFileChecksumRecords(bytes, pdb, moduleIndex, records) {
  const module = pdb.dbi?.modules[moduleIndex];
  if (!module) throw new RangeError("Classic PDB module index does not exist");
  const checksumSubsectionIndex = module.c13?.subsections.findIndex(
    (subsection) => subsection.kind === 0xf4
  ) ?? -1;
  const checksumOffsets = new Map();
  const checksumData = [];
  let checksumDataLength = 0;
  for (const record of records) {
    const recordLength = (6 + record.checksum.length + 3) & ~3;
    if (checksumDataLength + recordLength > 0xffffffff) {
      throw new RangeError("Classic PDB file-checksum subsection exceeds its 32-bit size limit");
    }
    if (record.sourceOffset !== null) {
      if (checksumOffsets.has(record.sourceOffset)) {
        throw new FormatError("Classic PDB file-checksum source offsets are duplicated");
      }
      checksumOffsets.set(record.sourceOffset, checksumDataLength);
    }
    const recordBytes = new Uint8Array(recordLength);
    const recordView = new DataView(recordBytes.buffer);
    recordView.setUint32(0, record.fileNameOffset, true);
    recordView.setUint8(4, record.checksum.length);
    recordView.setUint8(5, record.checksumKind);
    recordBytes.set(record.checksum, 6);
    checksumData.push(recordBytes);
    checksumDataLength += recordLength;
  }
  const rewrittenChecksumData = new Uint8Array(checksumDataLength);
  let checksumDataOffset = 0;
  for (const recordBytes of checksumData) {
    rewrittenChecksumData.set(recordBytes, checksumDataOffset);
    checksumDataOffset += recordBytes.length;
  }

  const rewrittenSubsections = (module.c13?.subsections ?? []).map((subsection, index) => {
    if (index === checksumSubsectionIndex) {
      return { ...subsection, data: rewrittenChecksumData, sourceIndex: index };
    }
    if (subsection.kind !== 0xf2) return subsection;
    const data = Uint8Array.from(subsection.data);
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let blockOffset = 12;
    while (blockOffset < data.length) {
      const oldOffset = view.getUint32(blockOffset, true);
      const newOffset = checksumOffsets.get(oldOffset);
      if (newOffset === undefined) {
        throw new FormatError(
          "Classic PDB line block references a missing file-checksum record"
        );
      }
      view.setUint32(blockOffset, newOffset, true);
      blockOffset += view.getUint32(blockOffset + 8, true);
    }
    return { ...subsection, data, sourceIndex: index };
  });
  if (checksumSubsectionIndex < 0) {
    const subsection = { kind: 0xf4, data: rewrittenChecksumData };
    const firstLineSubsection = rewrittenSubsections.findIndex((entry) => entry.kind === 0xf2);
    if (firstLineSubsection < 0) rewrittenSubsections.push(subsection);
    else rewrittenSubsections.splice(firstLineSubsection, 0, subsection);
  }
  return rebuildClassicPdbC13Module(bytes, pdb, moduleIndex, rewrittenSubsections);
}

export function replaceClassicPdbFileChecksum(
  input,
  { moduleIndex, fileChecksumOffset, checksum, checksumKind } = {}
) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(moduleIndex) || moduleIndex < 0) {
    throw new RangeError("Classic PDB module index must be a non-negative integer");
  }
  if (!Number.isInteger(fileChecksumOffset) || fileChecksumOffset < 0) {
    throw new RangeError("Classic PDB file-checksum offset must be a non-negative integer");
  }

  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  const originalChecksum = module?.c13?.fileChecksums.get(fileChecksumOffset);
  if (!module || !originalChecksum) {
    throw new RangeError("Classic PDB file-checksum location does not exist");
  }
  const resolvedChecksumKind = getClassicPdbChecksumKind(checksum, checksumKind);

  const checksumSubsectionIndex = module.c13.subsections.findIndex(
    (subsection) => subsection.kind === 0xf4
  );
  if (checksumSubsectionIndex < 0) {
    throw new FormatError("Classic PDB file-checksum subsection is missing");
  }
  let c13Offset = 0;
  for (let index = 0; index < checksumSubsectionIndex; index++) {
    const subsection = module.c13.subsections[index];
    c13Offset += 8 + ((subsection.data.length + 3) & ~3);
  }
  let output;
  if (checksum.length === originalChecksum.checksum.length) {
    const streamOffset = module.symbolBytes + module.c11Bytes +
      c13Offset + 8 + fileChecksumOffset;
    output = replaceClassicPdbStreamBytes(bytes, pdb, module.streamIndex, streamOffset + 4,
      Uint8Array.of(checksum.length, resolvedChecksumKind));
    output = replaceClassicPdbStreamBytes(
      output,
      pdb,
      module.streamIndex,
      streamOffset + 6,
      checksum
    );
  } else {
    const records = [...module.c13.fileChecksums].map(([offset, record]) => {
      const isTarget = offset === fileChecksumOffset;
      return {
        sourceOffset: offset,
        fileNameOffset: record.fileNameOffset,
        checksum: isTarget ? checksum : record.checksum,
        checksumKind: isTarget ? resolvedChecksumKind : record.checksumKind
      };
    });
    output = rewriteClassicPdbFileChecksumRecords(bytes, pdb, moduleIndex, records);
  }
  parseClassicPdb(output);
  return output;
}

export function insertClassicPdbFileChecksum(
  input,
  { moduleIndex, fileNameOffset, checksum, checksumKind } = {}
) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(moduleIndex) || moduleIndex < 0) {
    throw new RangeError("Classic PDB module index must be a non-negative integer");
  }
  if (!Number.isInteger(fileNameOffset) || fileNameOffset < 0 ||
      fileNameOffset > 0xffffffff) {
    throw new RangeError("Classic PDB file-name offset must be an unsigned 32-bit integer");
  }
  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  if (!module) throw new RangeError("Classic PDB module index does not exist");
  if (pdb.info.stringTable && !pdb.info.stringTable.strings.has(fileNameOffset)) {
    throw new RangeError("Classic PDB file-name offset does not exist in the /names stream");
  }
  const resolvedChecksumKind = getClassicPdbChecksumKind(checksum, checksumKind);
  const records = [...(module.c13?.fileChecksums ?? [])].map(([sourceOffset, record]) => ({
    sourceOffset,
    fileNameOffset: record.fileNameOffset,
    checksum: record.checksum,
    checksumKind: record.checksumKind
  }));
  records.push({
    sourceOffset: null,
    fileNameOffset,
    checksum,
    checksumKind: resolvedChecksumKind
  });
  return rewriteClassicPdbFileChecksumRecords(bytes, pdb, moduleIndex, records);
}

export function removeClassicPdbFileChecksum(
  input,
  { moduleIndex, fileChecksumOffset } = {}
) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(moduleIndex) || moduleIndex < 0) {
    throw new RangeError("Classic PDB module index must be a non-negative integer");
  }
  if (!Number.isInteger(fileChecksumOffset) || fileChecksumOffset < 0) {
    throw new RangeError("Classic PDB file-checksum offset must be a non-negative integer");
  }
  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  const checksums = module?.c13?.fileChecksums;
  if (!module || !checksums?.has(fileChecksumOffset)) {
    throw new RangeError("Classic PDB file-checksum location does not exist");
  }
  if (module.c13.lines.some((subsection) =>
    subsection.blocks.some((block) => block.fileChecksumOffset === fileChecksumOffset)
  )) {
    throw new FormatError(
      `Classic PDB file-checksum record ${fileChecksumOffset} is referenced by line blocks`
    );
  }
  const records = [...checksums]
    .filter(([offset]) => offset !== fileChecksumOffset)
    .map(([sourceOffset, record]) => ({
      sourceOffset,
      fileNameOffset: record.fileNameOffset,
      checksum: record.checksum,
      checksumKind: record.checksumKind
    }));
  return rewriteClassicPdbFileChecksumRecords(bytes, pdb, moduleIndex, records);
}

function serializeCodeViewC13Subsections(subsections, originalPadding) {
  let byteLength = 0;
  for (const subsection of subsections) {
    if (subsection.data.length > 0xffffffff) {
      throw new UnsupportedFormatError("Classic PDB C13 subsection exceeds its size limit");
    }
    byteLength += 8 + ((subsection.data.length + 3) & ~3);
  }
  const output = new Uint8Array(byteLength);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const [index, subsection] of subsections.entries()) {
    view.setUint32(offset, subsection.kind, true);
    view.setUint32(offset + 4, subsection.data.length, true);
    output.set(subsection.data, offset + 8);
    const paddingLength = ((subsection.data.length + 3) & ~3) - subsection.data.length;
    const padding = originalPadding[index];
    if (paddingLength > 0 && padding?.length === paddingLength) {
      output.set(padding, offset + 8 + subsection.data.length);
    }
    offset += 8 + subsection.data.length + paddingLength;
  }
  return output;
}

function rebuildClassicPdbC13Module(bytes, pdb, moduleIndex, subsections) {
  const module = pdb.dbi?.modules[moduleIndex];
  const originalStream = module && pdb.streams[module.streamIndex]?.bytes;
  if (!module || !originalStream || module.streamIndex <= 3 ||
      pdb.dbi.modules.some((other, index) =>
        index !== moduleIndex && other.streamIndex === module.streamIndex
      )) {
    throw new UnsupportedFormatError(
      "Classic PDB C13 edits require a dedicated module stream"
    );
  }
  const originalC13Offset = module.symbolBytes + module.c11Bytes;
  const originalSubsections = module.c13?.subsections ?? [];
  const paddingBySubsection = new Map();
  let subsectionOffset = 0;
  for (const subsection of originalSubsections) {
    const paddingStart = subsectionOffset + 8 + subsection.data.length;
    const paddedEnd = (paddingStart + 3) & ~3;
    paddingBySubsection.set(subsection, originalStream.slice(
      originalC13Offset + paddingStart,
      originalC13Offset + paddedEnd
    ));
    subsectionOffset = paddedEnd;
  }
  const rewrittenPadding = subsections.map((subsection) => {
    const sourceIndex = Number.isInteger(subsection.sourceIndex)
      ? subsection.sourceIndex
      : originalSubsections.indexOf(subsection);
    return sourceIndex < 0
      ? new Uint8Array()
      : paddingBySubsection.get(originalSubsections[sourceIndex]) ?? new Uint8Array();
  });
  const rewrittenC13 = serializeCodeViewC13Subsections(subsections, rewrittenPadding);
  if (rewrittenC13.length > 0xffffffff) {
    throw new RangeError("Classic PDB C13 module data exceeds its 32-bit size limit");
  }
  const trailingOffset = originalC13Offset + module.c13Bytes;
  const trailingBytes = originalStream.subarray(trailingOffset);
  const rewrittenModuleStream = new Uint8Array(
    originalC13Offset + rewrittenC13.length + trailingBytes.length
  );
  rewrittenModuleStream.set(originalStream.subarray(0, originalC13Offset));
  rewrittenModuleStream.set(rewrittenC13, originalC13Offset);
  rewrittenModuleStream.set(trailingBytes, originalC13Offset + rewrittenC13.length);

  const dbiStream = pdb.streams[3]?.bytes;
  if (!dbiStream) throw new FormatError("Classic PDB DBI stream is missing");
  const rewrittenDbi = Uint8Array.from(dbiStream);
  new DataView(rewrittenDbi.buffer).setUint32(
    module.moduleInfoOffset + 44,
    rewrittenC13.length,
    true
  );
  let output = rebuildClassicPdbStreams(pdb, new Map([
    [module.streamIndex, rewrittenModuleStream],
    [3, rewrittenDbi]
  ]));
  const overlay = bytes.subarray(pdb.numBlocks * pdb.blockSize);
  if (overlay.length > 0) {
    const withOverlay = new Uint8Array(output.length + overlay.length);
    withOverlay.set(output);
    withOverlay.set(overlay, output.length);
    output = withOverlay;
  }
  parseClassicPdb(output);
  return output;
}

export function replaceClassicPdbSymbolName(input, { moduleIndex, recordIndex, name } = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(moduleIndex) || moduleIndex < 0) {
    throw new RangeError("Classic PDB module index must be a non-negative integer");
  }
  if (!Number.isInteger(recordIndex) || recordIndex < 0) {
    throw new RangeError("Classic PDB symbol record index must be a non-negative integer");
  }
  const replacement = encodeClassicPdbReplacementText(name, "Classic PDB symbol names");
  const pdb = parseClassicPdb(bytes);
  const module = pdb.dbi?.modules[moduleIndex];
  if (!module?.symbols) {
    throw new RangeError(`Classic PDB module ${moduleIndex} has no symbol records`);
  }
  const record = module.symbols.records[recordIndex];
  if (!record) throw new RangeError(`Classic PDB symbol record ${recordIndex} does not exist`);
  const nameOffset = getCodeViewSymbolNameOffset(record);
  if (nameOffset === null || typeof record.decoded?.name !== "string") {
    throw new UnsupportedFormatError("Classic PDB symbol record does not expose a replaceable name");
  }
  const recordDataEnd = record.offset + 4 + nameOffset + replacement.length + 1;
  const paddingSize = (4 - (recordDataEnd % 4)) % 4;
  const replacementData = new Uint8Array(nameOffset + replacement.length + 1 + paddingSize);
  replacementData.set(record.data.subarray(0, nameOffset));
  replacementData.set(replacement, nameOffset);
  replacementData[nameOffset + replacement.length] = 0;
  if (paddingSize > 0) {
    for (let index = 0; index < paddingSize; index++) {
      replacementData[nameOffset + replacement.length + 1 + index] = 0xf0 + paddingSize - index;
    }
  }
  const recordSize = 4 + replacementData.length;
  const recordBytes = new Uint8Array(recordSize);
  const recordView = new DataView(recordBytes.buffer);
  recordView.setUint16(0, 2 + replacementData.length, true);
  recordView.setUint16(2, record.kind, true);
  recordBytes.set(replacementData, 4);
  const oldRecordSize = 4 + record.data.length;
  const sizeDelta = recordSize - oldRecordSize;
  const stream = pdb.streams[module.streamIndex];
  const newSymbolBytes = module.symbolBytes + sizeDelta;
  const newStreamSize = stream.size + sizeDelta;
  if (sizeDelta !== 0 && module.symbols.records.some((symbol) =>
    codeViewScopeSymbolKinds.has(symbol.kind) || symbol.decoded === null
  )) {
    throw new UnsupportedFormatError(
      "Classic PDB symbol replacement cannot resize modules with scoped or unknown symbols"
    );
  }
  if (sizeDelta !== 0 && (
    module.streamIndex <= 3 ||
    pdb.dbi.modules.some((other, index) =>
      index !== moduleIndex && other.streamIndex === module.streamIndex
    )
  )) {
    throw new UnsupportedFormatError(
      "Classic PDB symbol replacement cannot resize a reserved or shared module stream"
    );
  }
  if (newSymbolBytes < 4 || newSymbolBytes > 0xffffffff ||
      newStreamSize < newSymbolBytes || newStreamSize > 0xffffffff) {
    throw new UnsupportedFormatError(
      "Classic PDB symbol replacement exceeds supported stream-size limits"
    );
  }
  const streamBytes = new Uint8Array(newStreamSize);
  streamBytes.set(stream.bytes.subarray(0, record.offset));
  streamBytes.set(recordBytes, record.offset);
  streamBytes.set(
    stream.bytes.subarray(record.offset + oldRecordSize),
    record.offset + recordSize
  );
  if (Math.ceil(newStreamSize / pdb.blockSize) !== stream.blockIndices.length) {
    const dbiBytes = Uint8Array.from(pdb.streams[3].bytes);
    new DataView(dbiBytes.buffer).setUint32(
      module.moduleInfoOffset + 36,
      newSymbolBytes,
      true
    );
    const output = rebuildClassicPdbStreams(pdb, new Map([
      [module.streamIndex, streamBytes],
      [3, dbiBytes]
    ]));
    parseClassicPdb(output);
    return output;
  }
  let output = writeClassicPdbStream(bytes, pdb, module.streamIndex, streamBytes);
  const updatedDbi = new Uint8Array(4);
  new DataView(updatedDbi.buffer).setUint32(0, newSymbolBytes, true);
  output = replaceClassicPdbStreamBytes(
    output,
    pdb,
    3,
    module.moduleInfoOffset + 36,
    updatedDbi
  );
  const updatedStreamSize = new Uint8Array(4);
  new DataView(updatedStreamSize.buffer).setUint32(0, newStreamSize, true);
  output = replaceClassicPdbDirectoryBytes(
    output,
    pdb,
    4 + 4 * module.streamIndex,
    updatedStreamSize
  );
  parseClassicPdb(output);
  return output;
}

export function replaceClassicPdbStringTableName(input, { nameOffset, name } = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(nameOffset) || nameOffset < 0) {
    throw new RangeError("Classic PDB string-table offset must be a non-negative integer");
  }
  const replacement = encodeClassicPdbReplacementText(name, "Classic PDB string-table names");
  const pdb = parseClassicPdb(bytes);
  const streamIndex = pdb.info.namedStreams.get("/names");
  if (streamIndex === undefined || !pdb.info.stringTable) {
    throw new UnsupportedFormatError("Classic PDB has no /names string table");
  }
  const existingName = pdb.info.stringTable.strings.get(nameOffset);
  if (existingName === undefined) {
    throw new RangeError(`Classic PDB string-table offset ${nameOffset} does not exist`);
  }
  const existingBytes = new TextEncoder().encode(existingName);
  if (replacement.length === existingBytes.length) {
    const output = replaceClassicPdbStreamBytes(
      bytes, pdb, streamIndex, 12 + nameOffset, replacement
    );
    parseClassicPdb(output);
    return output;
  }

  const updatedStrings = [];
  const remappedOffsets = new Map();
  const encoder = new TextEncoder();
  let updatedStringByteLength = 0;
  for (const [offset, value] of [...pdb.info.stringTable.strings].sort((a, b) => a[0] - b[0])) {
    remappedOffsets.set(offset, updatedStringByteLength);
    const encoded = offset === nameOffset ? replacement : encoder.encode(value);
    updatedStrings.push(encoded);
    updatedStrings.push(Uint8Array.of(0));
    updatedStringByteLength += encoded.length + 1;
  }
  if (updatedStringByteLength > 0xffffffff) {
    throw new UnsupportedFormatError("Classic PDB /names string table exceeds its 32-bit size limit");
  }
  const stringBytes = new Uint8Array(updatedStringByteLength);
  let stringByteOffset = 0;
  for (const part of updatedStrings) {
    stringBytes.set(part, stringByteOffset);
    stringByteOffset += part.length;
  }
  const stringTable = pdb.info.stringTable;
  const nameIds = stringTable.nameIds.map((offset) => {
    const updatedOffset = offset === 0 ? 0 : remappedOffsets.get(offset);
    if (updatedOffset === undefined) {
      throw new FormatError("Classic PDB /names hash table references a missing string");
    }
    return updatedOffset;
  });
  const namesStream = new Uint8Array(20 + stringBytes.length + nameIds.length * 4);
  const namesView = new DataView(namesStream.buffer);
  namesView.setUint32(0, stringTable.signature, true);
  namesView.setUint32(4, stringTable.hashVersion, true);
  namesView.setUint32(8, stringBytes.length, true);
  namesStream.set(stringBytes, 12);
  let namesOffset = 12 + stringBytes.length;
  namesView.setUint32(namesOffset, nameIds.length, true);
  namesOffset += 4;
  for (const offset of nameIds) {
    namesView.setUint32(namesOffset, offset, true);
    namesOffset += 4;
  }
  namesView.setUint32(namesOffset, stringTable.nameCount, true);

  const replacements = new Map([[streamIndex, namesStream]]);
  const mutableModuleStreams = new Map();
  for (const module of pdb.dbi?.modules ?? []) {
    if (!module.c13) continue;
    const stream = mutableModuleStreams.get(module.streamIndex) ??
      Uint8Array.from(pdb.streams[module.streamIndex].bytes);
    let updated = false;
    let subsectionOffset = 0;
    for (const subsection of module.c13.subsections) {
      if (subsection.kind === 0xf4) {
        const checksumData = Uint8Array.from(subsection.data);
        const checksumView = new DataView(checksumData.buffer);
        for (const [recordOffset, checksum] of module.c13.fileChecksums) {
          const updatedOffset = remappedOffsets.get(checksum.fileNameOffset);
          if (updatedOffset === undefined) {
            throw new FormatError("Classic PDB C13 checksum references a missing /names entry");
          }
          if (updatedOffset === checksum.fileNameOffset) continue;
          checksumView.setUint32(recordOffset, updatedOffset, true);
          updated = true;
        }
        if (updated) {
          stream.set(
            checksumData,
            module.symbolBytes + module.c11Bytes + subsectionOffset + 8
          );
        }
      }
      subsectionOffset = (subsectionOffset + 8 + subsection.data.length + 3) & ~3;
    }
    if (updated) mutableModuleStreams.set(module.streamIndex, stream);
  }
  for (const [moduleStreamIndex, moduleStream] of mutableModuleStreams) {
    replacements.set(moduleStreamIndex, moduleStream);
  }
  const output = rebuildClassicPdbStreams(pdb, replacements);
  parseClassicPdb(output);
  return output;
}
