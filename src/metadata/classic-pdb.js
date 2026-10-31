import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

const msfMagic = new TextEncoder().encode("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0");
const absentStream = 0xffffffff;

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
      name = new TextDecoder("utf-8", { fatal: true })
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
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
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
          new TextDecoder("utf-8", { fatal: true }).decode(names.subarray(nameOffset, terminator))
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

function readCodeViewName(bytes, offset, context) {
  const end = bytes.indexOf(0, offset);
  if (end < 0) throw new FormatError(`Classic PDB ${context} name is not null-terminated`);
  const padding = bytes.subarray(end + 1);
  if (padding.length > 0) {
    const marker = padding[padding.length - 1];
    const paddingLength = marker - 0xf0;
    if (paddingLength !== padding.length || padding.some((byte) => byte !== marker)) {
      throw new FormatError(`Classic PDB ${context} name has invalid CodeView padding`);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(offset, end));
  } catch (error) {
    throw new FormatError(`Classic PDB ${context} name is invalid UTF-8: ${error.message}`);
  }
}

function decodeCodeViewSymbol(kind, data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
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
      value = new TextDecoder("utf-8", { fatal: true })
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
      streams.push({ index, size: null, bytes: null });
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
    streams.push({ index, size, bytes: streamBytes });
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
    info,
    dbi,
    streams
  };
}
