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
  return {
    format: "MSF 7.0",
    blockSize,
    numBlocks,
    info: {
      version: infoView.getUint32(0, true),
      signature: infoView.getUint32(4, true),
      age: infoView.getUint32(8, true),
      guid: formatGuid(id),
      ...infoDetails
    },
    streams
  };
}
