import { BinaryReader, readCompressedUInt } from "../binary/reader.js";
import { FormatError } from "../binary/errors.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function validateStringsHeap(bytes) {
  let start = 1;
  while (start < bytes.length) {
    const end = bytes.indexOf(0, start);
    if (end < 0) {
      throw new FormatError("Unterminated string heap entry", { context: "#Strings" });
    }
    try {
      utf8Decoder.decode(bytes.subarray(start, end));
    } catch (error) {
      throw new FormatError(`Invalid UTF-8 string: ${error.message}`, { context: "#Strings" });
    }
    start = end + 1;
  }
}

function validateLengthPrefixedHeap(
  bytes,
  name,
  validatePayload = () => {},
  allowTrailingZeroPadding = false,
  entryOffsets = new Set([0])
) {
  const reader = new BinaryReader(bytes, { start: 1, baseOffset: 1, context: name });
  while (reader.remaining > 0) {
    if (allowTrailingZeroPadding &&
        bytes.subarray(reader.absoluteOffset).every((byte) => byte === 0)) {
      break;
    }
    const entryOffset = reader.absoluteOffset;
    entryOffsets.add(entryOffset);
    const prefixOffset = reader.position;
    const size = readCompressedUInt(reader);
    const prefixSize = reader.position - prefixOffset;
    const expectedPrefixSize = size <= 0x7f ? 1 : size <= 0x3fff ? 2 : 4;
    if (prefixSize !== expectedPrefixSize) {
      throw new FormatError(`Noncanonical length prefix in ${name}`, {
        offset: entryOffset,
        context: name
      });
    }
    validatePayload(reader.take(size), entryOffset);
  }
  return reader.absoluteOffset;
}

export function parseMetadataRoot(input, offset, size) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!Number.isInteger(offset) || !Number.isInteger(size) || offset < 0 || size < 0 || offset + size > bytes.length) {
    throw new FormatError("Metadata directory is outside the file", { offset, context: "metadata root" });
  }
  const reader = new BinaryReader(bytes, { start: offset, length: size, baseOffset: offset, context: "metadata root" });
  if (reader.u4() !== 0x424a5342) throw new FormatError("Invalid BSJB metadata signature", { offset });
  const majorVersion = reader.u2();
  const minorVersion = reader.u2();
  const reserved = reader.u4();
  if (reserved !== 0) {
    throw new FormatError("Metadata root reserved field must be zero", {
      offset: offset + 8,
      context: "metadata root"
    });
  }
  const versionLength = reader.u4();
  const versionBytes = reader.take(versionLength);
  const nul = versionBytes.indexOf(0);
  if (nul < 0 || versionBytes.subarray(nul).some((byte) => byte !== 0)) {
    throw new FormatError("Metadata version string is not null-terminated", {
      offset: offset + 16,
      context: "metadata root"
    });
  }
  let version;
  try {
    version = utf8Decoder.decode(versionBytes.subarray(0, nul));
  } catch (error) {
    throw new FormatError(`Invalid UTF-8 metadata version: ${error.message}`, {
      offset: offset + 16,
      context: "metadata root"
    });
  }
  reader.align(4);
  const flags = reader.u2();
  if (flags !== 0) {
    throw new FormatError("Metadata root flags must be zero", {
      offset: reader.absoluteOffset - 2,
      context: "metadata root"
    });
  }
  const streamCount = reader.u2();
  const streams = new Map();
  for (let i = 0; i < streamCount; i++) {
    const streamOffset = reader.u4();
    const streamSize = reader.u4();
    const nameBytes = [];
    for (let j = 0; j < 32; j++) {
      const value = reader.u1();
      if (value === 0) break;
      if (value > 0x7f) {
        throw new FormatError("Metadata stream name contains a non-ASCII byte", {
          offset: reader.absoluteOffset - 1,
          context: "metadata root"
        });
      }
      nameBytes.push(value);
    }
    if (reader.bytes[reader.position - 1] !== 0) {
      throw new FormatError("Metadata stream name is not null-terminated within 32 bytes", {
        offset: reader.absoluteOffset,
        context: "metadata root"
      });
    }
    const nameEnd = reader.position;
    reader.align(4);
    if (reader.bytes.subarray(nameEnd, reader.position).some((byte) => byte !== 0)) {
      throw new FormatError("Metadata stream name padding must be zero", {
        offset: offset + nameEnd,
        context: "metadata root"
      });
    }
    if (nameBytes.length === 0) {
      throw new FormatError("Metadata stream name must not be empty", {
        offset: reader.absoluteOffset,
        context: "metadata root"
      });
    }
    const name = String.fromCharCode(...nameBytes);
    if (streams.has(name)) throw new FormatError(`Duplicate metadata stream ${name}`, { offset: reader.absoluteOffset });
    if ((streamOffset & 3) !== 0) {
      throw new FormatError(`Metadata stream ${name} is not four-byte aligned`, {
        offset: offset + streamOffset,
        context: "metadata root"
      });
    }
    if (streamOffset + streamSize > size) {
      throw new FormatError(`Metadata stream ${name} exceeds the metadata directory`, {
        offset: offset + streamOffset,
        context: "metadata root"
      });
    }
    streams.set(name, {
      name,
      offset: offset + streamOffset,
      relativeOffset: streamOffset,
      size: streamSize,
      bytes: bytes.slice(offset + streamOffset, offset + streamOffset + streamSize)
    });
  }
  const streamHeaderEnd = reader.position;
  const ranges = [...streams.values()]
    .sort((left, right) => left.relativeOffset - right.relativeOffset);
  for (let index = 0; index < ranges.length; index++) {
    const stream = ranges[index];
    if (stream.relativeOffset < streamHeaderEnd) {
      throw new FormatError(`Metadata stream ${stream.name} overlaps the stream directory`, {
        offset: offset + stream.relativeOffset,
        context: "metadata root"
      });
    }
    const next = ranges[index + 1];
    if (stream.size > 0 && next && stream.relativeOffset + stream.size > next.relativeOffset) {
      throw new FormatError(`Metadata streams ${stream.name} and ${next.name} overlap`, {
        offset: offset + next.relativeOffset,
        context: "metadata root"
      });
    }
  }
  return { offset, size, majorVersion, minorVersion, version, versionLength, versionBytes, flags, streams };
}

export class MetadataHeaps {
  constructor(streams) {
    this.strings = streams.get("#Strings")?.bytes.slice();
    this.userStrings = streams.get("#US")?.bytes.slice();
    this.guids = streams.get("#GUID")?.bytes.slice();
    this.blobs = streams.get("#Blob")?.bytes.slice();
    this.userStringDataEnd = this.userStrings?.length ?? 0;
    this.blobEntryOffsets = null;
    this.userStringEntryOffsets = null;
    for (const [name, bytes] of [
      ["#Strings", this.strings],
      ["#US", this.userStrings],
      ["#Blob", this.blobs]
    ]) {
      if (bytes && (bytes.length === 0 || bytes[0] !== 0)) {
        throw new FormatError(`${name} heap is missing its zero entry`, { context: name });
      }
    }
    if (this.guids && this.guids.length % 16 !== 0) {
      throw new FormatError("#GUID heap size is not a multiple of 16 bytes", { context: "#GUID" });
    }
    if (this.strings) validateStringsHeap(this.strings);
    if (this.blobs) {
      this.blobEntryOffsets = new Set([0]);
      validateLengthPrefixedHeap(this.blobs, "#Blob", () => {}, false, this.blobEntryOffsets);
    }
    if (this.userStrings) {
      this.userStringEntryOffsets = new Set([0]);
      this.userStringDataEnd = validateLengthPrefixedHeap(this.userStrings, "#US", (payload, offset) => {
        const textLength = payload.length - 1;
        if (payload.length < 1 || (textLength & 1) !== 0 || payload[textLength] > 1) {
          throw new FormatError("Invalid UTF-16LE user-string encoding", {
            offset,
            context: "#US"
          });
        }
      }, true, this.userStringEntryOffsets);
    }
  }

  #heap(bytes, name, index) {
    if (!bytes) throw new FormatError(`Metadata heap ${name} is missing`);
    if (!Number.isInteger(index) || index < 0 || index >= bytes.length) {
      throw new FormatError(`Index ${index} is outside ${name}`, { context: "metadata heap" });
    }
    return bytes;
  }

  getString(index) {
    if (index === 0) return "";
    const bytes = this.#heap(this.strings, "#Strings", index);
    let end = index;
    while (end < bytes.length && bytes[end] !== 0) end++;
    if (end === bytes.length) throw new FormatError("Unterminated string heap entry", { context: "#Strings" });
    try {
      return utf8Decoder.decode(bytes.subarray(index, end));
    } catch (error) {
      throw new FormatError(`Invalid UTF-8 string: ${error.message}`, { context: "#Strings" });
    }
  }

  getBlob(index) {
    if (index === 0) return new Uint8Array();
    const bytes = this.#heap(this.blobs, "#Blob", index);
    if (!this.blobEntryOffsets?.has(index)) {
      throw new FormatError(`Index ${index} is not a #Blob entry boundary`, {
        context: "#Blob"
      });
    }
    const reader = new BinaryReader(bytes, { start: index, baseOffset: index, context: "#Blob" });
    const size = readCompressedUInt(reader);
    return reader.take(size).slice();
  }

  getGuid(index) {
    if (index === 0) return null;
    const bytes = this.#heap(this.guids, "#GUID", (index - 1) * 16);
    const offset = (index - 1) * 16;
    if (offset + 16 > bytes.length) throw new FormatError("GUID index exceeds #GUID heap", { context: "#GUID" });
    return bytes.slice(offset, offset + 16);
  }

  getUserString(tokenOrOffset) {
    const offset = tokenOrOffset > 0xffffff ? tokenOrOffset & 0x00ffffff : tokenOrOffset;
    if (offset === 0) return "";
    const bytes = this.#heap(this.userStrings, "#US", offset);
    if (!this.userStringEntryOffsets?.has(offset) || offset >= this.userStringDataEnd) {
      throw new FormatError(`Index ${offset} is not a #US entry boundary`, {
        context: "#US"
      });
    }
    const reader = new BinaryReader(bytes, { start: offset, baseOffset: offset, context: "#US" });
    const size = readCompressedUInt(reader);
    if (size < 1) throw new FormatError("#US entry is missing its special-character byte", { context: "#US" });
    const payload = reader.take(size);
    const textLength = payload.length - 1;
    if ((textLength & 1) !== 0 || payload[textLength] > 1) {
      throw new FormatError("Invalid UTF-16LE user-string encoding", { context: "#US" });
    }
    let result = "";
    for (let index = 0; index < textLength; index += 0x8000) {
      const end = Math.min(textLength, index + 0x8000);
      const units = [];
      for (let offset = index; offset < end; offset += 2) {
        units.push(payload[offset] | (payload[offset + 1] << 8));
      }
      result += String.fromCharCode(...units);
    }
    return result;
  }
}
