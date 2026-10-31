import { FormatError } from "../binary/errors.js";

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function streamNameBytes(name) {
  const bytes = new TextEncoder().encode(name);
  if (bytes.length > 31 || bytes.includes(0)) throw new FormatError(`Invalid metadata stream name ${name}`);
  return bytes;
}

export function serializeMetadataRoot(root, streams) {
  const entries = [...streams].map(([name, bytes]) => ({
    name,
    nameBytes: streamNameBytes(name),
    bytes: bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
    offset: 0
  }));
  const versionBytes = root.versionBytes ?? new TextEncoder().encode(`${root.version}\0`);
  if (entries.length > 0xffff) throw new RangeError("Metadata stream count exceeds the format limit");
  let headerSize = 4 + 2 + 2 + 4 + 4 + versionBytes.length;
  headerSize = align(headerSize, 4) + 2 + 2;
  for (const entry of entries) headerSize += 8 + align(entry.nameBytes.length + 1, 4);
  let cursor = align(headerSize, 4);
  for (const entry of entries) {
    entry.offset = cursor;
    cursor = align(cursor + entry.bytes.length, 4);
  }
  if (cursor > 0xffffffff) throw new RangeError("Metadata root exceeds the CLI size limit");

  const output = new Uint8Array(cursor);
  const view = new DataView(output.buffer);
  let position = 0;
  view.setUint32(position, 0x424a5342, true); position += 4;
  view.setUint16(position, root.majorVersion, true); position += 2;
  view.setUint16(position, root.minorVersion, true); position += 2;
  view.setUint32(position, 0, true); position += 4;
  view.setUint32(position, versionBytes.length, true); position += 4;
  output.set(versionBytes, position); position += versionBytes.length;
  position = align(position, 4);
  view.setUint16(position, root.flags, true); position += 2;
  view.setUint16(position, entries.length, true); position += 2;
  for (const entry of entries) {
    view.setUint32(position, entry.offset, true); position += 4;
    view.setUint32(position, entry.bytes.length, true); position += 4;
    output.set(entry.nameBytes, position); position += entry.nameBytes.length;
    output[position++] = 0;
    position = align(position, 4);
  }
  if (position !== headerSize) throw new FormatError("Metadata stream directory size calculation failed");
  for (const entry of entries) output.set(entry.bytes, entry.offset);
  return output;
}
