import { FormatError } from "../binary/errors.js";
import {
  codedIndexWidth,
  encodeCodedIndex,
  metadataTableNames,
  metadataTableSchemas,
  tableIndexWidth
} from "./tables.js";

function assertUnsigned(value, max, label) {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new FormatError(`${label} value ${value} does not fit its encoded width`);
  }
}

function appendU1(output, value) {
  assertUnsigned(value, 0xff, "u1");
  output.push(value);
}

function appendU2(output, value) {
  assertUnsigned(value, 0xffff, "u2");
  output.push(value & 0xff, value >>> 8);
}

function appendU4(output, value) {
  assertUnsigned(value, 0xffffffff, "u4");
  output.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function appendU8(output, value) {
  const number = BigInt(value);
  if (number < 0n || number > 0xffffffffffffffffn) throw new RangeError("u8 value is out of range");
  for (let index = 0; index < 8; index++) output.push(Number((number >> BigInt(index * 8)) & 0xffn));
}

function columnWidth(field, counts, heapSizes, present) {
  const [kind, value, , pointer] = field;
  if (kind === "u1") return 1;
  if (kind === "u2") return 2;
  if (kind === "u4") return 4;
  if (kind === "str") return (heapSizes & 1) !== 0 ? 4 : 2;
  if (kind === "guid") return (heapSizes & 2) !== 0 ? 4 : 2;
  if (kind === "blob") return (heapSizes & 4) !== 0 ? 4 : 2;
  if (kind === "table") {
    const table = pointer !== undefined && present.has(pointer) ? pointer : value;
    return tableIndexWidth(counts[table]);
  }
  return codedIndexWidth(value, counts);
}

function columnValue(row, field) {
  const [kind, value, name] = field;
  const column = row[name ?? value];
  if (kind === "table") return column?.rid ?? column ?? 0;
  if (kind === "coded") {
    const target = column?.target;
    return target ? encodeCodedIndex(target.table, target.rid, value) : 0;
  }
  return column ?? 0;
}

function writeRow(output, row, schema, counts, heapSizes, present) {
  for (const field of schema) {
    const [kind, value, name] = field;
    const encoded = columnValue(row, field);
    const width = columnWidth(field, counts, heapSizes, present);
    if (kind === "u1") appendU1(output, encoded);
    else if (kind === "u2") appendU2(output, encoded);
    else if (width === 2) appendU2(output, encoded);
    else appendU4(output, encoded);
  }
}

export function serializeTablesStream(tables, heapStreams) {
  const rows = new Map([...tables.rows].map(([id, tableRows]) => [id, [...tableRows]]));
  const valid = tables.valid;
  const present = new Set();
  const counts = tables.counts ? [...tables.counts] : Array(64).fill(0);
  for (let id = 0; id < 64; id++) {
    if ((valid & (1n << BigInt(id))) !== 0n || rows.has(id)) {
      if (!metadataTableSchemas[id]) throw new FormatError(`Cannot serialize unsupported metadata table ${id}`);
      present.add(id);
      counts[id] = rows.get(id)?.length ?? tables.counts[id] ?? 0;
    }
  }
  let heapSizes = 0;
  if ((heapStreams.get("#Strings")?.length ?? 0) >= 0x10000) heapSizes |= 1;
  if (Math.floor((heapStreams.get("#GUID")?.length ?? 0) / 16) >= 0x10000) heapSizes |= 2;
  if ((heapStreams.get("#Blob")?.length ?? 0) >= 0x10000) heapSizes |= 4;

  const output = [];
  appendU4(output, tables.reserved ?? 0);
  appendU1(output, tables.majorVersion);
  appendU1(output, tables.minorVersion);
  appendU1(output, heapSizes);
  appendU1(output, tables.reservedByte ?? 1);
  let validBits = 0n;
  for (const id of present) validBits |= 1n << BigInt(id);
  appendU8(output, validBits);
  appendU8(output, tables.sorted);
  for (const id of [...present].sort((a, b) => a - b)) appendU4(output, counts[id]);
  for (const id of [...present].sort((a, b) => a - b)) {
    const schema = metadataTableSchemas[id];
    for (const row of rows.get(id) ?? []) writeRow(output, row, schema, counts, heapSizes, present);
  }
  return Uint8Array.from(output);
}

export function appendCompressedUInt(value) {
  if (!Number.isInteger(value) || value < 0 || value >= 0x20000000) {
    throw new RangeError("Compressed unsigned integer is out of range");
  }
  if (value < 0x80) return Uint8Array.of(value);
  if (value < 0x4000) return Uint8Array.of(0x80 | (value >>> 8), value & 0xff);
  return Uint8Array.of(
    0xc0 | (value >>> 24),
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  );
}

export function appendCompressedInt(value) {
  if (!Number.isInteger(value) || value < -0x10000000 || value > 0x0fffffff) {
    throw new RangeError("Compressed signed integer is out of range");
  }
  const width = value >= -64 && value <= 63 ? 1 : value >= -0x2000 && value <= 0x1fff ? 2 : 4;
  const modulus = 2 ** (width === 1 ? 7 : width === 2 ? 14 : 29);
  const encoded = (((value * 2) % modulus) + modulus) % modulus + (value < 0 ? 1 : 0);
  if (width === 1) return Uint8Array.of(encoded);
  if (width === 2) return Uint8Array.of(0x80 | (encoded >>> 8), encoded & 0xff);
  return Uint8Array.of(
    0xc0 | Math.floor(encoded / 0x1000000),
    Math.floor(encoded / 0x10000) & 0xff,
    Math.floor(encoded / 0x100) & 0xff,
    encoded & 0xff
  );
}

export function appendStringHeap(heap, value) {
  if (typeof value !== "string" || value.includes("\0")) throw new TypeError("Metadata strings must be null-free strings");
  const source = heap.length === 0 ? Uint8Array.of(0) : heap;
  const encoded = new TextEncoder().encode(value);
  const output = new Uint8Array(source.length + encoded.length + 1);
  output.set(source);
  output.set(encoded, source.length);
  const index = source.length;
  return { heap: output, index };
}

export function appendBlobHeap(heap, value) {
  const payload = value instanceof Uint8Array ? value : new Uint8Array(value);
  const source = heap.length === 0 ? Uint8Array.of(0) : heap;
  const prefix = appendCompressedUInt(payload.length);
  const output = new Uint8Array(source.length + prefix.length + payload.length);
  output.set(source);
  output.set(prefix, source.length);
  output.set(payload, source.length + prefix.length);
  return { heap: output, index: source.length };
}

export function appendUserStringHeap(heap, value) {
  if (typeof value !== "string") throw new TypeError("User strings must be strings");
  const source = heap.length === 0 ? Uint8Array.of(0) : heap;
  if (source.length > 0x00ffffff) throw new RangeError("#US offset exceeds the user-string token range");
  const payloadLength = value.length * 2 + 1;
  const prefix = appendCompressedUInt(payloadLength);
  const output = new Uint8Array(source.length + prefix.length + payloadLength);
  output.set(source);
  output.set(prefix, source.length);
  let hasSpecialCharacter = false;
  let offset = source.length + prefix.length;
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    output[offset++] = codeUnit & 0xff;
    output[offset++] = codeUnit >>> 8;
    if ((codeUnit >= 0x0001 && codeUnit <= 0x0008) ||
        (codeUnit >= 0x000e && codeUnit <= 0x001f) ||
        codeUnit === 0x0027 || codeUnit === 0x002d ||
        codeUnit === 0x007f || codeUnit > 0x007e) {
      hasSpecialCharacter = true;
    }
  }
  output[offset] = hasSpecialCharacter ? 1 : 0;
  return { heap: output, index: source.length };
}

export function tableName(id) {
  return metadataTableNames[id] ?? `Table${id}`;
}
