import test from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import {
  codedIndexWidth,
  decodeCodedIndex,
  encodeCodedIndex,
  MetadataHeaps,
  parseMetadataRoot,
  parseTablesStream,
  tableIndexWidth
} from "../src/index.js";
import { parseEmbeddedPortablePdbData } from "../src/pe/headers.js";
import { resolveMethodParameters, resolveTypes } from "../src/resolution/module.js";

function makeMetadataRoot({
  streamName = Uint8Array.from([0x23, 0x7e]),
  streamOffset = 36,
  streamSize = 1,
  versionBytes = Uint8Array.from([0x76, 0x31, 0]),
  reserved = 0
} = {}) {
  const alignedVersionEnd = (16 + versionBytes.length + 3) & ~3;
  const streamHeader = alignedVersionEnd + 4;
  const headerSize = streamHeader + 8 + ((streamName.length + 1 + 3) & ~3);
  const size = Math.max(headerSize, streamOffset + streamSize);
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x424a5342, true);
  view.setUint16(4, 1, true);
  view.setUint16(6, 1, true);
  view.setUint32(8, reserved, true);
  view.setUint32(12, versionBytes.length, true);
  bytes.set(versionBytes, 16);
  view.setUint16(alignedVersionEnd, 0, true);
  view.setUint16(alignedVersionEnd + 2, 1, true);
  view.setUint32(streamHeader, streamOffset, true);
  view.setUint32(streamHeader + 4, streamSize, true);
  bytes.set(streamName, streamHeader + 8);
  return { bytes, headerSize };
}

test("coded-index width changes at the tag-adjusted row-count boundary", () => {
  const definitions = {
    TypeDefOrRef: 2, HasConstant: 2, HasCustomAttribute: 5, HasFieldMarshal: 1,
    HasDeclSecurity: 2, MemberRefParent: 3, HasSemantics: 1, MethodDefOrRef: 1,
    MemberForwarded: 1, Implementation: 2, CustomAttributeType: 3, ResolutionScope: 2,
    TypeOrMethodDef: 1
  };
  for (const [kind, bits] of Object.entries(definitions)) {
    const threshold = 2 ** (16 - bits);
    const counts = Array(64).fill(threshold - 1);
    assert.equal(codedIndexWidth(kind, counts), 2, `${kind} below threshold`);
    counts.fill(threshold);
    assert.equal(codedIndexWidth(kind, counts), 4, `${kind} at threshold`);
  }
});

test("coded-index encode/decode preserves table and row identity", () => {
  const raw = encodeCodedIndex(6, 17, "MemberRefParent");
  assert.deepEqual(decodeCodedIndex(raw, "MemberRefParent"), {
    table: 6,
    tableName: "MethodDef",
    rid: 17
  });
  assert.equal(encodeCodedIndex(2, 0, "TypeDefOrRef"), 0);
  assert.throws(() => decodeCodedIndex(1, "MemberRefParent"), /zero row ID/);
  const large = encodeCodedIndex(27, 0x1fffffff, "MemberRefParent");
  assert.equal(decodeCodedIndex(large, "MemberRefParent").rid, 0x1fffffff);
});

test("simple table indexes use 2 bytes through 65,535 rows and 4 bytes after", () => {
  assert.equal(tableIndexWidth(0), 2);
  assert.equal(tableIndexWidth(65535), 2);
  assert.equal(tableIndexWidth(65536), 4);
});

test("table row counts are bounded by available stream data", () => {
  const bytes = new Uint8Array(28);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(8, 1n << 6n, true);
  view.setUint32(24, 1, true);
  bytes[7] = 1;
  assert.throws(() => parseTablesStream({ bytes, offset: 0, name: "#~" }), /row count exceeds/);
});

test("metadata tables reject reserved heap-size flag bits", () => {
  const bytes = new Uint8Array(24);
  bytes[6] = 0x80;
  bytes[7] = 1;
  assert.throws(() => parseTablesStream({ bytes, offset: 0, name: "#~" }), /reserved bits/);
});

test("metadata list indexes must be one-based and ordered", () => {
  function makeTypeDefStream(fieldStarts) {
    const bytes = new Uint8Array(32 + fieldStarts.length * 14 + 6);
    const view = new DataView(bytes.buffer);
    bytes[7] = 1;
    view.setBigUint64(8, (1n << 2n) | (1n << 4n), true);
    view.setUint32(24, fieldStarts.length, true);
    view.setUint32(28, 1, true);
    fieldStarts.forEach((fieldStart, index) => {
      const rowOffset = 32 + index * 14;
      view.setUint16(rowOffset + 10, fieldStart, true);
      view.setUint16(rowOffset + 12, 1, true);
    });
    return { bytes, offset: 0, name: "#~" };
  }

  assert.throws(() => parseTablesStream(makeTypeDefStream([0, 1])), /one-based list position/);
  assert.throws(() => parseTablesStream(makeTypeDefStream([2, 1])), /indexes are not ordered/);
  assert.equal(parseTablesStream(makeTypeDefStream([1, 2])).get("TypeDef").length, 2);
});

test("declared sorted metadata tables and generic parameter flags are validated", () => {
  function makeTypeRefStream(scopes) {
    const bytes = new Uint8Array(24 + 8 + 10 + scopes.length * 6);
    const view = new DataView(bytes.buffer);
    bytes[7] = 1;
    view.setBigUint64(8, (1n << 0n) | (1n << 1n), true);
    view.setBigUint64(16, 1n << 1n, true);
    view.setUint32(24, 1, true);
    view.setUint32(28, scopes.length, true);
    scopes.forEach((scope, index) => view.setUint16(42 + index * 6, scope, true));
    return { bytes, offset: 0, name: "#~" };
  }
  assert.throws(() => parseTablesStream(makeTypeRefStream([4, 0])), /TypeRef rows are not ordered/);
  assert.equal(parseTablesStream(makeTypeRefStream([0, 4])).get("TypeRef").length, 2);

  const bytes = new Uint8Array(54);
  const view = new DataView(bytes.buffer);
  bytes[7] = 1;
  view.setBigUint64(8, (1n << 2n) | (1n << 42n), true);
  view.setUint32(24, 1, true);
  view.setUint32(28, 1, true);
  view.setUint16(42, 1, true);
  view.setUint16(44, 1, true);
  view.setUint16(46, 0, true);
  view.setUint16(48, 0x20, true);
  view.setUint16(50, 2, true);
  assert.throws(() => parseTablesStream({ bytes, offset: 0, name: "#~" }), /GenericParam row 1 contains invalid flags/);
});

test("declared sorted EventMap and PropertyMap tables validate owner ordering", () => {
  function makeOwnerMapStream(mapTableId, targetTableId, ownerRids = [2, 1]) {
    const typeDefOffset = 36;
    const mapOffset = typeDefOffset + 2 * 14;
    const targetOffset = mapOffset + 2 * 4;
    const bytes = new Uint8Array(targetOffset + 2 * 6);
    const view = new DataView(bytes.buffer);
    bytes[7] = 1;
    const valid = (1n << 2n) | (1n << BigInt(mapTableId)) | (1n << BigInt(targetTableId));
    view.setBigUint64(8, valid, true);
    view.setBigUint64(16, 1n << BigInt(mapTableId), true);
    view.setUint32(24, 2, true);
    view.setUint32(28, 2, true);
    view.setUint32(32, 2, true);
    for (let index = 0; index < 2; index++) {
      const offset = typeDefOffset + index * 14;
      view.setUint16(offset + 10, 1, true);
      view.setUint16(offset + 12, 1, true);
      view.setUint16(mapOffset + index * 4, ownerRids[index], true);
      view.setUint16(mapOffset + index * 4 + 2, index + 1, true);
    }
    return { bytes, offset: 0, name: "#~" };
  }

  assert.throws(() => parseTablesStream(makeOwnerMapStream(18, 20)),
    /EventMap rows are not ordered by their sorted key/);
  assert.throws(() => parseTablesStream(makeOwnerMapStream(21, 23)),
    /PropertyMap rows are not ordered by their sorted key/);
  assert.throws(() => parseTablesStream(makeOwnerMapStream(18, 20, [1, 1])),
    /EventMap rows contain a duplicate key/);
  assert.throws(() => parseTablesStream(makeOwnerMapStream(21, 23, [1, 1])),
    /PropertyMap rows contain a duplicate key/);
});

test("metadata tables reject invalid reserved header values", () => {
  const bytes = new Uint8Array(24);
  bytes[7] = 1;
  assert.equal(parseTablesStream({ bytes, offset: 0, name: "#~" }).counts.length, 64);
  new DataView(bytes.buffer).setUint32(0, 1, true);
  assert.throws(() => parseTablesStream({ bytes, offset: 0, name: "#~" }), /invalid reserved fields/);
  new DataView(bytes.buffer).setUint32(0, 0, true);
  bytes[7] = 0;
  assert.throws(() => parseTablesStream({ bytes, offset: 0, name: "#~" }),
    /invalid reserved fields/);
});

test("#- pointer tables resolve TypeDef field and method lists through indirection", () => {
  const rows = new Map([
    [2, [
      {
        rid: 1, Flags: 0, TypeName: 1, TypeNamespace: 0, Extends: { target: null },
        FieldList: { table: 3, rid: 1 }, MethodList: { table: 5, rid: 1 }
      },
      {
        rid: 2, Flags: 0, TypeName: 2, TypeNamespace: 0, Extends: { target: null },
        FieldList: { table: 3, rid: 3 }, MethodList: { table: 5, rid: 3 }
      }
    ]],
    [3, [
      { rid: 1, Field: { rid: 2 } },
      { rid: 2, Field: { rid: 1 } }
    ]],
    [5, [
      { rid: 1, Method: { rid: 2 } },
      { rid: 2, Method: { rid: 1 } }
    ]],
    [6, [
      { rid: 1, ParamList: { table: 7, rid: 1 } },
      { rid: 2, ParamList: { table: 7, rid: 3 } }
    ]],
    [7, [
      { rid: 1, Param: { rid: 2 } },
      { rid: 2, Param: { rid: 1 } }
    ]],
    [18, [
      { rid: 1, Parent: { rid: 1 }, EventList: { table: 19, rid: 1 } },
      { rid: 2, Parent: { rid: 2 }, EventList: { table: 19, rid: 3 } }
    ]],
    [19, [
      { rid: 1, Event: { rid: 2 } },
      { rid: 2, Event: { rid: 1 } }
    ]],
    [21, [
      { rid: 1, Parent: { rid: 1 }, PropertyList: { table: 22, rid: 1 } },
      { rid: 2, Parent: { rid: 2 }, PropertyList: { table: 22, rid: 3 } }
    ]],
    [22, [
      { rid: 1, Property: { rid: 2 } },
      { rid: 2, Property: { rid: 1 } }
    ]]
  ]);
  const counts = Array(64).fill(0);
  counts[2] = 2;
  counts[3] = 2;
  counts[4] = 2;
  counts[5] = 2;
  counts[6] = 2;
  counts[7] = 2;
  counts[8] = 2;
  counts[18] = 2;
  counts[19] = 2;
  counts[20] = 2;
  counts[21] = 2;
  counts[22] = 2;
  counts[23] = 2;
  const metadata = {
    counts,
    get(name) {
      const id = typeof name === "number" ? name : {
        TypeDef: 2, FieldPtr: 3, MethodPtr: 5, MethodDef: 6, ParamPtr: 7,
        EventMap: 18, EventPtr: 19, PropertyMap: 21, PropertyPtr: 22
      }[name];
      return rows.get(id) ?? [];
    }
  };
  const types = resolveTypes(metadata, {
    getString(index) {
      return index === 1 ? "First" : "Second";
    }
  });
  assert.deepEqual(types.map((type) => type.fieldRids), [[2, 1], []]);
  assert.deepEqual(types.map((type) => type.methodRids), [[2, 1], []]);
  assert.deepEqual(types.map((type) => type.eventRids), [[2, 1], []]);
  assert.deepEqual(types.map((type) => type.propertyRids), [[2, 1], []]);
  assert.deepEqual(resolveMethodParameters(metadata), [[2, 1], []]);

  rows.get(21).push({ ...rows.get(21)[0], rid: 3 });
  assert.throws(() => resolveTypes(metadata, {
    getString(index) {
      return index === 1 ? "First" : "Second";
    }
  }), /multiple PropertyMap rows/);
});

test("metadata heap readers resolve strings, blobs, GUIDs and user strings", () => {
  const heaps = new MetadataHeaps(new Map([
    ["#Strings", { bytes: Uint8Array.from([0, 0x6f, 0x6b, 0]) }],
    ["#Blob", { bytes: Uint8Array.from([0, 2, 0xaa, 0xbb]) }],
    ["#GUID", { bytes: Uint8Array.from({ length: 16 }, (_, index) => index) }],
    ["#US", { bytes: Uint8Array.from([0, 5, 0x68, 0, 0x69, 0, 0]) }]
  ]));
  assert.equal(heaps.getString(1), "ok");
  assert.deepEqual([...heaps.getBlob(1)], [0xaa, 0xbb]);
  assert.deepEqual([...heaps.getGuid(1)], Array.from({ length: 16 }, (_, index) => index));
  assert.equal(heaps.getUserString(0x70000001), "hi");
  assert.equal(new MetadataHeaps(new Map([
    ["#US", { bytes: Uint8Array.from([0, 3, 0x00, 0xd8, 0]) }]
  ])).getUserString(1), "\ud800");
});

test("metadata heap readers validate required zero entries and GUID width", () => {
  for (const name of ["#Strings", "#US", "#Blob"]) {
    assert.throws(() => new MetadataHeaps(new Map([
      [name, { bytes: Uint8Array.from([1]) }]
    ])), /missing its zero entry/);
  }
  assert.throws(() => new MetadataHeaps(new Map([
    ["#GUID", { bytes: Uint8Array.from([0]) }]
  ])), /multiple of 16 bytes/);
});

test("metadata heap readers reject malformed unreferenced entries", () => {
  assert.throws(() => new MetadataHeaps(new Map([
    ["#Strings", { bytes: Uint8Array.from([0, 0xc0, 0xaf, 0]) }]
  ])), /Invalid UTF-8/);
  assert.throws(() => new MetadataHeaps(new Map([
    ["#Strings", { bytes: Uint8Array.from([0, 0x61]) }]
  ])), /Unterminated string heap entry/);
  assert.throws(() => new MetadataHeaps(new Map([
    ["#Blob", { bytes: Uint8Array.from([0, 2, 0xaa]) }]
  ])), /exceeds the available/);
  assert.throws(() => new MetadataHeaps(new Map([
    ["#Blob", { bytes: Uint8Array.from([0, 0x80, 0x01, 0xaa]) }]
  ])), /Noncanonical length prefix/);
  assert.throws(() => new MetadataHeaps(new Map([
    ["#US", { bytes: Uint8Array.from([0, 1, 2]) }]
  ])), /Invalid UTF-16LE user-string encoding/);
});

test("metadata roots reject malformed version and stream directory data", () => {
  const valid = makeMetadataRoot();
  assert.equal(parseMetadataRoot(valid.bytes, 0, valid.bytes.length).streams.has("#~"), true);

  const unaligned = makeMetadataRoot({ streamOffset: 37 });
  assert.throws(() => parseMetadataRoot(unaligned.bytes, 0, unaligned.bytes.length), /not four-byte aligned/);

  const overlapsHeader = makeMetadataRoot({ streamOffset: 32, streamSize: 0 });
  assert.throws(() => parseMetadataRoot(overlapsHeader.bytes, 0, overlapsHeader.bytes.length),
    /overlaps the stream directory/);

  const nonAsciiName = makeMetadataRoot({ streamName: Uint8Array.from([0x23, 0xff]) });
  assert.throws(() => parseMetadataRoot(nonAsciiName.bytes, 0, nonAsciiName.bytes.length), /non-ASCII/);

  const unterminatedVersion = makeMetadataRoot({ versionBytes: Uint8Array.from([0x76, 0x31]) });
  assert.throws(() => parseMetadataRoot(unterminatedVersion.bytes, 0, unterminatedVersion.bytes.length),
    /not null-terminated/);

  const trailingVersionData = makeMetadataRoot({
    versionBytes: Uint8Array.from([0x76, 0x31, 0, 0x78, 0])
  });
  assert.throws(() => parseMetadataRoot(trailingVersionData.bytes, 0, trailingVersionData.bytes.length),
    /not null-terminated/);

  const nonzeroReserved = makeMetadataRoot({ reserved: 1 });
  assert.throws(() => parseMetadataRoot(nonzeroReserved.bytes, 0, nonzeroReserved.bytes.length),
    /reserved field must be zero/);
});

test("embedded Portable PDB data validates and exposes its metadata streams", () => {
  const metadata = new Uint8Array(112);
  const view = new DataView(metadata.buffer);
  view.setUint32(0, 0x424a5342, true);
  view.setUint16(4, 1, true);
  view.setUint16(6, 1, true);
  view.setUint32(12, 4, true);
  metadata.set(Uint8Array.of(0x50, 0x44, 0x42, 0), 16);
  view.setUint16(22, 2, true);
  view.setUint32(24, 52, true);
  view.setUint32(28, 36, true);
  metadata.set(Uint8Array.of(0x23, 0x50, 0x64, 0x62, 0), 32);
  view.setUint32(40, 88, true);
  view.setUint32(44, 24, true);
  metadata.set(Uint8Array.of(0x23, 0x7e, 0), 48);
  metadata.set(Uint8Array.from({ length: 20 }, (_, index) => index), 52);
  view.setUint32(72, 0x06000001, true);
  view.setUint32(76, 1 << 6, true);
  view.setUint32(84, 3, true);

  const compressed = deflateRawSync(metadata);
  const container = new Uint8Array(8 + compressed.length);
  container.set(Uint8Array.of(0x4d, 0x50, 0x44, 0x42));
  new DataView(container.buffer).setUint32(4, metadata.length, true);
  container.set(compressed, 8);

  const pdb = parseEmbeddedPortablePdbData(container, 0, container.length);
  assert.equal(pdb.uncompressedSize, metadata.length);
  assert.deepEqual(pdb.id, Uint8Array.from({ length: 20 }, (_, index) => index));
  assert.equal(pdb.entryPointToken, 0x06000001);
  assert.equal(pdb.referencedTypeSystemTables, 1n << 6n);
  assert.equal(pdb.metadataRoot.streams.has("#Pdb"), true);
  assert.equal(pdb.metadataRoot.streams.has("#~"), true);
  assert.deepEqual(pdb.rowCounts, new Map([[6, 3]]));

  const invalid = Uint8Array.from(container);
  invalid[0] = 0;
  assert.throws(() => parseEmbeddedPortablePdbData(invalid, 0, invalid.length), /MPDB header/);

  const truncated = Uint8Array.from(container);
  new DataView(truncated.buffer).setUint32(4, metadata.length + 1, true);
  assert.throws(() => parseEmbeddedPortablePdbData(truncated, 0, truncated.length),
    /decompressed size does not match/);
});
