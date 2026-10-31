import test from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import {
  appendPortablePdbDocumentName,
  codedIndexWidth,
  decodeCodedIndex,
  encodeCodedIndex,
  encodePortablePdbDocumentName,
  encodePortablePdbSequencePoints,
  MetadataHeaps,
  parseMetadataRoot,
  parseTablesStream,
  tableIndexWidth
} from "../src/index.js";
import { parseEmbeddedPortablePdbData } from "../src/pe/headers.js";
import {
  decodePortablePdbCustomDebugInformation,
  decodePortablePdbDocumentName,
  decodePortablePdbSequencePoints,
  parsePortablePdbTables,
  validatePortablePdbAssemblyReferences,
  validatePortablePdbCodeViewIdentity
} from "../src/metadata/portable-pdb.js";
import { serializeTablesStream } from "../src/metadata/writer.js";
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
  assert.equal(new MetadataHeaps(new Map([
    ["#Strings", { bytes: Uint8Array.from([0, 0xef, 0xbb, 0xbf, 0]) }]
  ])).getString(1), "\ufeff");
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
  metadata[95] = 1;

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
  assert.equal(pdb.tables.counts[6], 3);

  const invalid = Uint8Array.from(container);
  invalid[0] = 0;
  assert.throws(() => parseEmbeddedPortablePdbData(invalid, 0, invalid.length), /MPDB header/);
  const truncated = Uint8Array.from(container);
  new DataView(truncated.buffer).setUint32(4, metadata.length + 1, true);
  assert.throws(() => parseEmbeddedPortablePdbData(truncated, 0, truncated.length),
    /decompressed size does not match/);

  const invalidMaskMetadata = Uint8Array.from(metadata);
  const invalidMaskView = new DataView(invalidMaskMetadata.buffer);
  invalidMaskView.setUint32(76, 0, true);
  invalidMaskView.setUint32(80, 1 << 13, true);
  const invalidMaskCompressed = deflateRawSync(invalidMaskMetadata);
  const invalidMaskContainer = new Uint8Array(8 + invalidMaskCompressed.length);
  invalidMaskContainer.set(Uint8Array.of(0x4d, 0x50, 0x44, 0x42));
  new DataView(invalidMaskContainer.buffer).setUint32(4, invalidMaskMetadata.length, true);
  invalidMaskContainer.set(invalidMaskCompressed, 8);
  assert.throws(() => parseEmbeddedPortablePdbData(
    invalidMaskContainer, 0, invalidMaskContainer.length
  ), /non-type-system metadata table/);
});

test("Portable PDB document names and sequence points round-trip bounded blobs", () => {
  const heaps = {
    getBlob(index) {
      return new Map([[1, new TextEncoder().encode("src")], [2, new TextEncoder().encode("a.cs")]]).get(index);
    }
  };
  const documentNameBlob = encodePortablePdbDocumentName("\\", [1, 2]);
  assert.deepEqual(documentNameBlob, Uint8Array.from([0x5c, 1, 2]));
  assert.equal(decodePortablePdbDocumentName(documentNameBlob, heaps), "src\\a.cs");
  assert.equal(
    decodePortablePdbDocumentName(encodePortablePdbDocumentName("🧭", [1, 2]), heaps),
    "src🧭a.cs"
  );
  assert.equal(
    decodePortablePdbDocumentName(encodePortablePdbDocumentName("\ufeff", [1, 2]), heaps),
    "src\ufeffa.cs"
  );
  assert.throws(() => encodePortablePdbDocumentName("::", [1, 2]), /separator/);
  assert.throws(() => encodePortablePdbDocumentName("\ud800", [1, 2]), /valid Unicode/);
  const appendedDocumentName = appendPortablePdbDocumentName(
    Uint8Array.of(0),
    "src\\\ufeffa.cs",
    "\\"
  );
  const appendedHeaps = new MetadataHeaps(new Map([
    ["#Blob", { bytes: appendedDocumentName.heap }]
  ]));
  assert.equal(
    decodePortablePdbDocumentName(
      appendedHeaps.getBlob(appendedDocumentName.nameBlobIndex),
      appendedHeaps
    ),
    "src\\\ufeffa.cs"
  );

  const decoded = decodePortablePdbSequencePoints(
    Uint8Array.from([0, 0, 0, 5, 10, 2, 4, 1, 4, 2, 0x7f, 0, 2, 3, 0, 0]),
    { documentRid: 1, documentCount: 2, localSignatureCount: 0 }
  );
  assert.equal(decoded.localSignatureRid, 0);
  assert.deepEqual(decoded.points, [
    { offset: 0, documentRid: 1, hidden: false, startLine: 10, startColumn: 2, endLine: 10, endColumn: 7 },
    { offset: 4, documentRid: 1, hidden: false, startLine: 11, startColumn: 1, endLine: 12, endColumn: 3 },
    { offset: 7, documentRid: 2, hidden: true, startLine: 0xfeefee, startColumn: 0, endLine: 0xfeefee, endColumn: 0 }
  ]);
  const sequencePointContext = { documentRid: 1, documentCount: 2, localSignatureCount: 0 };
  const encoded = encodePortablePdbSequencePoints(decoded, sequencePointContext);
  assert.deepEqual(
    decodePortablePdbSequencePoints(encoded, sequencePointContext),
    decoded
  );
  const nilDocumentPoints = {
    localSignatureRid: 0,
    points: [{
      offset: 0,
      documentRid: 2,
      hidden: true,
      startLine: 0xfeefee,
      startColumn: 0,
      endLine: 0xfeefee,
      endColumn: 0
    }]
  };
  const nilDocumentContext = { documentRid: 0, documentCount: 2, localSignatureCount: 0 };
  assert.deepEqual(
    decodePortablePdbSequencePoints(
      encodePortablePdbSequencePoints(nilDocumentPoints, nilDocumentContext),
      nilDocumentContext
    ),
    nilDocumentPoints
  );
  assert.throws(() => encodePortablePdbSequencePoints({
    localSignatureRid: 0,
    points: []
  }, nilDocumentContext), /require an initial document/);
  assert.throws(() => decodePortablePdbSequencePoints(
    Uint8Array.from([0, 0, 1, 0x7f, 1, 0]),
    { documentRid: 1, documentCount: 1, localSignatureCount: 0 }
  ), /sequence-point source spans/);
});

test("Portable PDB table serialization retains external row-index widths", () => {
  const counts = Array(64).fill(0);
  counts[6] = 0x10000;
  counts[50] = 1;
  const tables = {
    majorVersion: 2,
    minorVersion: 0,
    reserved: 0,
    reservedByte: 1,
    valid: 1n << 50n,
    sorted: 0n,
    counts,
    rows: new Map([[50, [{
      rid: 1,
      Method: { rid: 0x10000 },
      ImportScope: { rid: 0 },
      VariableList: { rid: 1 },
      ConstantList: { rid: 1 },
      StartOffset: 0,
      Length: 1
    }]]])
  };
  const streamBytes = serializeTablesStream(tables, new Map());
  const reparsed = parseTablesStream(
    { name: "#~", offset: 0, bytes: streamBytes },
    counts
  );
  assert.equal(reparsed.row(50, 1).Method.rid, 0x10000);
});

test("Portable PDB type-system counts and entry point match the assembly", () => {
  const pdb = {
    rowCounts: new Map([[2, 3], [6, 2]]),
    entryPointToken: 0x06000002
  };
  const assemblyCounts = Array(64).fill(0);
  assemblyCounts[2] = 3;
  assemblyCounts[6] = 2;
  assert.doesNotThrow(() => validatePortablePdbAssemblyReferences(pdb, assemblyCounts));
  const mismatchedCounts = assemblyCounts.slice();
  mismatchedCounts[2] = 4;
  assert.throws(() => validatePortablePdbAssemblyReferences(pdb, mismatchedCounts),
    /row count.*does not match assembly metadata/);
  assert.throws(() => validatePortablePdbAssemblyReferences(
    { ...pdb, entryPointToken: 0x06000003 },
    assemblyCounts
  ), /entry point references a missing MethodDef/);
});

test("embedded Portable PDB identity matches its RSDS CodeView record", () => {
  const id = Uint8Array.from([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
  ]);
  const codeView = { format: "RSDS", guid: "04030201-0605-0807-090a-0b0c0d0e0f10", age: 1 };
  assert.doesNotThrow(() => validatePortablePdbCodeViewIdentity({ id }, codeView));
  assert.throws(
    () => validatePortablePdbCodeViewIdentity({ id }, { ...codeView, guid: "00000000-0000-0000-0000-000000000000" }),
    /does not match its CodeView GUID/
  );
  assert.throws(
    () => validatePortablePdbCodeViewIdentity({ id }, { ...codeView, age: 2 }),
    /age must be one/
  );
});

test("Portable PDB rejects partially overlapping local scopes and import cycles", () => {
  const rows = new Map([
    [48, []],
    [49, []],
    [50, [
      { rid: 1, Method: { rid: 1 }, StartOffset: 0, Length: 10, VariableList: { rid: 1 }, ConstantList: { rid: 1 } },
      { rid: 2, Method: { rid: 1 }, StartOffset: 5, Length: 10, VariableList: { rid: 1 }, ConstantList: { rid: 1 } }
    ]],
    [51, []],
    [52, []],
    [53, []],
    [54, []],
    [55, []]
  ]);
  const tables = { get: (id) => rows.get(id) ?? [] };
  const heaps = {
    getBlob: () => new Uint8Array(),
    getGuid: () => null,
    getString: () => ""
  };
  assert.throws(() => parsePortablePdbTables(tables, heaps, new Array(64).fill(0)),
    /partially overlaps/);

  rows.set(50, []);
  rows.set(53, [{ Parent: { rid: 2 } }, { Parent: { rid: 1 } }]);
  assert.throws(() => parsePortablePdbTables(tables, heaps, new Array(64).fill(0)),
    /parent relationships contain a cycle/);
});

test("Portable PDB decodes embedded source and SourceLink custom debug data", () => {
  const source = Uint8Array.from([0x61, 0x62, 0x63]);
  const compressedSource = deflateRawSync(source);
  const embeddedSourceValue = new Uint8Array(4 + compressedSource.length);
  new DataView(embeddedSourceValue.buffer).setInt32(0, source.length, true);
  embeddedSourceValue.set(compressedSource, 4);
  const embeddedSource = decodePortablePdbCustomDebugInformation({
    Kind: 1,
    Value: 1,
    Parent: { target: { table: 48 } }
  }, {
    getGuid: () => Uint8Array.from([
      0x1b, 0x57, 0x8a, 0x0e, 0x26, 0x69, 0x6e, 0x46,
      0xb4, 0xad, 0x8a, 0xb0, 0x46, 0x11, 0xf5, 0xfe
    ]),
    getBlob: () => embeddedSourceValue
  });
  assert.deepEqual(embeddedSource.embeddedSource, source);

  const sourceLink = decodePortablePdbCustomDebugInformation({
    Kind: 1,
    Value: 1,
    Parent: { target: { table: 0 } }
  }, {
    getGuid: () => Uint8Array.from([
      0x56, 0x05, 0x11, 0xcc, 0x91, 0xa0, 0x38, 0x4d,
      0x9f, 0xec, 0x25, 0xab, 0x9a, 0x35, 0x1a, 0x6a
    ]),
    getBlob: () => new TextEncoder().encode("{\"documents\":{}}")
  });
  assert.deepEqual(sourceLink.sourceLink, { documents: {} });

  const sourceLinkData = (json) => decodePortablePdbCustomDebugInformation({
    Kind: 1,
    Value: 1,
    Parent: { target: { table: 0 } }
  }, {
    getGuid: () => Uint8Array.from([
      0x56, 0x05, 0x11, 0xcc, 0x91, 0xa0, 0x38, 0x4d,
      0x9f, 0xec, 0x25, 0xab, 0x9a, 0x35, 0x1a, 0x6a
    ]),
    getBlob: () => new TextEncoder().encode(json)
  });
  assert.throws(() => sourceLinkData("{\"documents\":null}"),
    /documents value must be a JSON object/);
  assert.throws(() => sourceLinkData("{\"documents\":{\"src/*\":1}}"),
    /mappings must be strings/);

  assert.throws(() => decodePortablePdbCustomDebugInformation({
    Kind: 1,
    Value: 1,
    Parent: { target: { table: 48 } }
  }, {
    getGuid: () => Uint8Array.from([
      0x1b, 0x57, 0x8a, 0x0e, 0x26, 0x69, 0x6e, 0x46,
      0xb4, 0xad, 0x8a, 0xb0, 0x46, 0x11, 0xf5, 0xfe
    ]),
    getBlob: () => Uint8Array.of(0xff, 0xff, 0xff, 0xff)
  }), /reserved content format/);
});
