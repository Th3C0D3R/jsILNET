import test from "node:test";
import assert from "node:assert/strict";
import { parseClassicPdb } from "../src/index.js";
import {
  parseCodeViewC13Subsections,
  parseCodeViewSymbolRecords,
  parsePdbStringTable
} from "../src/metadata/classic-pdb.js";

function makeClassicPdb() {
  const blockSize = 512;
  const bytes = new Uint8Array(blockSize * 6);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"));
  view.setUint32(32, blockSize, true);
  view.setUint32(36, 1, true);
  view.setUint32(40, 6, true);
  view.setUint32(44, 16, true);
  view.setUint32(48, 0, true);
  view.setUint32(52, 3, true);

  view.setUint32(blockSize * 3, 4, true);
  view.setUint32(blockSize * 4, 2, true);
  view.setUint32(blockSize * 4 + 4, 0xffffffff, true);
  view.setUint32(blockSize * 4 + 8, 52, true);
  view.setUint32(blockSize * 4 + 12, 5, true);

  const info = blockSize * 5;
  view.setUint32(info, 20000404, true);
  view.setUint32(info + 4, 0x12345678, true);
  view.setUint32(info + 8, 3, true);
  view.setUint32(info + 36, 8, true);
  bytes.set(Uint8Array.from([
    0x04, 0x03, 0x02, 0x01, 0x06, 0x05, 0x08, 0x07,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  ]), info + 12);
  return bytes;
}

test("classic PDB parser exposes MSF streams and information-stream identity", () => {
  const pdb = parseClassicPdb(makeClassicPdb());
  assert.equal(pdb.format, "MSF 7.0");
  assert.equal(pdb.blockSize, 512);
  assert.equal(pdb.info.version, 20000404);
  assert.equal(pdb.info.signature, 0x12345678);
  assert.equal(pdb.info.age, 3);
  assert.equal(pdb.info.guid, "01020304-0506-0708-090a-0b0c0d0e0f10");
  assert.deepEqual(pdb.info.namedStreams, new Map());
  assert.deepEqual(pdb.info.featureSignatures, []);
  assert.equal(pdb.streams[0].bytes, null);
  assert.equal(pdb.streams[1].bytes.length, 52);
});

test("classic PDB parser rejects invalid signatures and overlapping MSF blocks", () => {
  const invalidSignature = makeClassicPdb();
  invalidSignature[0] ^= 0xff;
  assert.throws(() => parseClassicPdb(invalidSignature), /invalid MSF 7.0 signature/);

  const overlapping = makeClassicPdb();
  new DataView(overlapping.buffer).setUint32(512 * 4 + 12, 4, true);
  assert.throws(() => parseClassicPdb(overlapping), /overlaps another MSF structure/);
});

test("classic PDB module symbols preserve bounded CodeView record payloads", () => {
  const bytes = Uint8Array.from([
    4, 0, 0, 0,
    4, 0, 0x77, 0x77, 0xaa, 0xbb,
    2, 0, 0x04, 0x11
  ]);
  assert.deepEqual(parseCodeViewSymbolRecords(bytes), {
    signature: 4,
    records: [
      { offset: 4, kind: 0x7777, data: Uint8Array.from([0xaa, 0xbb]) },
      { offset: 10, kind: 0x1104, data: new Uint8Array() }
    ]
  });
  assert.throws(() => parseCodeViewSymbolRecords(Uint8Array.from([4, 0, 0, 0, 1])),
    /length is truncated/);
  assert.throws(() => parseCodeViewSymbolRecords(Uint8Array.from([4, 0, 0, 0, 5, 0, 1, 2])),
    /exceeds its stream bounds/);
});

test("classic PDB symbol decoding exposes public, data, and procedure names", () => {
  const decodeRecord = (kind, data) => {
    const stream = new Uint8Array(8 + data.length);
    const streamView = new DataView(stream.buffer);
    streamView.setUint32(0, 4, true);
    streamView.setUint16(4, data.length + 2, true);
    streamView.setUint16(6, kind, true);
    stream.set(data, 8);
    return parseCodeViewSymbolRecords(stream).records[0].decoded;
  };
  const publicRecord = Uint8Array.from([
    4, 0, 0, 0,
    18, 0, 0x0e, 0x11,
    1, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 3, 0,
    0x70, 0x75, 0x62, 0, 0xf2, 0xf2
  ]);
  assert.deepEqual(parseCodeViewSymbolRecords(publicRecord).records[0].decoded, {
    kind: "public",
    flags: 1,
    offset: 0x11223344,
    segment: 3,
    name: "pub"
  });

  const data = new Uint8Array(4 + 2 + 2 + 10 + 4);
  const view = new DataView(data.buffer);
  view.setUint32(0, 4, true);
  view.setUint16(4, 16, true);
  view.setUint16(6, 0x110d, true);
  view.setUint32(8, 0x1000, true);
  view.setUint32(12, 0x40, true);
  view.setUint16(16, 2, true);
  data.set([0x67, 0x6c, 0x6f, 0], 18);
  assert.deepEqual(parseCodeViewSymbolRecords(data).records[0].decoded, {
    kind: "data",
    typeIndex: 0x1000,
    offset: 0x40,
    segment: 2,
    name: "glo"
  });
  assert.deepEqual(decodeRecord(0x1113, data.subarray(8)), {
    kind: "threadData",
    typeIndex: 0x1000,
    offset: 0x40,
    segment: 2,
    name: "glo"
  });
  const thunk = new Uint8Array(27);
  const thunkView = new DataView(thunk.buffer);
  thunkView.setUint32(0, 1, true);
  thunkView.setUint32(4, 2, true);
  thunkView.setUint32(8, 3, true);
  thunkView.setUint32(12, 0x40, true);
  thunkView.setUint16(16, 2, true);
  thunkView.setUint16(18, 5, true);
  thunk[20] = 4;
  thunk.set([0x74, 0x68, 0x75, 0x6e, 0x6b, 0], 21);
  assert.deepEqual(decodeRecord(0x1102, thunk), {
    kind: "thunk",
    parent: 1,
    end: 2,
    next: 3,
    offset: 0x40,
    segment: 2,
    length: 5,
    ordinal: 4,
    name: "thunk"
  });

  const procedure = new Uint8Array(4 + 2 + 2 + 35 + 5);
  const procedureView = new DataView(procedure.buffer);
  procedureView.setUint32(0, 4, true);
  procedureView.setUint16(4, 42, true);
  procedureView.setUint16(6, 0x1110, true);
  procedureView.setUint32(8, 12, true);
  procedureView.setUint32(12, 14, true);
  procedureView.setUint32(16, 16, true);
  procedureView.setUint32(20, 18, true);
  procedureView.setUint32(24, 2, true);
  procedureView.setUint32(28, 4, true);
  procedureView.setUint32(32, 0x1234, true);
  procedureView.setUint32(36, 0x2000, true);
  procedureView.setUint16(40, 1, true);
  procedure[42] = 2;
  procedure.set([0x6d, 0x65, 0x74, 0x68, 0], 43);
  assert.deepEqual(parseCodeViewSymbolRecords(procedure).records[0].decoded, {
    kind: "procedure",
    parent: 12,
    end: 14,
    next: 16,
    codeSize: 18,
    debugStart: 2,
    debugEnd: 4,
    typeIndex: 0x1234,
    offset: 0x2000,
    segment: 1,
    flags: 2,
    name: "meth"
  });

  const local = new Uint8Array(10);
  const localView = new DataView(local.buffer);
  localView.setUint32(0, 0x1002, true);
  localView.setUint16(4, 3, true);
  local.set([0x76, 0x61, 0x72, 0], 6);
  assert.deepEqual(decodeRecord(0x113e, local), {
    kind: "local",
    typeIndex: 0x1002,
    flags: 3,
    name: "var"
  });

  const bpRelative = new Uint8Array(14);
  const bpView = new DataView(bpRelative.buffer);
  bpView.setInt32(0, -12, true);
  bpView.setUint32(4, 0x1003, true);
  bpRelative.set([0x73, 0x74, 0x61, 0x63, 0x6b, 0], 8);
  assert.deepEqual(decodeRecord(0x110b, bpRelative), {
    kind: "bpRelative",
    offset: -12,
    typeIndex: 0x1003,
    name: "stack"
  });

  const registerRelative = new Uint8Array(14);
  const registerView = new DataView(registerRelative.buffer);
  registerView.setInt32(0, 4, true);
  registerView.setUint32(4, 0x1004, true);
  registerView.setUint16(8, 17, true);
  registerRelative.set([0x72, 0x65, 0x67, 0], 10);
  assert.deepEqual(decodeRecord(0x1111, registerRelative), {
    kind: "registerRelative",
    offset: 4,
    typeIndex: 0x1004,
    register: 17,
    name: "reg"
  });

  const constant = new Uint8Array(10);
  const constantView = new DataView(constant.buffer);
  constantView.setUint32(0, 0x1005, true);
  constantView.setUint16(4, 0x8001, true);
  constantView.setInt16(6, -9, true);
  constant.set([0x63, 0], 8);
  assert.deepEqual(decodeRecord(0x1107, constant), {
    kind: "constant",
    typeIndex: 0x1005,
    value: -9,
    name: "c"
  });
  assert.throws(() => decodeRecord(0x1107, constant.subarray(0, 7)),
    /numeric value is truncated/);
});

test("classic PDB C13 line subsections decode bounded line and column records", () => {
  const c13 = new Uint8Array(60);
  const view = new DataView(c13.buffer);
  view.setUint32(0, 0xf2, true);
  view.setUint32(4, 36, true);
  view.setUint32(8, 0x20, true);
  view.setUint16(12, 2, true);
  view.setUint16(14, 1, true);
  view.setUint32(16, 10, true);
  view.setUint32(20, 0, true);
  view.setUint32(24, 1, true);
  view.setUint32(28, 24, true);
  view.setUint32(32, 4, true);
  view.setUint32(36, 0x80000005, true);
  view.setUint16(40, 3, true);
  view.setUint16(42, 9, true);
  view.setUint32(44, 0xf4, true);
  view.setUint32(48, 8, true);
  view.setUint32(52, 1, true);
  c13[56] = 0;
  c13[57] = 0;

  const parsed = parseCodeViewC13Subsections(c13);
  assert.equal(parsed.subsections.length, 2);
  assert.deepEqual(parsed.lines[0], {
    relocationOffset: 0x20,
    segment: 2,
    flags: 1,
    codeSize: 10,
    blocks: [{
      fileChecksumOffset: 0,
      fileNameOffset: 1,
      fileName: null,
      checksumKind: 0,
      checksum: new Uint8Array(),
      lines: [{
        offset: 4,
        startLine: 5,
        endLineDelta: 0,
        isStatement: true,
        startColumn: 3,
        endColumn: 9
      }]
    }]
  });
  assert.throws(() => parseCodeViewC13Subsections(c13.subarray(0, 10)),
    /subsection exceeds its module stream/);
});

test("classic PDB string table resolves file names from checksum offsets", () => {
  const bytes = new Uint8Array(37);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xeffeeffe, true);
  view.setUint32(4, 1, true);
  view.setUint32(8, 9, true);
  bytes.set([0, 0x66, 0x6f, 0x6f, 0, 0x62, 0x61, 0x72, 0], 12);
  view.setUint32(21, 2, true);
  view.setUint32(25, 1, true);
  view.setUint32(29, 5, true);
  view.setUint32(33, 2, true);
  const strings = parsePdbStringTable(bytes);
  assert.equal(strings.strings.get(1), "foo");
  assert.equal(strings.strings.get(5), "bar");
  assert.deepEqual(strings.nameIds, [1, 5]);
  assert.throws(() => parsePdbStringTable(bytes.subarray(0, 20)),
    /string bytes exceed the stream bounds/);
});
