import test from "node:test";
import assert from "node:assert/strict";
import {
  parseClassicPdb,
  insertClassicPdbFileChecksum,
  removeClassicPdbFileChecksum,
  replaceClassicPdbFileChecksum,
  insertClassicPdbLineBlock,
  removeClassicPdbLineBlock,
  replaceClassicPdbLineBlock,
  replaceClassicPdbLineInfo,
  replaceClassicPdbModuleNames,
  replaceClassicPdbStringTableName,
  replaceClassicPdbSymbolName,
  removeClassicPdbSymbol,
  insertClassicPdbConstantSymbol,
  insertClassicPdbPublicSymbol,
  insertClassicPdbDataSymbol
} from "../src/index.js";
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

function makeC13LineBytes({ twoChecksums = false, hasColumns = true } = {}) {
  const blockCount = twoChecksums ? 2 : 1;
  const blockSize = hasColumns ? 24 : 20;
  const lineDataLength = 12 + blockCount * blockSize;
  const checksumDataLength = blockCount * 24;
  const checksumSubsectionOffset = 8 + lineDataLength;
  const c13 = new Uint8Array(checksumSubsectionOffset + 8 + checksumDataLength);
  const view = new DataView(c13.buffer);
  view.setUint32(0, 0xf2, true);
  view.setUint32(4, lineDataLength, true);
  view.setUint32(8, 0x20, true);
  view.setUint16(12, 2, true);
  view.setUint16(14, hasColumns ? 1 : 0, true);
  view.setUint32(16, 10, true);
  for (let index = 0; index < blockCount; index++) {
    const blockOffset = 20 + index * blockSize;
    view.setUint32(blockOffset, index * 24, true);
    view.setUint32(blockOffset + 4, 1, true);
    view.setUint32(blockOffset + 8, blockSize, true);
    view.setUint32(blockOffset + 12, 4 + index, true);
    view.setUint32(blockOffset + 16, 0x80000005, true);
    if (hasColumns) {
      view.setUint16(blockOffset + 20, 3, true);
      view.setUint16(blockOffset + 22, 9, true);
    }
  }
  view.setUint32(checksumSubsectionOffset, 0xf4, true);
  view.setUint32(checksumSubsectionOffset + 4, checksumDataLength, true);
  for (let index = 0; index < blockCount; index++) {
    const checksumOffset = checksumSubsectionOffset + 8 + index * 24;
    view.setUint32(checksumOffset, 1, true);
    view.setUint8(checksumOffset + 4, 16);
    view.setUint8(checksumOffset + 5, 1);
    for (let byte = 0; byte < 16; byte++) {
      view.setUint8(checksumOffset + 6 + byte, 0x10 + index + byte);
    }
  }
  return c13;
}

function makeClassicPdbWithSymbols({
  crossBlockName = false,
  knownPrefix = false,
  withSymbols = true,
  withC13 = false,
  lineInfo = false,
  twoChecksums = false,
  lineColumns = true,
  trailingModuleBytes = new Uint8Array()
} = {}) {
  const blockSize = 512;
  const symbolBytes = crossBlockName ? 516 : withSymbols ? 24 : 0;
  const c13Bytes = lineInfo
    ? makeC13LineBytes({ twoChecksums, hasColumns: lineColumns })
    : withC13
      ? Uint8Array.from([0x77, 0x77, 0x77, 0x77, 3, 0, 0, 0, 1, 2, 3, 0])
      : new Uint8Array();
  const symbolStream = new Uint8Array(
    symbolBytes + c13Bytes.length + trailingModuleBytes.length
  );
  const symbolView = new DataView(symbolStream.buffer);
  const symbolRecordOffset = crossBlockName ? 496 : 4;
  const bytes = new Uint8Array(blockSize * (crossBlockName ? 9 : 8));
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"));
  view.setUint32(32, blockSize, true);
  view.setUint32(36, 1, true);
  view.setUint32(40, bytes.length / blockSize, true);
  view.setUint32(44, crossBlockName ? 40 : 36, true);
  view.setUint32(48, 0, true);
  view.setUint32(52, 3, true);

  const directoryOffset = blockSize * 4;
  view.setUint32(blockSize * 3, 4, true);
  view.setUint32(directoryOffset, 5, true);
  view.setUint32(directoryOffset + 4, 0xffffffff, true);
  view.setUint32(directoryOffset + 8, 52, true);
  view.setUint32(directoryOffset + 12, 0xffffffff, true);
  view.setUint32(directoryOffset + 16, 144, true);
  view.setUint32(directoryOffset + 20, symbolStream.length, true);
  view.setUint32(directoryOffset + 24, 5, true);
  view.setUint32(directoryOffset + 28, 6, true);
  view.setUint32(directoryOffset + 32, 7, true);
  if (crossBlockName) view.setUint32(directoryOffset + 36, 8, true);

  const infoOffset = blockSize * 5;
  view.setUint32(infoOffset, 20000404, true);
  view.setUint32(infoOffset + 4, 0x12345678, true);
  view.setUint32(infoOffset + 8, 3, true);
  view.setUint32(infoOffset + 36, 8, true);
  bytes.set(Uint8Array.from([
    0x04, 0x03, 0x02, 0x01, 0x06, 0x05, 0x08, 0x07,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  ]), infoOffset + 12);

  const dbiOffset = blockSize * 6;
  view.setInt32(dbiOffset, -1, true);
  view.setUint32(dbiOffset + 4, 19990903, true);
  view.setUint32(dbiOffset + 8, 3, true);
  view.setUint16(dbiOffset + 12, 0xffff, true);
  view.setUint16(dbiOffset + 16, 0xffff, true);
  view.setUint16(dbiOffset + 20, 0xffff, true);
  view.setUint32(dbiOffset + 24, 80, true);
  view.setUint16(dbiOffset + 64 + 34, 4, true);
  view.setUint32(dbiOffset + 64 + 36, symbolBytes, true);
  view.setUint32(dbiOffset + 64 + 44, c13Bytes.length, true);
  bytes.set([0x74, 0x65, 0x73, 0x74, 0], dbiOffset + 64 + 64);
  bytes.set([0x74, 0x65, 0x73, 0x74, 0x2e, 0x6f, 0x62, 0x6a, 0],
    dbiOffset + 64 + 69);

  symbolStream.set(c13Bytes, symbolBytes);
  symbolStream.set(trailingModuleBytes, symbolBytes + c13Bytes.length);
  if (withSymbols) {
    symbolView.setUint32(0, 4, true);
    if (crossBlockName) {
      symbolView.setUint16(4, 490, true);
      symbolView.setUint16(6, knownPrefix ? 0x110e : 0x7777, true);
      if (knownPrefix) {
        symbolView.setUint32(8, 1, true);
        symbolView.setUint32(12, 0x20, true);
        symbolView.setUint16(16, 1, true);
        symbolStream.fill(0x61, 18, 495);
      } else {
        symbolStream.fill(0xaa, 8, symbolRecordOffset);
      }
    }
    symbolView.setUint16(symbolRecordOffset, 18, true);
    symbolView.setUint16(symbolRecordOffset + 2, 0x110e, true);
    symbolView.setUint32(symbolRecordOffset + 4, 1, true);
    symbolView.setUint32(symbolRecordOffset + 8, 0x20, true);
    symbolView.setUint16(symbolRecordOffset + 12, 1, true);
    symbolStream.set([0x70, 0x75, 0x62, 0, 0xf2, 0xf1], symbolRecordOffset + 14);
  }
  bytes.set(symbolStream.subarray(0, blockSize), blockSize * 7);
  if (crossBlockName) bytes.set(symbolStream.subarray(blockSize), blockSize * 8);
  return bytes;
}

function makeClassicPdbWithNames() {
  const blockSize = 512;
  const bytes = new Uint8Array(blockSize * 7);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"));
  view.setUint32(32, blockSize, true);
  view.setUint32(36, 1, true);
  view.setUint32(40, 7, true);
  view.setUint32(44, 24, true);
  view.setUint32(52, 3, true);
  view.setUint32(blockSize * 3, 4, true);

  const directoryOffset = blockSize * 4;
  view.setUint32(directoryOffset, 3, true);
  view.setUint32(directoryOffset + 4, 0xffffffff, true);
  view.setUint32(directoryOffset + 8, 72, true);
  view.setUint32(directoryOffset + 12, 37, true);
  view.setUint32(directoryOffset + 16, 5, true);
  view.setUint32(directoryOffset + 20, 6, true);

  const infoOffset = blockSize * 5;
  view.setUint32(infoOffset, 20000404, true);
  view.setUint32(infoOffset + 4, 0x12345678, true);
  view.setUint32(infoOffset + 8, 3, true);
  view.setUint32(infoOffset + 28, 8, true);
  bytes.set([0, 0x2f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0], infoOffset + 32);
  view.setUint32(infoOffset + 40, 1, true);
  view.setUint32(infoOffset + 44, 1, true);
  view.setUint32(infoOffset + 48, 1, true);
  view.setUint32(infoOffset + 52, 1, true);
  view.setUint32(infoOffset + 56, 0, true);
  view.setUint32(infoOffset + 60, 1, true);
  view.setUint32(infoOffset + 64, 2, true);
  view.setUint32(infoOffset + 68, 0, true);
  bytes.set([
    0xfe, 0xef, 0xfe, 0xef, 1, 0, 0, 0, 9, 0, 0, 0,
    0, 0x66, 0x6f, 0x6f, 0, 0x62, 0x61, 0x72, 0,
    2, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0
  ], blockSize * 6);
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

test("classic PDB module names can be replaced with DBI stream rebuilding", () => {
  const original = makeClassicPdbWithSymbols({ withC13: true });
  const originalPdb = parseClassicPdb(original);
  const rewritten = replaceClassicPdbModuleNames(original, {
    moduleIndex: 0,
    moduleName: "renamed-module"
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  assert.equal(rewrittenPdb.dbi.modules[0].moduleName, "renamed-module");
  assert.equal(rewrittenPdb.dbi.modules[0].objectName, "test.obj");
  assert.equal(
    rewrittenPdb.dbi.substreamSizes.moduleInfo,
    originalPdb.dbi.substreamSizes.moduleInfo + 8
  );
  assert.deepEqual(
    rewrittenPdb.streams[4].bytes,
    originalPdb.streams[4].bytes
  );
  assert.deepEqual(rewrittenPdb.dbi.modules[0].c13, originalPdb.dbi.modules[0].c13);

  const renamedObject = replaceClassicPdbModuleNames(rewritten, {
    moduleIndex: 0,
    objectName: "x.obj"
  });
  const renamedObjectPdb = parseClassicPdb(renamedObject);
  assert.equal(renamedObjectPdb.dbi.modules[0].moduleName, "renamed-module");
  assert.equal(renamedObjectPdb.dbi.modules[0].objectName, "x.obj");
  assert.throws(() => replaceClassicPdbModuleNames(original, {
    moduleIndex: 0,
    moduleName: "invalid\0name"
  }), /without null characters/);
  assert.throws(() => replaceClassicPdbModuleNames(original, {
    moduleIndex: 2,
    moduleName: "missing"
  }), /module index does not exist/);

  const overlay = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const overlaid = new Uint8Array(original.length + overlay.length);
  overlaid.set(original);
  overlaid.set(overlay, original.length);
  const editedOverlay = replaceClassicPdbModuleNames(overlaid, {
    moduleIndex: 0,
    objectName: "overlay.obj"
  });
  assert.deepEqual(editedOverlay.subarray(-overlay.length), overlay);
  assert.equal(parseClassicPdb(editedOverlay).dbi.modules[0].objectName, "overlay.obj");
});

test("classic PDB symbol names resize across MSF block allocations", () => {
  const original = makeClassicPdbWithSymbols();
  const rewritten = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "long"
  });
  assert.notEqual(rewritten, original);
  assert.equal(parseClassicPdb(rewritten).dbi.modules[0].symbols.records[0].decoded.name, "long");

  const expected = Uint8Array.from(original);
  expected.set([0x6c, 0x6f, 0x6e, 0x67, 0, 0xf1], 512 * 7 + 18);
  assert.deepEqual(rewritten, expected);
  assert.throws(() => replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "\ud800"
  }), /valid Unicode/);

  const resized = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "expansive"
  });
  const resizedPdb = parseClassicPdb(resized);
  assert.equal(resizedPdb.dbi.modules[0].symbols.records[0].decoded.name, "expansive");
  assert.equal(resizedPdb.dbi.modules[0].symbolBytes, 28);
  assert.equal(resizedPdb.streams[4].size, 28);
  const bomSymbol = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "\ufeff"
  });
  assert.equal(parseClassicPdb(bomSymbol).dbi.modules[0].symbols.records[0].decoded.name, "\ufeff");
  const shrunk = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "x"
  });
  const shrunkPdb = parseClassicPdb(shrunk);
  assert.equal(shrunkPdb.dbi.modules[0].symbols.records[0].decoded.name, "x");
  assert.equal(shrunkPdb.dbi.modules[0].symbolBytes, 20);
  const acrossBlocks = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "x".repeat(500)
  });
  const acrossBlocksPdb = parseClassicPdb(acrossBlocks);
  assert.equal(acrossBlocksPdb.dbi.modules[0].symbols.records[0].decoded.name, "x".repeat(500));
  assert.ok(acrossBlocksPdb.streams[4].blockIndices.length > 1);
});

test("classic PDB standalone symbols can be removed while preserving module data", () => {
  const original = makeClassicPdbWithSymbols({
    lineInfo: true,
    trailingModuleBytes: Uint8Array.of(0xaa, 0xbb, 0xcc)
  });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalStream = originalPdb.streams[originalModule.streamIndex];
  const overlay = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const overlaid = new Uint8Array(original.length + overlay.length);
  overlaid.set(original);
  overlaid.set(overlay, original.length);

  const rewritten = removeClassicPdbSymbol(overlaid, {
    moduleIndex: 0,
    recordIndex: 0
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  const rewrittenModule = rewrittenPdb.dbi.modules[0];
  const rewrittenStream = rewrittenPdb.streams[rewrittenModule.streamIndex];
  assert.equal(rewrittenModule.symbolBytes, 4);
  assert.deepEqual(rewrittenModule.symbols.records, []);
  assert.equal(rewrittenModule.c13Bytes, originalModule.c13Bytes);
  assert.deepEqual(
    rewrittenStream.bytes.subarray(rewrittenModule.symbolBytes),
    originalStream.bytes.subarray(originalModule.symbolBytes)
  );
  assert.deepEqual(rewritten.subarray(-overlay.length), overlay);

  const unknownSymbols = makeClassicPdbWithSymbols({ crossBlockName: true });
  const unknownSymbolsBefore = Uint8Array.from(unknownSymbols);
  assert.throws(() => removeClassicPdbSymbol(unknownSymbols, {
    moduleIndex: 0,
    recordIndex: 1
  }), /scoped or unknown symbols/);
  assert.throws(() => replaceClassicPdbSymbolName(unknownSymbols, {
    moduleIndex: 0,
    recordIndex: 1,
    name: "a-long-name"
  }), /scoped or unknown symbols/);
  assert.deepEqual(unknownSymbols, unknownSymbolsBefore);

  const multiBlockSymbols = makeClassicPdbWithSymbols({
    crossBlockName: true,
    knownPrefix: true
  });
  const multiBlockPdb = parseClassicPdb(multiBlockSymbols);
  assert.equal(multiBlockPdb.dbi.modules[0].symbols.records.length, 2);
  assert.equal(multiBlockPdb.dbi.modules[0].symbols.records[0].decoded.name.length, 477);
  const multiBlockOverlay = Uint8Array.of(0x91, 0x82, 0x73);
  const overlaidMultiBlock = new Uint8Array(multiBlockSymbols.length + multiBlockOverlay.length);
  overlaidMultiBlock.set(multiBlockSymbols);
  overlaidMultiBlock.set(multiBlockOverlay, multiBlockSymbols.length);
  const removedMultiBlockSymbol = removeClassicPdbSymbol(overlaidMultiBlock, {
    moduleIndex: 0,
    recordIndex: 1
  });
  const removedMultiBlockPdb = parseClassicPdb(removedMultiBlockSymbol);
  assert.equal(removedMultiBlockPdb.streams[4].blockIndices.length, 1);
  assert.equal(removedMultiBlockPdb.dbi.modules[0].symbolBytes, 496);
  assert.equal(removedMultiBlockPdb.dbi.modules[0].symbols.records.length, 1);
  assert.deepEqual(removedMultiBlockSymbol.subarray(-multiBlockOverlay.length), multiBlockOverlay);
});

test("classic PDB public symbols can be appended before module data", () => {
  const original = makeClassicPdbWithSymbols({
    lineInfo: true,
    trailingModuleBytes: Uint8Array.of(0x31, 0x32, 0x33)
  });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalStream = originalPdb.streams[originalModule.streamIndex];
  const rewritten = insertClassicPdbPublicSymbol(original, {
    moduleIndex: 0,
    flags: 3,
    offset: 0x1234,
    segment: 2,
    name: "AddedPublic"
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  const rewrittenModule = rewrittenPdb.dbi.modules[0];
  const addedSymbol = rewrittenModule.symbols.records[1].decoded;
  assert.equal(addedSymbol.kind, "public");
  assert.equal(addedSymbol.name, "AddedPublic");
  assert.equal(addedSymbol.flags, 3);
  assert.equal(addedSymbol.offset, 0x1234);
  assert.equal(addedSymbol.segment, 2);
  assert.deepEqual(
    rewrittenPdb.streams[rewrittenModule.streamIndex].bytes.subarray(rewrittenModule.symbolBytes),
    originalStream.bytes.subarray(originalModule.symbolBytes)
  );

  const moduleWithoutSymbols = makeClassicPdbWithSymbols({
    withSymbols: false,
    lineInfo: true
  });
  const moduleWithoutSymbolsPdb = parseClassicPdb(moduleWithoutSymbols);
  const emptySymbolsModule = moduleWithoutSymbolsPdb.dbi.modules[0];
  assert.equal(emptySymbolsModule.symbols, null);
  const firstSymbolPdb = parseClassicPdb(insertClassicPdbPublicSymbol(moduleWithoutSymbols, {
    moduleIndex: 0,
    offset: 7,
    segment: 1,
    name: "FirstPublic"
  }));
  const firstSymbolModule = firstSymbolPdb.dbi.modules[0];
  assert.ok(firstSymbolModule.symbolBytes > 4);
  assert.equal(firstSymbolModule.symbols.signature, 4);
  assert.equal(firstSymbolModule.symbols.records[0].decoded.name, "FirstPublic");
  assert.deepEqual(
    firstSymbolPdb.streams[firstSymbolModule.streamIndex].bytes.subarray(
      firstSymbolModule.symbolBytes
    ),
    moduleWithoutSymbolsPdb.streams[emptySymbolsModule.streamIndex].bytes
  );

  const unchanged = Uint8Array.from(original);
  assert.throws(() => insertClassicPdbPublicSymbol(original, {
    moduleIndex: 0,
    offset: 1,
    segment: 0x10000,
    name: "Invalid"
  }), /unsigned 16-bit integer/);
  assert.deepEqual(original, unchanged);
});

test("classic PDB local data symbols can be appended before module data", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalStream = originalPdb.streams[originalModule.streamIndex];
  const rewritten = insertClassicPdbDataSymbol(original, {
    moduleIndex: 0,
    typeIndex: 0x1001,
    offset: 0x5678,
    segment: 4,
    name: "StaticValue"
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  const rewrittenModule = rewrittenPdb.dbi.modules[0];
  const addedSymbol = rewrittenModule.symbols.records[1].decoded;
  assert.equal(addedSymbol.kind, "data");
  assert.equal(addedSymbol.typeIndex, 0x1001);
  assert.equal(addedSymbol.offset, 0x5678);
  assert.equal(addedSymbol.segment, 4);
  assert.equal(addedSymbol.name, "StaticValue");
  assert.deepEqual(
    rewrittenPdb.streams[rewrittenModule.streamIndex].bytes.subarray(rewrittenModule.symbolBytes),
    originalStream.bytes.subarray(originalModule.symbolBytes)
  );

  const unchanged = Uint8Array.from(original);
  assert.throws(() => insertClassicPdbDataSymbol(original, {
    moduleIndex: 0,
    typeIndex: -1,
    offset: 1,
    segment: 1,
    name: "Invalid"
  }), /type index must be an unsigned 32-bit integer/);
  assert.deepEqual(original, unchanged);
});

test("classic PDB constant symbols encode supported numeric values and preserve module data", () => {
  const original = makeClassicPdbWithSymbols({
    lineInfo: true,
    trailingModuleBytes: Uint8Array.of(0x31, 0x32, 0x33)
  });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalStream = originalPdb.streams[originalModule.streamIndex];
  const overlay = Uint8Array.of(0x91, 0x82, 0x73);
  const overlaid = new Uint8Array(original.length + overlay.length);
  overlaid.set(original);
  overlaid.set(overlay, original.length);

  const values = [
    0x7fff,
    -9,
    -0x8000,
    0xffff,
    0x8000,
    -0x80000000,
    0xffffffff,
    -0x80000001n,
    -(1n << 63n),
    (1n << 64n) - 1n,
    1.25,
    -0
  ];
  let rewritten = overlaid;
  for (const [index, value] of values.entries()) {
    const name = `Constant${index}`;
    rewritten = insertClassicPdbConstantSymbol(rewritten, {
      moduleIndex: 0,
      typeIndex: 0x1005,
      value,
      name
    });
    const pdb = parseClassicPdb(rewritten);
    const module = pdb.dbi.modules[0];
    const decoded = module.symbols.records.at(-1).decoded;
    assert.equal(decoded.kind, "constant");
    assert.equal(decoded.typeIndex, 0x1005);
    assert.equal(decoded.value, value);
    assert.equal(decoded.name, name);
    assert.deepEqual(
      pdb.streams[module.streamIndex].bytes.subarray(module.symbolBytes),
      originalStream.bytes.subarray(originalModule.symbolBytes)
    );
    assert.deepEqual(rewritten.subarray(-overlay.length), overlay);
  }

  const moduleWithoutSymbols = makeClassicPdbWithSymbols({
    withSymbols: false,
    lineInfo: true
  });
  const firstConstantModule = parseClassicPdb(insertClassicPdbConstantSymbol(
    moduleWithoutSymbols,
    { moduleIndex: 0, typeIndex: 0x1005, value: 2.5, name: "FirstConstant" }
  )).dbi.modules[0];
  assert.equal(firstConstantModule.symbols.signature, 4);
  assert.equal(firstConstantModule.symbols.records[0].decoded.kind, "constant");
  assert.equal(firstConstantModule.symbols.records[0].decoded.value, 2.5);

  const unchanged = Uint8Array.from(original);
  assert.throws(() => insertClassicPdbConstantSymbol(original, {
    moduleIndex: 0,
    typeIndex: 0x1005,
    value: Number.MAX_SAFE_INTEGER + 1,
    name: "Invalid"
  }), /must be safe integers/);
  assert.deepEqual(original, unchanged);
  assert.throws(() => insertClassicPdbConstantSymbol(original, {
    moduleIndex: 0,
    typeIndex: 0x1005,
    value: NaN,
    name: "Invalid"
  }), /must be finite numbers or BigInts/);
  assert.deepEqual(original, unchanged);
  assert.throws(() => insertClassicPdbConstantSymbol(original, {
    moduleIndex: 0,
    typeIndex: 0x1005,
    value: 1n << 64n,
    name: "Invalid"
  }), /must fit in 64 bits/);
  assert.deepEqual(original, unchanged);
  assert.throws(() => insertClassicPdbConstantSymbol(original, {
    moduleIndex: 0,
    typeIndex: 0x100000000,
    value: 1,
    name: "Invalid"
  }), /type index must be an unsigned 32-bit integer/);
  assert.deepEqual(original, unchanged);
});

test("classic PDB symbol resizing preserves trailing C13 module data", () => {
  const original = makeClassicPdbWithSymbols({ withC13: true });
  const rewritten = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "expansive"
  });
  const pdb = parseClassicPdb(rewritten);
  const module = pdb.dbi.modules[0];
  assert.equal(module.symbolBytes, 28);
  assert.equal(module.c13Bytes, 12);
  assert.equal(pdb.streams[module.streamIndex].size, 40);
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalC13 = originalPdb.streams[originalModule.streamIndex].bytes.subarray(
    originalModule.symbolBytes + originalModule.c11Bytes
  );
  const acrossBlocks = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 0,
    name: "x".repeat(500)
  });
  const acrossBlocksPdb = parseClassicPdb(acrossBlocks);
  const enlargedModule = acrossBlocksPdb.dbi.modules[0];
  assert.equal(enlargedModule.symbolBytes, 520);
  assert.equal(enlargedModule.c13Bytes, 12);
  assert.deepEqual(
    acrossBlocksPdb.streams[enlargedModule.streamIndex].bytes.subarray(
      enlargedModule.symbolBytes + enlargedModule.c11Bytes
    ),
    originalC13
  );
  assert.ok(acrossBlocksPdb.streams[enlargedModule.streamIndex].blockIndices.length > 1);
  assert.deepEqual(module.c13.subsections, [{
    kind: 0x77777777,
    data: Uint8Array.from([1, 2, 3])
  }]);
});

test("classic PDB symbol names can cross MSF stream blocks", () => {
  const original = makeClassicPdbWithSymbols({ crossBlockName: true });
  const rewritten = replaceClassicPdbSymbolName(original, {
    moduleIndex: 0,
    recordIndex: 1,
    name: "long"
  });
  assert.equal(parseClassicPdb(rewritten).dbi.modules[0].symbols.records[1].decoded.name, "long");
  assert.deepEqual(rewritten.subarray(512 * 7 + 510, 512 * 8 + 4),
    Uint8Array.from([0x6c, 0x6f, 0x6e, 0x67, 0, 0xf1]));
});

test("classic PDB /names entries can be replaced with offset remapping", () => {
  const original = makeClassicPdbWithNames();
  const rewritten = replaceClassicPdbStringTableName(original, {
    nameOffset: 1,
    name: "bar"
  });
  assert.equal(parseClassicPdb(rewritten).info.stringTable.strings.get(1), "bar");
  assert.deepEqual(rewritten.subarray(512 * 6 + 13, 512 * 6 + 16),
    Uint8Array.from([0x62, 0x61, 0x72]));
  const bomName = replaceClassicPdbStringTableName(original, {
    nameOffset: 1,
    name: "\ufeff"
  });
  assert.equal(parseClassicPdb(bomName).info.stringTable.strings.get(1), "\ufeff");
  const expanded = parseClassicPdb(replaceClassicPdbStringTableName(original, {
    nameOffset: 1,
    name: "longer"
  }));
  assert.equal(expanded.info.stringTable.strings.get(1), "longer");
  assert.equal(expanded.info.stringTable.strings.get(8), "bar");
  assert.deepEqual(expanded.info.stringTable.nameIds, [1, 8]);
  const shortened = parseClassicPdb(replaceClassicPdbStringTableName(original, {
    nameOffset: 1,
    name: "x"
  }));
  assert.equal(shortened.info.stringTable.strings.get(1), "x");
  assert.equal(shortened.info.stringTable.strings.get(3), "bar");
  assert.deepEqual(shortened.info.stringTable.nameIds, [1, 3]);
});

test("classic PDB module symbols preserve bounded CodeView record payloads", () => {
  const bytes = Uint8Array.from([
    4, 0, 0, 0,
    4, 0, 0x77, 0x77, 0xaa, 0xbb,
    2, 0, 0x76, 0x77
  ]);
  assert.deepEqual(parseCodeViewSymbolRecords(bytes), {
    signature: 4,
    records: [
      { offset: 4, kind: 0x7777, data: Uint8Array.from([0xaa, 0xbb]) },
      { offset: 10, kind: 0x7776, data: new Uint8Array() }
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
    0x70, 0x75, 0x62, 0, 0xf2, 0xf1
  ]);
  assert.deepEqual(parseCodeViewSymbolRecords(publicRecord).records[0].decoded, {
    kind: "public",
    flags: 1,
    offset: 0x11223344,
    segment: 3,
    name: "pub"
  });
  const invalidPublicPadding = publicRecord.slice();
  invalidPublicPadding[23] = 0xf2;
  assert.throws(() => parseCodeViewSymbolRecords(invalidPublicPadding), /invalid CodeView padding/);

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
  const frameProcedure = new Uint8Array(26);
  const frameView = new DataView(frameProcedure.buffer);
  frameView.setUint32(0, 0x100, true);
  frameView.setUint32(4, 4, true);
  frameView.setUint32(8, 8, true);
  frameView.setUint32(12, 12, true);
  frameView.setUint32(16, 16, true);
  frameView.setUint16(20, 2, true);
  frameView.setUint32(22, 0x1234, true);
  assert.deepEqual(decodeRecord(0x1012, frameProcedure), {
    kind: "frameProcedure",
    frameSize: 0x100,
    paddingSize: 4,
    paddingOffset: 8,
    savedRegisterSize: 12,
    exceptionHandlerOffset: 16,
    exceptionHandlerSegment: 2,
    flags: 0x1234
  });
  assert.deepEqual(decodeRecord(0x1124, Uint8Array.from([0x4e, 0x53, 0])), {
    kind: "namespace",
    name: "NS"
  });
  const compileInfo = new Uint8Array(26);
  const compileView = new DataView(compileInfo.buffer);
  compileView.setUint32(0, 3, true);
  compileView.setUint16(4, 0x8664, true);
  for (let index = 0; index < 8; index++) compileView.setUint16(6 + index * 2, index + 1, true);
  compileInfo.set([0x63, 0x76, 0x31, 0], 22);
  assert.deepEqual(decodeRecord(0x113c, compileInfo), {
    kind: "compileInfo",
    flags: 3,
    machine: 0x8664,
    frontEndVersion: { major: 1, minor: 2, build: 3, qfe: 4 },
    backEndVersion: { major: 5, minor: 6, build: 7, qfe: 8 },
    version: "cv1"
  });
  const objectName = new Uint8Array(8);
  const objectView = new DataView(objectName.buffer);
  objectView.setUint32(0, 0x12345678, true);
  objectName.set([0x6f, 0x62, 0x6a, 0], 4);
  assert.deepEqual(decodeRecord(0x1101, objectName), {
    kind: "objectName",
    signature: 0x12345678,
    name: "obj"
  });
  const block = new Uint8Array(20);
  const blockView = new DataView(block.buffer);
  blockView.setUint32(0, 1, true);
  blockView.setUint32(4, 2, true);
  blockView.setUint32(8, 0x30, true);
  blockView.setUint32(12, 0x40, true);
  blockView.setUint16(16, 3, true);
  block.set([0x62, 0], 18);
  assert.deepEqual(decodeRecord(0x1103, block), {
    kind: "block",
    parent: 1,
    end: 2,
    codeSize: 0x30,
    offset: 0x40,
    segment: 3,
    name: "b"
  });
  const emptyBlock = block.slice();
  emptyBlock.fill(0, 18);
  assert.deepEqual(decodeRecord(0x1103, emptyBlock), {
    kind: "block",
    parent: 1,
    end: 2,
    codeSize: 0x30,
    offset: 0x40,
    segment: 3,
    name: ""
  });
  const withScope = block.slice();
  withScope.set([0x78, 0], 18);
  assert.deepEqual(decodeRecord(0x1104, withScope), {
    kind: "withScope",
    parent: 1,
    end: 2,
    codeSize: 0x30,
    offset: 0x40,
    segment: 3,
    expression: "x"
  });
  assert.deepEqual(decodeRecord(0x0006, new Uint8Array()), { kind: "scopeEnd" });
  assert.deepEqual(decodeRecord(0x114e, new Uint8Array()), { kind: "scopeEnd" });

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

test("classic PDB C13 line records can be edited without resizing module streams", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true });
  const originalPdb = parseClassicPdb(original);
  const originalLine = originalPdb.dbi.modules[0].c13.lines[0].blocks[0].lines[0];
  assert.deepEqual(originalLine, {
    offset: 4,
    startLine: 5,
    endLineDelta: 0,
    isStatement: true,
    startColumn: 3,
    endColumn: 9
  });

  const rewritten = replaceClassicPdbLineInfo(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lineIndex: 0,
    line: {
      offset: 8,
      startLine: 42,
      endLineDelta: 2,
      isStatement: false,
      startColumn: 7,
      endColumn: 15
    }
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  assert.deepEqual(rewrittenPdb.dbi.modules[0].c13.lines[0].blocks[0].lines[0], {
    offset: 8,
    startLine: 42,
    endLineDelta: 2,
    isStatement: false,
    startColumn: 7,
    endColumn: 15
  });
  assert.equal(rewritten.length, original.length);
  assert.deepEqual(
    parseClassicPdb(original).dbi.modules[0].c13.lines[0].blocks[0].lines[0],
    originalLine
  );
  assert.throws(() => replaceClassicPdbLineInfo(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lineIndex: 0,
    line: { startLine: 0x1000000 }
  }), /line number fields are out of range/);
  assert.throws(() => replaceClassicPdbLineInfo(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lineIndex: 0,
    line: { offset: 11 }
  }), /line offset exceeds its code contribution/);
  assert.throws(() => replaceClassicPdbLineInfo(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lineIndex: 0,
    line: { offset: 0x100000000 }
  }), /line number fields are out of range/);
  assert.throws(() => replaceClassicPdbLineInfo(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lineIndex: 0,
    line: { startColumn: 16, endColumn: 15 }
  }), /line column fields are out of range/);
});

test("classic PDB C13 line blocks can be resized with columns and trailing module data preserved", () => {
  const trailing = Uint8Array.of(0x91, 0x92, 0x93);
  const basePdb = makeClassicPdbWithSymbols({
    lineInfo: true,
    trailingModuleBytes: trailing
  });
  const overlay = Uint8Array.of(0xc1, 0xc2, 0xc3, 0xc4);
  const original = new Uint8Array(basePdb.length + overlay.length);
  original.set(basePdb);
  original.set(overlay, basePdb.length);
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalC13Bytes = originalModule.c13Bytes;
  const originalStream = originalPdb.streams[originalModule.streamIndex].bytes;
  const trailingStart = originalModule.symbolBytes +
    originalModule.c11Bytes + originalC13Bytes;
  assert.deepEqual(originalStream.slice(trailingStart), trailing);

  const lines = [
    {
      offset: 2,
      startLine: 10,
      endLineDelta: 1,
      isStatement: true,
      startColumn: 2,
      endColumn: 8
    },
    {
      offset: 7,
      startLine: 20,
      endLineDelta: 3,
      isStatement: false,
      startColumn: 1,
      endColumn: 4
    }
  ];
  const expanded = replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines
  });
  const expandedPdb = parseClassicPdb(expanded);
  const expandedModule = expandedPdb.dbi.modules[0];
  assert.deepEqual(expandedModule.c13.lines[0].blocks[0].lines, lines);
  assert.equal(expandedModule.c13Bytes, originalC13Bytes + 12);
  assert.deepEqual(
    expanded.subarray(expandedPdb.numBlocks * expandedPdb.blockSize),
    overlay
  );
  assert.deepEqual(
    expandedPdb.streams[expandedModule.streamIndex].bytes.slice(
      expandedModule.symbolBytes + expandedModule.c11Bytes + expandedModule.c13Bytes
    ),
    trailing
  );
  assert.deepEqual(
    parseClassicPdb(original).dbi.modules[0].c13.lines[0].blocks[0].lines,
    originalPdb.dbi.modules[0].c13.lines[0].blocks[0].lines
  );

  const shrunk = replaceClassicPdbLineBlock(expanded, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines: [lines[1]]
  });
  const shrunkPdb = parseClassicPdb(shrunk);
  assert.deepEqual(shrunkPdb.dbi.modules[0].c13.lines[0].blocks[0].lines, [lines[1]]);
  assert.equal(shrunkPdb.dbi.modules[0].c13Bytes, originalC13Bytes);
  assert.deepEqual(
    shrunkPdb.streams[shrunkPdb.dbi.modules[0].streamIndex].bytes.slice(
      shrunkPdb.dbi.modules[0].symbolBytes +
      shrunkPdb.dbi.modules[0].c11Bytes +
      shrunkPdb.dbi.modules[0].c13Bytes
    ),
    trailing
  );
});

test("classic PDB C13 line blocks resize without columns and validate replacements", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true, lineColumns: false });
  const lines = [{
    offset: 6,
    startLine: 28,
    endLineDelta: 0,
    isStatement: false
  }];
  const rewritten = replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines
  });
  assert.deepEqual(
    parseClassicPdb(rewritten).dbi.modules[0].c13.lines[0].blocks[0].lines,
    lines
  );
  assert.throws(() => replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines: [{ ...lines[0], offset: 11 }]
  }), /out-of-range fields/);
  assert.throws(() => replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines: [{ ...lines[0], startColumn: 1, endColumn: 2 }]
  }), /invalid fields/);
  assert.throws(() => replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines: [
      { ...lines[0], offset: 7 },
      { ...lines[0], offset: 2 }
    ]
  }), /offsets must be nondecreasing/);
  assert.throws(() => replaceClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0,
    lines: []
  }), /non-empty lines array/);
});

test("classic PDB C13 line blocks can be inserted and removed by checksum reference", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true, twoChecksums: true });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const originalBlocks = originalModule.c13.lines[0].blocks;
  assert.equal(originalBlocks.length, 2);

  const inserted = insertClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    beforeBlockIndex: 1,
    fileChecksumOffset: 24,
    lines: originalBlocks[0].lines
  });
  const insertedPdb = parseClassicPdb(inserted);
  const insertedBlocks = insertedPdb.dbi.modules[0].c13.lines[0].blocks;
  assert.equal(insertedBlocks.length, 3);
  assert.equal(insertedBlocks[1].fileChecksumOffset, 24);
  assert.deepEqual(insertedBlocks[1].lines, originalBlocks[0].lines);
  assert.ok(insertedPdb.dbi.modules[0].c13.fileChecksums.has(
    insertedBlocks[1].fileChecksumOffset
  ));

  const removed = removeClassicPdbLineBlock(inserted, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 1
  });
  const removedPdb = parseClassicPdb(removed);
  assert.deepEqual(
    removedPdb.dbi.modules[0].c13.lines[0].blocks,
    [originalBlocks[0], originalBlocks[1]]
  );
  assert.throws(() => insertClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    beforeBlockIndex: 0,
    fileChecksumOffset: 8,
    lines: originalBlocks[0].lines
  }), /checksum location does not exist/);

  const removedFirst = removeClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0
  });
  assert.deepEqual(
    parseClassicPdb(removedFirst).dbi.modules[0].c13.lines[0].blocks,
    [originalBlocks[1]]
  );
  const removedLast = removeClassicPdbLineBlock(removedFirst, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0
  });
  assert.deepEqual(
    parseClassicPdb(removedLast).dbi.modules[0].c13.lines[0].blocks,
    []
  );
});

test("classic PDB C13 file checksums can be replaced and resized with line references remapped", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true });
  const originalPdb = parseClassicPdb(original);
  const originalChecksum = originalPdb.dbi.modules[0].c13.fileChecksums.get(0);
  assert.equal(originalChecksum.checksumKind, 1);
  assert.equal(originalChecksum.checksum.length, 16);

  const checksum = Uint8Array.from({ length: 16 }, (_, index) => 0xa0 + index);
  const rewritten = replaceClassicPdbFileChecksum(original, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum
  });
  const rewrittenPdb = parseClassicPdb(rewritten);
  assert.deepEqual(rewrittenPdb.dbi.modules[0].c13.fileChecksums.get(0).checksum, checksum);
  assert.deepEqual(
    rewrittenPdb.dbi.modules[0].c13.lines[0].blocks[0].lines[0],
    originalPdb.dbi.modules[0].c13.lines[0].blocks[0].lines[0]
  );
  assert.equal(rewritten.length, original.length);
  assert.deepEqual(
    parseClassicPdb(original).dbi.modules[0].c13.fileChecksums.get(0).checksum,
    originalChecksum.checksum
  );
  assert.throws(() => replaceClassicPdbFileChecksum(original, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum: new Uint8Array(17)
  }), /no supported checksum kind/);
  assert.throws(() => replaceClassicPdbFileChecksum(original, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum: new Uint8Array(16),
    checksumKind: 3
  }), /requires 32 bytes/);

  const multipleChecksums = makeClassicPdbWithSymbols({
    lineInfo: true,
    twoChecksums: true
  });
  const multiplePdb = parseClassicPdb(multipleChecksums);
  const multipleModule = multiplePdb.dbi.modules[0];
  assert.deepEqual([...multipleModule.c13.fileChecksums.keys()], [0, 24]);
  assert.equal(multipleModule.c13.lines[0].blocks[1].fileChecksumOffset, 24);
  const sha256Checksum = Uint8Array.from({ length: 32 }, (_, index) => 0x80 + index);
  const resized = replaceClassicPdbFileChecksum(multipleChecksums, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum: sha256Checksum
  });
  const resizedPdb = parseClassicPdb(resized);
  const resizedModule = resizedPdb.dbi.modules[0];
  assert.deepEqual([...resizedModule.c13.fileChecksums.keys()], [0, 40]);
  assert.deepEqual(resizedModule.c13.fileChecksums.get(0).checksum, sha256Checksum);
  assert.equal(resizedModule.c13.fileChecksums.get(0).checksumKind, 3);
  assert.equal(resizedModule.c13.lines[0].blocks[1].fileChecksumOffset, 40);
  assert.deepEqual(
    resizedModule.c13.lines[0].blocks[1].lines[0],
    multipleModule.c13.lines[0].blocks[1].lines[0]
  );
  assert.equal(resizedModule.c13Bytes, multipleModule.c13Bytes + 16);

  const noChecksum = parseClassicPdb(replaceClassicPdbFileChecksum(multipleChecksums, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum: new Uint8Array()
  }));
  const noChecksumModule = noChecksum.dbi.modules[0];
  assert.equal(noChecksumModule.c13.fileChecksums.get(0).checksumKind, 0);
  assert.deepEqual([...noChecksumModule.c13.fileChecksums.keys()], [0, 8]);
  assert.equal(noChecksumModule.c13.lines[0].blocks[1].fileChecksumOffset, 8);

  const overlay = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const withOverlay = new Uint8Array(multipleChecksums.length + overlay.length);
  withOverlay.set(multipleChecksums);
  withOverlay.set(overlay, multipleChecksums.length);
  const resizedWithOverlay = replaceClassicPdbFileChecksum(withOverlay, {
    moduleIndex: 0,
    fileChecksumOffset: 0,
    checksum: sha256Checksum
  });
  assert.deepEqual(resizedWithOverlay.subarray(-overlay.length), overlay);
});

test("classic PDB C13 checksums can be appended and safely removed", () => {
  const original = makeClassicPdbWithSymbols({ lineInfo: true, twoChecksums: true });
  const originalPdb = parseClassicPdb(original);
  const originalModule = originalPdb.dbi.modules[0];
  const appendedDigest = new Uint8Array(20).fill(0x5a);
  const appended = insertClassicPdbFileChecksum(original, {
    moduleIndex: 0,
    fileNameOffset: 1,
    checksum: appendedDigest
  });
  const appendedPdb = parseClassicPdb(appended);
  const appendedModule = appendedPdb.dbi.modules[0];
  assert.deepEqual([...appendedModule.c13.fileChecksums.keys()], [0, 24, 48]);
  assert.deepEqual(appendedModule.c13.fileChecksums.get(48).checksum, appendedDigest);
  assert.equal(appendedModule.c13.fileChecksums.get(48).checksumKind, 2);
  assert.deepEqual(
    appendedModule.c13.lines[0].blocks.map((block) => block.fileChecksumOffset),
    originalModule.c13.lines[0].blocks.map((block) => block.fileChecksumOffset)
  );
  const appendedLineBlock = insertClassicPdbLineBlock(appended, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    beforeBlockIndex: 2,
    fileChecksumOffset: 48,
    lines: originalModule.c13.lines[0].blocks[0].lines
  });
  assert.equal(
    parseClassicPdb(appendedLineBlock).dbi.modules[0].c13.lines[0].blocks[2]
      .fileChecksumOffset,
    48
  );
  const removedLineBlock = removeClassicPdbLineBlock(appendedLineBlock, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 2
  });
  const withoutAppended = removeClassicPdbFileChecksum(removedLineBlock, {
    moduleIndex: 0,
    fileChecksumOffset: 48
  });
  assert.deepEqual(
    [...parseClassicPdb(withoutAppended).dbi.modules[0].c13.fileChecksums.keys()],
    [0, 24]
  );
  assert.throws(() => removeClassicPdbFileChecksum(original, {
    moduleIndex: 0,
    fileChecksumOffset: 0
  }), /referenced by line blocks/);

  const noFirstBlock = removeClassicPdbLineBlock(original, {
    moduleIndex: 0,
    lineSubsectionIndex: 0,
    blockIndex: 0
  });
  const removedFirstChecksum = parseClassicPdb(removeClassicPdbFileChecksum(noFirstBlock, {
    moduleIndex: 0,
    fileChecksumOffset: 0
  }));
  const remappedModule = removedFirstChecksum.dbi.modules[0];
  assert.deepEqual([...remappedModule.c13.fileChecksums.keys()], [0]);
  assert.equal(remappedModule.c13.lines[0].blocks[0].fileChecksumOffset, 0);
  assert.deepEqual(
    remappedModule.c13.fileChecksums.get(0).checksum,
    originalModule.c13.fileChecksums.get(24).checksum
  );

  const noC13 = makeClassicPdbWithSymbols();
  const firstChecksum = parseClassicPdb(insertClassicPdbFileChecksum(noC13, {
    moduleIndex: 0,
    fileNameOffset: 1,
    checksum: new Uint8Array()
  }));
  assert.deepEqual(
    [...firstChecksum.dbi.modules[0].c13.fileChecksums.keys()],
    [0]
  );
  assert.equal(firstChecksum.dbi.modules[0].c13.fileChecksums.get(0).checksumKind, 0);
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
