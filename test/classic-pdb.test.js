import test from "node:test";
import assert from "node:assert/strict";
import { parseClassicPdb } from "../src/index.js";

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
