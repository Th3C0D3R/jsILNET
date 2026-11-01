import test from "node:test";
import assert from "node:assert/strict";
import { BinaryReader, readCompressedInt, readCompressedUInt } from "../src/index.js";
import { appendCompressedInt } from "../src/metadata/writer.js";

test("BinaryReader reads little-endian primitives within a bounded view", () => {
  const reader = new BinaryReader(Uint8Array.from([0xaa, 0x34, 0x12, 0x78]), {
    start: 1,
    length: 2,
    baseOffset: 10,
    context: "test"
  });
  assert.equal(reader.u2(), 0x1234);
  assert.throws(() => reader.u1(), /exceeds the available/);
});

test("compressed unsigned integers decode all legal widths", () => {
  assert.equal(readCompressedUInt(new BinaryReader(Uint8Array.from([0x7f]))), 0x7f);
  assert.equal(readCompressedUInt(new BinaryReader(Uint8Array.from([0x80, 0x80]))), 0x80);
  assert.equal(readCompressedUInt(new BinaryReader(Uint8Array.from([0xc0, 0x00, 0x40, 0x00]))), 0x4000);
  assert.throws(() => readCompressedUInt(new BinaryReader(Uint8Array.from([0x80, 0x7f]))),
    /Non-canonical compressed unsigned integer/);
  assert.throws(() => readCompressedUInt(new BinaryReader(Uint8Array.from([0xc0, 0x00, 0x00, 0x7f]))),
    /Non-canonical compressed unsigned integer/);
  assert.throws(() => readCompressedUInt(new BinaryReader(Uint8Array.from([0xe0]))), /Invalid compressed/);
});

test("compressed signed integers sign-extend each encoded width", () => {
  for (const [bytes, expected] of [
    [[0x00], 0],
    [[0x7e], 63],
    [[0x7f], -1],
    [[0x01], -64],
    [[0x80, 0x80], 64],
    [[0xbf, 0x7f], -65],
    [[0xc0, 0x00, 0x40, 0x00], 8192],
    [[0xdf, 0xff, 0xbf, 0xff], -8193]
  ]) {
    assert.equal(readCompressedInt(new BinaryReader(Uint8Array.from(bytes))), expected);
  }
  assert.throws(() => readCompressedInt(new BinaryReader(Uint8Array.from([0x80, 0x7e]))),
    /Non-canonical compressed signed integer/);
  assert.throws(() => readCompressedInt(new BinaryReader(Uint8Array.from([0xc0, 0x00, 0x3f, 0xfe]))),
    /Non-canonical compressed signed integer/);
  assert.throws(() => readCompressedInt(new BinaryReader(Uint8Array.of(0xe0))), /Invalid compressed signed integer prefix/);
});

test("compressed signed integer writer round-trips the width boundaries", () => {
  for (const value of [-0x10000000, -0x2001, -0x2000, -65, -64, -1, 0, 63, 64, 0x1fff, 0x2000, 0x0fffffff]) {
    assert.equal(readCompressedInt(new BinaryReader(appendCompressedInt(value))), value);
  }
  assert.throws(() => appendCompressedInt(0x10000000), /out of range/);
});
