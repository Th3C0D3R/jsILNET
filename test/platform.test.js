import assert from "node:assert/strict";
import { createHash as createNodeHash } from "node:crypto";
import { deflateRawSync as deflateNodeRaw, inflateRawSync as inflateNodeRaw } from "node:zlib";
import test from "node:test";
import { deflateRawSync, inflateRawSync } from "../src/platform/compression.js";
import { createHash } from "../src/platform/crypto.js";

test("portable raw DEFLATE inter-operates with Node's raw DEFLATE", () => {
  const input = new TextEncoder().encode("portable compression ".repeat(80));
  assert.deepEqual(Uint8Array.from(inflateRawSync(deflateNodeRaw(input))), input);
  assert.deepEqual(Uint8Array.from(inflateNodeRaw(deflateRawSync(input))), input);
});

test("portable raw DEFLATE enforces its decompressed size limit", () => {
  const input = new Uint8Array(1024).fill(0x41);
  const compressed = deflateRawSync(input);
  assert.deepEqual(inflateRawSync(compressed, { maxOutputLength: input.length }), input);
  assert.throws(
    () => inflateRawSync(compressed, { maxOutputLength: input.length - 1 }),
    /exceeds/
  );
});

test("portable hashes match the supported Node hash implementations", () => {
  const input = new TextEncoder().encode("jsILNET browser platform");
  for (const name of ["sha1", "sha256", "sha384", "sha512"]) {
    const expected = createNodeHash(name).update(input).digest();
    assert.deepEqual(createHash(name).update(input).digest(), Uint8Array.from(expected));
  }
});
