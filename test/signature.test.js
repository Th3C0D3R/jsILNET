import test from "node:test";
import assert from "node:assert/strict";
import {
  encodeSignature,
  encodeTypeSignature,
  parseSignature,
  parseTypeSignature,
  remapTypeReferences
} from "../src/index.js";

test("method signatures decode and re-encode calling conventions and sentinels", () => {
  const bytes = Uint8Array.from([0x05, 0x02, 0x01, 0x08, 0x41, 0x0e]);
  const signature = parseSignature(bytes);
  assert.equal(signature.kind, "method");
  assert.equal(signature.callingConvention, 5);
  assert.equal(signature.sentinelIndex, 1);
  assert.deepEqual(signature.parameters.map((parameter) => parameter.elementType), [0x08, 0x0e]);
  assert.deepEqual(encodeSignature(signature), bytes);
});

test("array and generic-instance type signatures round-trip", () => {
  const arrayBytes = Uint8Array.from([0x14, 0x08, 0x01, 0x01, 0x04, 0x01, 0x7d]);
  const array = parseTypeSignature(arrayBytes);
  assert.deepEqual(array, {
    kind: "array",
    type: { kind: "primitive", elementType: 0x08 },
    rank: 1,
    sizes: [4],
    lowerBounds: [-2]
  });
  assert.deepEqual(encodeTypeSignature(array), arrayBytes);

  const genericBytes = Uint8Array.from([0x15, 0x12, 0x05, 0x01, 0x0e]);
  const generic = parseTypeSignature(genericBytes);
  assert.equal(generic.kind, "genericInstance");
  assert.deepEqual(generic.genericType, { table: 1, tableName: "TypeRef", rid: 1 });
  assert.deepEqual(encodeTypeSignature(generic), genericBytes);
});

test("field, local, property, and method-instantiation signatures round-trip", () => {
  for (const bytes of [
    [0x06, 0x12, 0x05],
    [0x07, 0x02, 0x08, 0x45, 0x1d, 0x0e],
    [0x68, 0x01, 0x0e, 0x08],
    [0x0a, 0x02, 0x08, 0x0e]
  ]) {
    const signature = parseSignature(Uint8Array.from(bytes));
    assert.deepEqual(encodeSignature(signature), Uint8Array.from(bytes));
  }
});

test("signature parser rejects invalid type references and trailing bytes", () => {
  assert.throws(() => parseTypeSignature(Uint8Array.from([0x12, 0x00])), /cannot be nil/);
  assert.throws(() => parseTypeSignature(Uint8Array.from([0x12, 0x05]), {
    counts: Array(64).fill(0)
  }), /missing TypeRef row 1/);
  assert.throws(() => parseSignature(Uint8Array.from([0x06, 0x08, 0x00])), /Trailing bytes/);
  assert.throws(() => parseSignature(Uint8Array.from([0x00, 0x00, 0x01, 0x41])), /SENTINEL is invalid/);
});

test("signature parser bounds adversarially deep nested types", () => {
  const nested = Uint8Array.from([...Array(101).fill(0x1d), 0x08]);
  assert.throws(() => parseTypeSignature(nested), /Signature type nesting limit exceeded/);
});

test("signature TypeRef remapping updates nested references without changing other tables", () => {
  const signature = parseTypeSignature(Uint8Array.from([0x15, 0x12, 0x05, 0x01, 0x0e]));
  const remapped = remapTypeReferences(signature, (rid) => rid + 4);
  assert.deepEqual(remapped.genericType, { table: 1, tableName: "TypeRef", rid: 5 });
  assert.deepEqual(signature.genericType, { table: 1, tableName: "TypeRef", rid: 1 });
  assert.deepEqual(remapTypeReferences({ table: 2, rid: 7 }, (rid) => rid + 4), { table: 2, rid: 7 });
});
