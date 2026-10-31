import test from "node:test";
import assert from "node:assert/strict";
import {
  encodeCustomAttribute,
  parseCustomAttribute,
  parsePermissionSet
} from "../src/metadata/custom-attributes.js";

test("custom-attribute fixed and named primitive/string values round-trip", () => {
  const fixedTypes = [
    { kind: "primitive", elementType: 0x08 },
    { kind: "string" }
  ];
  const bytes = Uint8Array.from([
    1, 0,
    42, 0, 0, 0,
    2, 0x48, 0x69,
    1, 0,
    0x54, 0x02,
    7, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64,
    1
  ]);
  const parsed = parseCustomAttribute(bytes, fixedTypes);
  assert.deepEqual(parsed, {
    fixedArguments: [42, "Hi"],
    namedArguments: [{
      kind: "property",
      type: { kind: "primitive", elementType: 0x02 },
      name: "Enabled",
      value: true
    }]
  });
  assert.deepEqual(encodeCustomAttribute(parsed, fixedTypes), bytes);
});

test("custom-attribute codecs validate prologs, booleans, and trailing data", () => {
  const booleanType = [{ kind: "primitive", elementType: 0x02 }];
  assert.throws(() => parseCustomAttribute(Uint8Array.from([0, 0, 0, 0]), booleanType), /prolog/);
  assert.throws(() => parseCustomAttribute(Uint8Array.from([1, 0, 2, 0, 0]), booleanType), /Boolean/);
  assert.throws(() => parseCustomAttribute(Uint8Array.from([1, 0, 0, 0, 0]), []), /Trailing bytes/);
});

test("custom-attribute codecs support arrays, boxed values, and enums", () => {
  const fixedTypes = [
    { kind: "array", elementType: { kind: "primitive", elementType: 0x08 } },
    { kind: "object" }
  ];
  const value = {
    fixedArguments: [
      [3, -4],
      { type: { kind: "string" }, value: "boxed" }
    ],
    namedArguments: [{
      kind: "field",
      type: { kind: "enum", name: "Example.Mode", elementType: 0x08 },
      name: "Mode",
      value: 2
    }]
  };
  const bytes = encodeCustomAttribute(value, fixedTypes);
  assert.deepEqual(parseCustomAttribute(bytes, fixedTypes, () => 0x08), value);
});

test("custom-attribute codecs support System.Type values and boxed System.Type values", () => {
  const fixedTypes = [
    { kind: "type" },
    { kind: "object" },
    { kind: "type" }
  ];
  const value = {
    fixedArguments: [
      "System.String, System.Private.CoreLib",
      { type: { kind: "type" }, value: "System.Int32, System.Private.CoreLib" },
      null
    ],
    namedArguments: [{
      kind: "property",
      type: { kind: "type" },
      name: "NullableType",
      value: null
    }]
  };
  const bytes = encodeCustomAttribute(value, fixedTypes);
  assert.deepEqual(parseCustomAttribute(bytes, fixedTypes), value);
});

test("custom-attribute codecs reject excessive nested types and boxed values", () => {
  const nestedBlob = Uint8Array.from([1, 0, ...new Array(40).fill(0x51)]);
  assert.throws(() => parseCustomAttribute(nestedBlob, [{ kind: "object" }]), /nesting exceeds supported depth/);

  let boxed = { type: { kind: "primitive", elementType: 0x08 }, value: 1 };
  for (let depth = 0; depth < 40; depth++) {
    boxed = { type: { kind: "object" }, value: boxed };
  }
  assert.throws(() => encodeCustomAttribute({ fixedArguments: [boxed], namedArguments: [] }, [{ kind: "object" }]),
    /nesting exceeds supported depth/);
});

test("binary PermissionSet blobs decode named security-attribute values", () => {
  const blob = Uint8Array.from([
    0x2e, 1, 1, 0x41, 13,
    1, 0, 0x54, 0x02, 7,
    0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 1
  ]);
  assert.deepEqual(parsePermissionSet(blob), {
    format: "binary",
    attributes: [{
      typeName: "A",
      namedArguments: [{
        kind: "property",
        type: { kind: "primitive", elementType: 0x02 },
        name: "Enabled",
        value: true
      }]
    }]
  });
  assert.throws(() => parsePermissionSet(Uint8Array.from([0x2e, 1, 1, 0x41, 3, 0, 0, 1])),
    /Trailing bytes after PermissionSet attribute data/);
  const xml = "<PermissionSet><IPermission class=\"Example.Permission\" /></PermissionSet>";
  assert.deepEqual(parsePermissionSet(new TextEncoder().encode(xml)), {
    format: "xml",
    xml
  });
  assert.throws(() => parsePermissionSet(Uint8Array.from([0x3c])),
    /not UTF-8 XML text/);
  assert.throws(() => parsePermissionSet(Uint8Array.from([0xff, 0xfe, 0x3c, 0x00])),
    /encoding is unsupported/);
});
