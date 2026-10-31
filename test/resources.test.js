import test from "node:test";
import assert from "node:assert/strict";
import { parseManifestResources } from "../src/metadata/resources.js";

test("manifest resources expose bounded embedded payloads and external references", () => {
  const bytes = Uint8Array.from([3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);
  const rows = [
    { rid: 1, Offset: 0, Flags: 1, Name: 1, Implementation: { target: null } },
    { rid: 2, Offset: 0, Flags: 2, Name: 2, Implementation: { target: { table: 35, rid: 1 } } }
  ];
  const resources = parseManifestResources(
    bytes,
    { rva: 0x2000, size: bytes.length },
    rows,
    { getString: (index) => index === 1 ? "embedded" : "linked" },
    (rva, size) => {
      assert.equal(rva, 0x2000);
      assert.equal(size, bytes.length);
      return 0;
    }
  );
  assert.equal(resources[0].name, "embedded");
  assert.deepEqual(resources[0].data, Uint8Array.from([0xaa, 0xbb, 0xcc]));
  assert.equal(resources[1].name, "linked");
  assert.equal(resources[1].data, null);
  assert.deepEqual(resources[1].implementation, { table: 35, rid: 1 });
});

test("manifest resource parsing rejects missing directories and out-of-bounds payloads", () => {
  const row = { rid: 1, Offset: 0, Flags: 0, Name: 0, Implementation: { target: null } };
  const heaps = { getString: () => "" };
  assert.throws(() => parseManifestResources(
    new Uint8Array(),
    { rva: 0, size: 0 },
    [row],
    heaps,
    () => 0
  ), /no CLI resources directory/);
  assert.throws(() => parseManifestResources(
    Uint8Array.from([5, 0, 0, 0, 0]),
    { rva: 0x2000, size: 5 },
    [row],
    heaps,
    () => 0
  ), /payload exceeds/);
});
