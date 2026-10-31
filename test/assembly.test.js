import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import {
  encodeCodedIndex,
  encodeSignature,
  parseCliHeader,
  parseAssembly,
  parsePE,
  parseSignature,
  remapTypeReferences
} from "../src/index.js";
import { appendPeSection } from "../src/writer/pe.js";
import { MetadataHeaps } from "../src/metadata/streams.js";
import { appendBlobHeap, appendCompressedUInt } from "../src/metadata/writer.js";
import { encodeStrongNamePublicKey } from "../src/metadata/strong-name.js";
import { listOpcodes } from "../src/il/opcodes.js";

const fixture = readFileSync(new URL("./fixtures/Fixture.dll", import.meta.url));

function withoutDebugDirectory(input = fixture) {
  const bytes = Uint8Array.from(input);
  const pe = parsePE(bytes);
  const directoryOffset = pe.optionalHeaderOffset +
    (pe.optionalHeaderMagic === 0x10b ? 96 : 112) + 6 * 8;
  const view = new DataView(bytes.buffer);
  view.setUint32(directoryOffset, 0, true);
  view.setUint32(directoryOffset + 4, 0, true);
  return bytes;
}

function withoutLocalSignatureTokens(input = fixture) {
  const bytes = Uint8Array.from(input);
  const assembly = parseAssembly(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (const method of assembly.methods) {
    const body = assembly.getMethodBody(method.rid);
    if (body?.format === "fat") view.setUint32(body.headerOffset + 8, 0, true);
  }
  return bytes;
}

function setCatchClauseToken(assembly, token) {
  const method = assembly.methods.find((candidate) => candidate.name === "Finally");
  assert.ok(method);
  const body = assembly.getMethodBody(method.rid);
  const section = body.sections.find((candidate) => candidate.clauses.length > 0);
  assert.ok(section);
  const clause = section.clauses[0];
  const view = new DataView(
    assembly.bytes.buffer,
    assembly.bytes.byteOffset,
    assembly.bytes.byteLength
  );
  if (section.fat) {
    view.setUint32(section.offset + 4, 0, true);
  } else {
    view.setUint16(section.offset + 4, 0, true);
  }
  const tokenOffset = section.offset + 4 + (section.fat ? 20 : 8);
  view.setUint32(tokenOffset, token, true);
  clause.flags = 0;
  clause.classTokenOrFilterOffset = token;
}

function addEncToken(assembly, tableId, token) {
  const rows = assembly.tables.rows.get(tableId) ?? [];
  const tableName = tableId === 30 ? "ENCLog" : "ENCMap";
  const row = { table: tableId, tableName, rid: rows.length + 1, Token: token };
  if (tableId === 30) row.FuncCode = 0;
  rows.push(row);
  assembly.tables.rows.set(tableId, rows);
  assembly.tables.counts[tableId] = rows.length;
  assembly.tables.valid |= 1n << BigInt(tableId);
  assembly._metadataDirty = true;
}

function usePointerTable(assembly, {
  pointerId,
  targetId,
  column,
  listTableId,
  listColumn,
  pointerName,
  targetName
}) {
  const tablesStream = assembly.metadataRoot.streams.get("#~");
  assert.ok(tablesStream);
  assembly.metadataRoot.streams.delete("#~");
  assembly.metadataRoot.streams.set("#-", tablesStream);
  const targets = assembly.tables.get(targetId);
  const pointers = targets.map((target, index) => ({
    table: pointerId,
    tableName: pointerName,
    rid: index + 1,
    [column]: {
      raw: target.rid,
      table: targetId,
      tableName: targetName,
      rid: target.rid
    }
  }));
  assembly.tables.rows.set(pointerId, pointers);
  assembly.tables.counts[pointerId] = pointers.length;
  assembly.tables.valid |= 1n << BigInt(pointerId);
  for (const row of assembly.tables.get(listTableId)) {
    const rid = row[listColumn].rid;
    row[listColumn] = {
      raw: rid,
      table: pointerId,
      tableName: pointerName,
      rid
    };
  }
  assembly._metadataDirty = true;
}

function addExtraPEDataDirectory(input) {
  const pe = parsePE(input);
  const delta = 8;
  const sectionTableEnd = pe.sectionOffset + pe.sectionCount * 40;
  if (pe.sizeOfHeaders - sectionTableEnd < delta) {
    throw new Error("Fixture has insufficient PE header padding for an extra data directory");
  }
  const bytes = new Uint8Array(input.length);
  bytes.set(input.subarray(0, pe.sectionOffset));
  bytes.set(input.subarray(pe.sectionOffset, sectionTableEnd), pe.sectionOffset + delta);
  bytes.set(input.subarray(sectionTableEnd + delta), sectionTableEnd + delta);

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  view.setUint16(pe.peOffset + 20, pe.optionalHeaderSize + delta, true);
  view.setUint32(
    pe.optionalHeaderOffset + (pe.optionalHeaderMagic === 0x10b ? 92 : 108),
    17,
    true
  );
  const fixedOptionalHeaderSize = pe.optionalHeaderMagic === 0x10b ? 96 : 112;
  view.setUint32(
    pe.optionalHeaderOffset + fixedOptionalHeaderSize + 16 * 8,
    0x1234,
    true
  );
  view.setUint32(
    pe.optionalHeaderOffset + fixedOptionalHeaderSize + 16 * 8 + 4,
    0x5678,
    true
  );
  return bytes;
}

function addStrongNameSignatureSlot(input, size) {
  const assembly = parseAssembly(input);
  const metadataOffset = assembly.pe.rvaToOffset(
    assembly.cli.metadataRva,
    assembly.cli.metadataSize
  );
  const metadata = assembly.bytes.subarray(metadataOffset, metadataOffset + assembly.cli.metadataSize);
  const payload = new Uint8Array(size + metadata.length);
  payload.set(metadata, size);
  const appended = appendPeSection(
    assembly.bytes,
    assembly.pe,
    assembly.cli,
    payload,
    size,
    metadata.length
  );
  const pe = parsePE(appended.bytes);
  const cli = parseCliHeader(pe);
  const view = new DataView(appended.bytes.buffer, appended.bytes.byteOffset, appended.bytes.byteLength);
  view.setUint32(cli.strongNameDirectoryOffset, appended.virtualAddress, true);
  view.setUint32(cli.strongNameDirectoryOffset + 4, size, true);
  return appended.bytes;
}

function setStrongNameAssemblyKey(assembly, privateKey, hashAlgorithm) {
  const publicKey = encodeStrongNamePublicKey(privateKey, hashAlgorithm);
  const assemblyRow = assembly.tables.row(32, 1);
  const heapStreams = new Map([...assembly.metadataRoot.streams].map(([name, stream]) =>
    [name, stream.bytes.slice()]
  ));
  const appendedPublicKey = appendBlobHeap(heapStreams.get("#Blob"), publicKey);
  heapStreams.set("#Blob", appendedPublicKey.heap);
  assemblyRow.HashAlgId = hashAlgorithm;
  assemblyRow.Flags |= 0x01;
  assemblyRow.PublicKey = appendedPublicKey.index;
  assembly._heapStreams = heapStreams;
  assembly.heaps = new MetadataHeaps(new Map([...heapStreams].map(([name, bytes]) =>
    [name, { bytes }]
  )));
  assembly._metadataDirty = true;
}

function makeMinimalPE32Plus() {
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x80, true);
  view.setUint32(0x80, 0x00004550, true);
  view.setUint16(0x84, 0x8664, true);
  view.setUint16(0x86, 1, true);
  view.setUint16(0x94, 240, true);
  const optionalOffset = 0x98;
  view.setUint16(optionalOffset, 0x20b, true);
  view.setUint32(optionalOffset + 32, 0x1000, true);
  view.setUint32(optionalOffset + 36, 0x200, true);
  view.setUint32(optionalOffset + 56, 0x2000, true);
  view.setUint32(optionalOffset + 60, 0x200, true);
  view.setUint32(optionalOffset + 108, 16, true);
  const sectionOffset = optionalOffset + 240;
  bytes.set(new TextEncoder().encode(".text"), sectionOffset);
  view.setUint32(sectionOffset + 8, 0x100, true);
  view.setUint32(sectionOffset + 12, 0x1000, true);
  view.setUint32(sectionOffset + 16, 0x200, true);
  view.setUint32(sectionOffset + 20, 0x200, true);
  return bytes;
}

function makeMinimalManagedPE32Plus({ unknownStream = false } = {}) {
  const bytes = makeMinimalPE32Plus();
  const view = new DataView(bytes.buffer);
  const optionalOffset = 0x98;
  const sectionOffset = optionalOffset + 240;
  const metadataSize = unknownStream ? 144 : 124;
  view.setUint16(0x86, 1, true);
  view.setUint32(optionalOffset + 4, 0x200, true);
  view.setBigUint64(optionalOffset + 24, 0x140000000n, true);
  view.setUint32(optionalOffset + 112 + 14 * 8, 0x1000, true);
  view.setUint32(optionalOffset + 112 + 14 * 8 + 4, 72, true);
  bytes.set(new TextEncoder().encode(".text"), sectionOffset);
  view.setUint32(sectionOffset + 8, 0x200, true);
  view.setUint32(sectionOffset + 12, 0x1000, true);

  const cliOffset = 0x200;
  view.setUint32(cliOffset, 72, true);
  view.setUint16(cliOffset + 4, 2, true);
  view.setUint16(cliOffset + 6, 5, true);
  view.setUint32(cliOffset + 8, 0x1048, true);
  view.setUint32(cliOffset + 12, metadataSize, true);
  view.setUint32(cliOffset + 16, 1, true);

  const metadataOffset = 0x248;
  view.setUint32(metadataOffset, 0x424a5342, true);
  view.setUint16(metadataOffset + 4, 1, true);
  view.setUint16(metadataOffset + 6, 1, true);
  view.setUint32(metadataOffset + 12, 3, true);
  bytes.set([0x76, 0x31, 0], metadataOffset + 16);
  view.setUint16(metadataOffset + 20, 0, true);
  view.setUint16(metadataOffset + 22, unknownStream ? 3 : 2, true);
  const tablesRelativeOffset = unknownStream ? 72 : 56;
  const stringsRelativeOffset = tablesRelativeOffset + 56;
  const extraRelativeOffset = stringsRelativeOffset + 12;
  view.setUint32(metadataOffset + 24, tablesRelativeOffset, true);
  view.setUint32(metadataOffset + 28, 56, true);
  bytes.set([0x23, 0x7e, 0, 0], metadataOffset + 32);
  view.setUint32(metadataOffset + 36, stringsRelativeOffset, true);
  view.setUint32(metadataOffset + 40, 12, true);
  bytes.set(new TextEncoder().encode("#Strings"), metadataOffset + 44);
  if (unknownStream) {
    view.setUint32(metadataOffset + 56, extraRelativeOffset, true);
    view.setUint32(metadataOffset + 60, 4, true);
    bytes.set(new TextEncoder().encode("#Extra"), metadataOffset + 64);
    bytes.set([1, 2, 3, 4], metadataOffset + extraRelativeOffset);
  }
  const tablesOffset = metadataOffset + tablesRelativeOffset;
  view.setBigUint64(tablesOffset + 8, 5n, true);
  bytes.set([2, 0, 0, 1], tablesOffset + 4);
  view.setUint32(tablesOffset + 24, 1, true);
  view.setUint32(tablesOffset + 28, 1, true);
  view.setUint16(tablesOffset + 32 + 2, 1, true);
  const typeDefOffset = tablesOffset + 32 + 10;
  view.setUint32(typeDefOffset, 0, true);
  view.setUint16(typeDefOffset + 4, 3, true);
  view.setUint16(typeDefOffset + 10, 1, true);
  view.setUint16(typeDefOffset + 12, 1, true);
  bytes.set([0, 0x6d, 0, 0x3c, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0],
    metadataOffset + stringsRelativeOffset);
  return bytes;
}

function makePE32PlusWithDebugDirectory() {
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x80, true);
  view.setUint32(0x80, 0x00004550, true);
  view.setUint16(0x84, 0x8664, true);
  view.setUint16(0x86, 3, true);
  view.setUint16(0x94, 240, true);
  const optionalOffset = 0x98;
  view.setUint16(optionalOffset, 0x20b, true);
  view.setUint32(optionalOffset + 32, 0x1000, true);
  view.setUint32(optionalOffset + 36, 0x200, true);
  view.setUint32(optionalOffset + 56, 0x4000, true);
  view.setUint32(optionalOffset + 60, 0x200, true);
  view.setUint32(optionalOffset + 112 + 6 * 8, 0x3000, true);
  view.setUint32(optionalOffset + 112 + 6 * 8 + 4, 28, true);
  view.setUint32(optionalOffset + 108, 16, true);
  const sectionOffset = optionalOffset + 240;
  const sections = [
    { name: ".one", virtualSize: 0x100, virtualAddress: 0x1000, rawSize: 0, rawPointer: 0 },
    { name: ".two", virtualSize: 0x100, virtualAddress: 0x2000, rawSize: 0, rawPointer: 0 },
    { name: ".data", virtualSize: 0x200, virtualAddress: 0x3000, rawSize: 0x200, rawPointer: 0x200 }
  ];
  sections.forEach((section, index) => {
    const offset = sectionOffset + index * 40;
    bytes.set(new TextEncoder().encode(section.name), offset);
    view.setUint32(offset + 8, section.virtualSize, true);
    view.setUint32(offset + 12, section.virtualAddress, true);
    view.setUint32(offset + 16, section.rawSize, true);
    view.setUint32(offset + 20, section.rawPointer, true);
  });
  view.setUint32(0x200 + 12, 2, true);
  view.setUint32(0x200 + 16, 16, true);
  view.setUint32(0x200 + 20, 0x3040, true);
  view.setUint32(0x200 + 24, 0x240, true);
  return bytes;
}

test("real compiler-produced assembly round-trips unchanged and exposes metadata/CIL", () => {
  const assembly = parseAssembly(fixture);
  assert.equal(Buffer.compare(assembly.toBuffer(), fixture), 0);
  assert.deepEqual(assembly.resources, []);
  const exposedBytes = assembly.bytes;
  exposedBytes[0] = 0;
  assert.equal(Buffer.compare(assembly.toBuffer(), fixture), 0);
  assert.ok(assembly.types.some((type) => type.name.startsWith("Sample`") && type.namespace === "JsILNET.Fixture"));
  assert.ok(assembly.methods.some((method) => method.name === "Answer"));
  assert.ok(assembly.methods.some((method) => method.parameters.length > 0));
  assert.ok(assembly.types.some((type) => type.events.length > 0));
  assert.ok(assembly.types.some((type) => type.properties.length > 0));
  assert.ok(assembly.typeRefs.some((type) => type.name === "IDisposable"));
  assert.ok(assembly.memberRefs.some((member) => member.name === ".ctor"));
  assert.ok(assembly.assemblyRefs.some((reference) => reference.name === "System.Runtime"));
  for (const method of assembly.methods) {
    if (method.rva !== 0) assert.ok(assembly.getInstructions(method.rid).length > 0, method.name);
  }
  const method = assembly.methods.find((item) => item.name === "Answer");
  assert.ok(assembly.getInstructions(method.rid).some((instruction) => instruction.opcode.name.startsWith("ldc.i4")));
});

test("same-width numeric and existing user-string tokens patch and reparse", () => {
  const assembly = parseAssembly(fixture);
  const answer = assembly.methods.find((method) => method.name === "Answer");
  const constant = assembly.getInstructions(answer.rid).find((instruction) => instruction.opcode.name === "ldc.i4.s");
  assert.ok(constant, "fixture should contain a one-byte numeric operand");
  assembly.setInstructionOperand(answer.rid, constant.offset, 43);
  const smallConstant = assembly.methods.find((method) => method.name === "SmallConstant");
  const compact = assembly.getInstructions(smallConstant.rid).find((instruction) => instruction.opcode.name === "ldc.i4.2");
  assert.ok(compact);
  assembly.setInstructionOpcode(smallConstant.rid, compact.offset, "ldc.i4.3");

  const greeting = assembly.methods.find((method) => method.name === "Greeting");
  const stringLoad = assembly.getInstructions(greeting.rid).find((instruction) => instruction.opcode.name === "ldstr");
  assert.ok(stringLoad);
  const farewell = assembly.methods.find((method) => method.name === "Farewell");
  const goodbyeToken = assembly.getInstructions(farewell.rid).find((instruction) => instruction.opcode.name === "ldstr").operand.value;
  assert.equal(assembly.heaps.getUserString(goodbyeToken), "goodbye");
  assembly.setInstructionOperand(greeting.rid, stringLoad.offset, goodbyeToken);

  const output = assembly.serialize();
  assert.notEqual(Buffer.compare(output, fixture), 0);
  const reparsed = parseAssembly(output);
  const answerAfter = reparsed.methods.find((method) => method.name === "Answer");
  assert.equal(reparsed.getInstructions(answerAfter.rid).find((instruction) => instruction.opcode.name === "ldc.i4.s").operand.value, 43);
  const smallConstantAfter = reparsed.methods.find((method) => method.name === "SmallConstant");
  assert.ok(reparsed.getInstructions(smallConstantAfter.rid).some((instruction) => instruction.opcode.name === "ldc.i4.3"));
  const greetingAfter = reparsed.methods.find((method) => method.name === "Greeting");
  const newStringToken = reparsed.getInstructions(greetingAfter.rid).find((instruction) => instruction.opcode.name === "ldstr").operand.value;
  assert.equal(reparsed.heaps.getUserString(newStringToken), "goodbye");
});

test("appended user strings can be used by ldstr and survive metadata rebuilding", () => {
  const assembly = parseAssembly(fixture);
  const greeting = assembly.methods.find((method) => method.name === "Greeting");
  const stringLoad = assembly.getInstructions(greeting.rid).find((instruction) => instruction.opcode.name === "ldstr");
  const value = "new\u0000line 'café";
  const token = assembly.addUserString(value);
  assert.equal(token >>> 24, 0x70);
  assert.equal(assembly.heaps.getUserString(token), value);
  assembly.setInstructionOperand(greeting.rid, stringLoad.offset, token);

  const reparsed = parseAssembly(assembly.serialize());
  const rewrittenGreeting = reparsed.methods.find((method) => method.name === "Greeting");
  const rewrittenToken = reparsed.getInstructions(rewrittenGreeting.rid)
    .find((instruction) => instruction.opcode.name === "ldstr").operand.value;
  assert.equal(reparsed.heaps.getUserString(rewrittenToken), value);
});

test("metadata token edits validate opcode table kinds and row bounds", () => {
  const assembly = parseAssembly(fixture);
  for (const method of assembly.methods) {
    for (const instruction of assembly.getInstructions(method.rid)) {
      if (instruction.operand?.kind === "token") {
        assembly.setInstructionOperand(method.rid, instruction.offset, instruction.operand.value);
      }
    }
  }
  const callSite = assembly.methods.map((method) => ({
    method,
    instruction: assembly.getInstructions(method.rid).find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  const targetMethod = assembly.methods.find((method) => method.name === "Answer");
  assert.ok(callSite && targetMethod);

  const validToken = 0x06000000 + targetMethod.rid;
  assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, validToken);
  assert.throws(() => assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, 0x04000001), /not valid for call/);
  assert.throws(() => assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, 0x06ffffff), /references missing MethodDef row/);
  const reparsed = parseAssembly(assembly.serialize());
  const rewrittenCall = reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset);
  assert.equal(rewrittenCall.operand.value, validToken);
});

test("Tier 1 rejects a variable-width edit", () => {
  const assembly = parseAssembly(fixture);
  const answer = assembly.methods.find((method) => method.name === "Answer");
  const constant = assembly.getInstructions(answer.rid).find((instruction) => instruction.opcode.name === "ldc.i4.s");
  assert.throws(() => assembly.setInstructionOperand(answer.rid, constant.offset, 500), /does not fit i1/);
});

test("editing a strong-name-signed image strips the signature directory and flag", () => {
  const signedInput = Uint8Array.from(fixture);
  const parsed = parseAssembly(signedInput);
  const answer = parsed.methods.find((method) => method.name === "Answer");
  const bodyOffset = parsed.pe.rvaToOffset(answer.rva, 1);
  const inputView = new DataView(signedInput.buffer, signedInput.byteOffset, signedInput.byteLength);
  inputView.setUint32(parsed.cli.strongNameFlagOffset, parsed.cli.flags | 0x08, true);
  inputView.setUint32(parsed.cli.strongNameDirectoryOffset, answer.rva, true);
  inputView.setUint32(parsed.cli.strongNameDirectoryOffset + 4, 1, true);

  const assembly = parseAssembly(signedInput);
  const constant = assembly.getInstructions(answer.rid).find((instruction) => instruction.opcode.name === "ldc.i4.s");
  assembly.setInstructionOperand(answer.rid, constant.offset, 43);
  const output = assembly.serialize();
  const outputView = new DataView(output.buffer, output.byteOffset, output.byteLength);
  assert.equal(outputView.getUint32(assembly.cli.strongNameFlagOffset, true) & 0x08, 0);
  assert.equal(outputView.getUint32(assembly.cli.strongNameDirectoryOffset, true), 0);
  assert.equal(outputView.getUint32(assembly.cli.strongNameDirectoryOffset + 4, true), 0);
  assert.equal(output[bodyOffset], 0);
});

test("strong-name signing preserves and verifies a reserved RSA signature slot", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const hashAlgorithm = 0x00008004;
  const signatureSize = Math.ceil(privateKey.asymmetricKeyDetails.modulusLength / 8);
  const assembly = parseAssembly(addStrongNameSignatureSlot(withoutDebugDirectory(), signatureSize));
  setStrongNameAssemblyKey(assembly, privateKey, hashAlgorithm);

  const signedBytes = assembly.signStrongName(privateKey).serialize();
  const signedAssembly = parseAssembly(signedBytes);
  assert.equal(signedAssembly.cli.flags & 0x08, 0x08);
  assert.equal(signedAssembly.verifyStrongNameSignature(), true);
  const mismatchedAssembly = parseAssembly(signedBytes);
  const mismatchedKey = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey;
  assert.throws(() => mismatchedAssembly.signStrongName(mismatchedKey), /does not match the Assembly public key/);
  assert.equal(mismatchedAssembly.modified, false);

  const answer = signedAssembly.methods.find((method) => method.name === "Answer");
  const instruction = signedAssembly.getInstructions(answer.rid)
    .find((item) => item.opcode.name === "ldc.i4.s");
  const resignedBytes = signedAssembly.setInstructionOperand(
    answer.rid,
    instruction.offset,
    43
  ).signStrongName(privateKey).serialize();
  assert.equal(parseAssembly(resignedBytes).verifyStrongNameSignature(), true);

  const corrupted = Uint8Array.from(resignedBytes);
  const corruptedAssembly = parseAssembly(corrupted);
  const bodyOffset = corruptedAssembly.pe.rvaToOffset(answer.rva, 1);
  corrupted[bodyOffset] ^= 0x01;
  assert.equal(parseAssembly(corrupted).verifyStrongNameSignature(), false);
  const invalidSignature = Uint8Array.from(resignedBytes);
  const invalidAssembly = parseAssembly(invalidSignature);
  const signatureOffset = invalidAssembly.pe.rvaToOffset(
    invalidAssembly.cli.strongNameSignature.rva,
    invalidAssembly.cli.strongNameSignature.size
  );
  invalidSignature[signatureOffset] ^= 0x01;
  assert.equal(parseAssembly(invalidSignature).verifyStrongNameSignature(), false);
});

test("strong-name signing rejects optional headers with additional directories", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const input = addExtraPEDataDirectory(withoutDebugDirectory());
  assert.equal(parseAssembly(input).pe.directories.length, 17);
  const assembly = parseAssembly(addStrongNameSignatureSlot(input, 128));
  setStrongNameAssemblyKey(assembly, privateKey, 0x00008004);

  assert.throws(
    () => assembly.signStrongName(privateKey).serialize(),
    /standard PE optional header with 16 data directories/
  );
});

test("strong-name signing supports SHA-256, SHA-384, and SHA-512 hash IDs", () => {
  for (const hashAlgorithm of [0x0000800c, 0x0000800d, 0x0000800e]) {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const size = Math.ceil(privateKey.asymmetricKeyDetails.modulusLength / 8);
    const assembly = parseAssembly(addStrongNameSignatureSlot(withoutDebugDirectory(), size));
    setStrongNameAssemblyKey(assembly, privateKey, hashAlgorithm);
    const output = assembly.signStrongName(privateKey).serialize();
    assert.equal(parseAssembly(output).verifyStrongNameSignature(), true);
  }
});

test("strong-name signing allocates a signature slot when the PE has none", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const assembly = parseAssembly(withoutDebugDirectory());
  setStrongNameAssemblyKey(assembly, privateKey, 0x00008004);
  assert.deepEqual(assembly.cli.strongNameSignature, { rva: 0, size: 0 });

  const signed = parseAssembly(assembly.signStrongName(privateKey).serialize());
  assert.ok(signed.cli.strongNameSignature.rva > 0);
  assert.equal(signed.cli.strongNameSignature.size, 128);
  assert.equal(signed.verifyStrongNameSignature(), true);
});

test("strong-name public-key replacement reallocates a differently sized signature slot", () => {
  const { privateKey: originalKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const { privateKey: replacementKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const assembly = parseAssembly(addStrongNameSignatureSlot(withoutDebugDirectory(), 128));
  setStrongNameAssemblyKey(assembly, originalKey, 0x00008004);

  const signed = parseAssembly(
    assembly.replaceStrongNamePublicKey(replacementKey).serialize()
  );
  assert.equal(signed.cli.strongNameSignature.size, 256);
  assert.deepEqual(
    Buffer.from(signed.heaps.getBlob(signed.tables.row(32, 1).PublicKey)),
    encodeStrongNamePublicKey(replacementKey, 0x00008004)
  );
  assert.equal(signed.verifyStrongNameSignature(), true);
});

test("Assembly identity replacement updates metadata heaps and version fields", () => {
  const assembly = parseAssembly(fixture);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  setStrongNameAssemblyKey(assembly, privateKey, 0x00008004);
  const identity = {
    name: "Fixture.Renamed",
    culture: "fr-FR",
    version: [2, 4, 6, 8]
  };
  assert.equal(assembly.replaceAssemblyIdentity(identity), assembly);
  assert.equal(assembly.module.assembly.name, identity.name);
  assert.equal(assembly.module.assembly.culture, identity.culture);
  assert.deepEqual(assembly.module.assembly.version, identity.version);

  const reparsed = parseAssembly(assembly.signStrongName(privateKey).serialize());
  assert.equal(reparsed.module.assembly.name, identity.name);
  assert.equal(reparsed.module.assembly.culture, identity.culture);
  assert.deepEqual(reparsed.module.assembly.version, identity.version);
  assert.equal(reparsed.verifyStrongNameSignature(), true);
});

test("Module name and generation replacement preserve the module MVID", () => {
  const assembly = parseAssembly(fixture);
  const mvid = assembly.module.mvid;
  assert.equal(assembly.replaceModule({ name: "Fixture.Module.dll", generation: 1 }), assembly);
  assert.equal(assembly.module.name, "Fixture.Module.dll");
  assert.equal(assembly.module.generation, 1);
  assert.deepEqual(assembly.module.mvid, mvid);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.module.name, "Fixture.Module.dll");
  assert.equal(reparsed.module.generation, 1);
  assert.deepEqual(reparsed.module.mvid, mvid);
  assert.throws(() => reparsed.replaceModule({ generation: 0x10000 }), /unsigned 16-bit/);
  assert.equal(reparsed.module.generation, 1);
});

test("structural edits still strip strong-name data unless re-signing is requested", () => {
  const signedInput = Uint8Array.from(fixture);
  const parsed = parseAssembly(signedInput);
  const answer = parsed.methods.find((method) => method.name === "Answer");
  const inputView = new DataView(signedInput.buffer, signedInput.byteOffset, signedInput.byteLength);
  inputView.setUint32(parsed.cli.strongNameFlagOffset, parsed.cli.flags | 0x08, true);
  inputView.setUint32(parsed.cli.strongNameDirectoryOffset, answer.rva, true);
  inputView.setUint32(parsed.cli.strongNameDirectoryOffset + 4, 1, true);

  const assembly = parseAssembly(signedInput);
  const lastTypeRef = assembly.typeRefs.at(-1);
  assembly.addTypeRef({
    scope: lastTypeRef.resolutionScope,
    name: "StructuralEdit",
    namespace: "JsILNET.Test"
  });
  const output = assembly.serialize();
  const reparsed = parseAssembly(output);
  assert.equal(reparsed.cli.flags & 0x08, 0);
  assert.deepEqual(reparsed.cli.strongNameSignature, { rva: 0, size: 0 });
});

test("Tier 1 refuses edits to Authenticode-signed PE files", () => {
  const signedInput = Uint8Array.from(fixture);
  const parsed = parseAssembly(signedInput);
  const securityDirectoryOffset = parsed.pe.optionalHeaderOffset +
    (parsed.pe.optionalHeaderMagic === 0x10b ? 96 : 112) + 4 * 8;
  const view = new DataView(signedInput.buffer, signedInput.byteOffset, signedInput.byteLength);
  view.setUint32(securityDirectoryOffset, 0x1000, true);
  view.setUint32(securityDirectoryOffset + 4, 16, true);
  const assembly = parseAssembly(signedInput);
  const answer = assembly.methods.find((method) => method.name === "Answer");
  const constant = assembly.getInstructions(answer.rid).find((instruction) => instruction.opcode.name === "ldc.i4.s");
  assert.throws(() => assembly.setInstructionOperand(answer.rid, constant.offset, 43), /Authenticode-signed/);
});

test("PE parser rejects data directories truncated by the optional header", () => {
  const parsed = parseAssembly(fixture);
  const malformed = Uint8Array.from(fixture);
  const directoryCountOffset = parsed.pe.optionalHeaderOffset +
    (parsed.pe.optionalHeaderMagic === 0x10b ? 92 : 108);
  const availableDirectories = Math.floor(
    (parsed.pe.optionalHeaderSize - (parsed.pe.optionalHeaderMagic === 0x10b ? 96 : 112)) / 8
  );
  new DataView(malformed.buffer).setUint32(directoryCountOffset, availableDirectories + 1, true);
  assert.throws(() => parseAssembly(malformed), /data directories that do not fit/);
});

test("PE32+ parsing honors its optional-header and section-table layout", () => {
  const pe = parsePE(makeMinimalPE32Plus());
  assert.equal(pe.optionalHeaderMagic, 0x20b);
  assert.equal(pe.optionalHeaderSize, 240);
  assert.equal(pe.sectionOffset, 0x188);
  assert.equal(pe.sections[0].name, ".text");
  assert.equal(pe.rvaToOffset(0x1000), 0x200);
  assert.equal(pe.rvaToOffset(0x11ff), 0x3ff);
});

test("PE32+ managed assemblies parse and round-trip through the CLI reader", () => {
  const bytes = makeMinimalManagedPE32Plus();
  const assembly = parseAssembly(bytes);
  assert.equal(assembly.pe.optionalHeaderMagic, 0x20b);
  assert.equal(assembly.cli.metadataRva, 0x1048);
  assert.deepEqual(assembly.methods, []);
  assert.deepEqual(assembly.serialize(), bytes);
});

test("PE32+ structural metadata rewriting appends and reparses a PE section", () => {
  const assembly = parseAssembly(makeMinimalManagedPE32Plus());
  const originalSectionCount = assembly.pe.sectionCount;
  const inserted = assembly.insertTypeRefSorted({
    scope: { table: "Module", rid: 1 },
    name: "PE32PlusAdded"
  });
  const reparsed = parseAssembly(assembly.serialize());

  assert.equal(reparsed.pe.optionalHeaderMagic, 0x20b);
  assert.equal(reparsed.pe.sectionCount, originalSectionCount + 1);
  assert.equal(reparsed.typeRefs[0].name, "PE32PlusAdded");
  assert.equal(inserted.token, 0x01000001);
});

test("structural serialization recomputes coded and string indexes at metadata-width thresholds", () => {
  const assembly = parseAssembly(makeMinimalManagedPE32Plus());
  const typeRefCount = 0x4000;
  const names = Array.from({ length: typeRefCount }, (_, index) =>
    `Added${index.toString().padStart(5, "0")}`
  );
  const encodedNames = names.map((name) => new TextEncoder().encode(name));
  const originalStrings = assembly.metadataRoot.streams.get("#Strings").bytes;
  const stringsSize = originalStrings.length +
    encodedNames.reduce((size, name) => size + name.length + 1, 0);
  const stringsHeap = new Uint8Array(stringsSize);
  stringsHeap.set(originalStrings);
  const rows = [];
  let nameOffset = originalStrings.length;
  const scope = {
    raw: encodeCodedIndex(0, 1, "ResolutionScope"),
    target: { table: 0, tableName: "Module", rid: 1 }
  };
  for (let index = 0; index < names.length; index++) {
    const encodedName = encodedNames[index];
    rows.push({
      table: 1,
      tableName: "TypeRef",
      rid: index + 1,
      ResolutionScope: scope,
      TypeName: nameOffset,
      TypeNamespace: 0
    });
    stringsHeap.set(encodedName, nameOffset);
    nameOffset += encodedName.length + 1;
  }
  const heapStreams = new Map([...assembly.metadataRoot.streams].map(([name, stream]) =>
    [name, stream.bytes.slice()]
  ));
  heapStreams.set("#Strings", stringsHeap);
  assembly._heapStreams = heapStreams;
  assembly.tables.rows.set(1, rows);
  assembly.tables.counts[1] = typeRefCount;
  assembly.tables.valid |= 1n << 1n;
  assembly.tables.sorted |= 1n << 1n;
  assembly.typeRefs = names.map((name, index) => ({
    rid: index + 1,
    name,
    namespace: "",
    resolutionScope: scope.target
  }));
  assembly._metadataDirty = true;

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.typeRefs.length, typeRefCount);
  assert.equal(reparsed.typeRefs.at(-1).name, names.at(-1));
  assert.equal(reparsed.tables.get("TypeRef").at(-1).ResolutionScope.raw, scope.raw);
});

test("unknown metadata streams remain readable and byte-identical on no-op round trips", () => {
  const bytes = makeMinimalManagedPE32Plus({ unknownStream: true });
  const assembly = parseAssembly(bytes);
  assert.deepEqual(assembly.metadataRoot.streams.get("#Extra").bytes, Uint8Array.from([1, 2, 3, 4]));
  assert.deepEqual(assembly.serialize(), bytes);
});

test("CodeView PDB paths can be replaced within their record size and preserve identity", () => {
  const assembly = parseAssembly(fixture);
  const codeView = assembly.pe.debugDirectoryEntries[0].codeView;
  assert.equal(codeView.format, "RSDS");
  const nextPath = codeView.path.replace(/Fixture\.pdb$/, "Fixture.xdb");
  assert.notEqual(nextPath, codeView.path);
  assert.equal(new TextEncoder().encode(nextPath).length, codeView.pathByteLength);
  assert.throws(() => assembly.replaceCodeViewPath(0, `${codeView.path}.longer`),
    /fit within its existing record/);
  assert.throws(() => assembly.replaceCodeViewPath(1, "other.pdb"),
    /not a supported CodeView record/);
  assert.equal(assembly.modified, false);

  const identity = { guid: codeView.guid, age: codeView.age };
  const shortened = parseAssembly(fixture);
  shortened.replaceCodeViewPath(0, "short.pdb");
  const shortenedCodeView = parseAssembly(shortened.serialize()).pe.debugDirectoryEntries[0].codeView;
  assert.equal(shortenedCodeView.path, "short.pdb");
  assert.deepEqual(
    { guid: shortenedCodeView.guid, age: shortenedCodeView.age },
    identity
  );
  shortened.replaceCodeViewPath(0, codeView.path);
  assert.equal(
    parseAssembly(shortened.serialize()).pe.debugDirectoryEntries[0].codeView.path,
    codeView.path
  );

  assembly.replaceCodeViewPath(0, nextPath);
  assert.equal(codeView.path, nextPath);
  const owner = assembly.types.at(-1);
  assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "DebugPathEditField",
    flags: 6,
    signature: Uint8Array.from([0x06, 0x08])
  });
  const reparsed = parseAssembly(assembly.serialize());
  const updated = reparsed.pe.debugDirectoryEntries[0].codeView;
  assert.equal(updated.path, nextPath);
  assert.deepEqual({ guid: updated.guid, age: updated.age }, identity);
  assert.equal(reparsed.types[owner.rid - 1].fields.at(-1).name, "DebugPathEditField");
});

test("metadata RID remapping is refused when PE debug data may reference tokens", () => {
  const assembly = parseAssembly(fixture);
  const originalTypeRefCount = assembly.typeRefs.length;
  assert.throws(() => assembly.insertTypeRefSorted({
    scope: { table: "Module", rid: 1 },
    name: "DebugSensitiveType"
  }), /token remapping is unsupported while a PE debug directory is present/);
  assert.equal(assembly.typeRefs.length, originalTypeRefCount);
  assert.equal(assembly.modified, false);

  const assemblyRefToken = assembly.addAssemblyRef({ name: "DebugSensitive.Dependency" });
  const originalAssemblyRefCount = assembly.assemblyRefs.length;
  assert.throws(() => assembly.removeAssemblyRef(assemblyRefToken & 0x00ffffff),
    /token remapping is unsupported while a PE debug directory is present/);
  assert.equal(assembly.assemblyRefs.length, originalAssemblyRefCount);
});

test("CLI metadata requires one Module row and the special first TypeDef", () => {
  const missingModule = makeMinimalManagedPE32Plus();
  const tablesOffset = 0x248 + 56;
  const missingModuleView = new DataView(missingModule.buffer);
  missingModuleView.setBigUint64(tablesOffset + 8, 1n << 2n, true);
  missingModuleView.setUint32(tablesOffset + 24, 1, true);
  missingModule.copyWithin(tablesOffset + 28, tablesOffset + 42, tablesOffset + 56);
  assert.throws(() => parseAssembly(missingModule), /exactly one Module row/);

  const missingSpecialType = makeMinimalManagedPE32Plus();
  new DataView(missingSpecialType.buffer).setUint16(tablesOffset + 32 + 10 + 4, 1, true);
  assert.throws(() => parseAssembly(missingSpecialType), /first TypeDef row must be the special <Module>/);
});

test("PE parser validates debug-directory entries and raw data bounds", () => {
  const parsed = parsePE(fixture);
  const codeViewEntry = parsed.debugDirectoryEntries.find((entry) => entry.type === 2);
  assert.ok(codeViewEntry?.codeView);
  assert.equal(codeViewEntry.codeView.format, "RSDS");
  assert.match(codeViewEntry.codeView.guid, /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.equal(codeViewEntry.codeView.age, 1);
  assert.match(codeViewEntry.codeView.path, /Fixture\.pdb$/);
  const legacyCodeView = Uint8Array.from(fixture);
  const legacyPath = legacyCodeView.slice(
    codeViewEntry.pointerToRawData + 24,
    codeViewEntry.pointerToRawData + codeViewEntry.sizeOfData
  );
  legacyCodeView.set([0x4e, 0x42, 0x31, 0x30], codeViewEntry.pointerToRawData);
  const legacyView = new DataView(legacyCodeView.buffer);
  legacyView.setUint32(codeViewEntry.pointerToRawData + 4, 0, true);
  legacyView.setUint32(codeViewEntry.pointerToRawData + 8, 1, true);
  legacyView.setUint32(codeViewEntry.pointerToRawData + 12, 2, true);
  legacyCodeView.set(legacyPath, codeViewEntry.pointerToRawData + 16);
  legacyCodeView.fill(
    0,
    codeViewEntry.pointerToRawData + 16 + legacyPath.length,
    codeViewEntry.pointerToRawData + codeViewEntry.sizeOfData
  );
  const legacyPdb = parsePE(legacyCodeView).debugDirectoryEntries.find((entry) => entry.type === 2).codeView;
  assert.equal(legacyPdb.format, "NB10");
  assert.equal(legacyPdb.age, 2);
  assert.match(legacyPdb.path, /Fixture\.pdb$/);
  const debugOffset = parsed.rvaToOffset(parsed.directories[6].rva);

  const outOfFileData = Uint8Array.from(fixture);
  new DataView(outOfFileData.buffer).setUint32(debugOffset + 24, outOfFileData.length - 1, true);
  assert.throws(() => parsePE(outOfFileData), /Debug data raw range is outside file data/);

  const malformedSize = Uint8Array.from(fixture);
  const directorySizeOffset = parsed.optionalHeaderOffset +
    (parsed.optionalHeaderMagic === 0x10b ? 96 : 112) + 6 * 8 + 4;
  new DataView(malformedSize.buffer).setUint32(directorySizeOffset, 27, true);
  assert.throws(() => parsePE(malformedSize), /multiple of IMAGE_DEBUG_DIRECTORY/);

  const malformedCodeView = Uint8Array.from(fixture);
  malformedCodeView[codeViewEntry.pointerToRawData + codeViewEntry.sizeOfData - 1] = 0x41;
  assert.throws(() => parsePE(malformedCodeView), /CodeView PDB path is not null-terminated/);
});

test("PE header expansion relocates debug data raw pointers", () => {
  const input = makePE32PlusWithDebugDirectory();
  const pe = parsePE(input);
  const debugEntry = pe.debugDirectoryEntries[0];
  const cli = { offset: 0x280, flags: 0 };
  const rewritten = appendPeSection(input, pe, cli, Uint8Array.from([0x42]), 0, 1);
  assert.equal(rewritten.headerExpansion, 0x200);
  const reparsed = parsePE(rewritten.bytes);
  assert.equal(reparsed.sections[2].rawPointer, pe.sections[2].rawPointer + 0x200);
  assert.equal(reparsed.debugDirectoryEntries[0].addressOfRawData, debugEntry.addressOfRawData);
  assert.equal(reparsed.debugDirectoryEntries[0].pointerToRawData, debugEntry.pointerToRawData + 0x200);
});

test("PE parser rejects out-of-file and overlapping section ranges", () => {
  const parsed = parsePE(fixture);
  assert.ok(parsed.sections.length > 1);
  const outOfFile = Uint8Array.from(fixture);
  const beyondFile = Math.ceil(outOfFile.length / parsed.fileAlignment) * parsed.fileAlignment;
  new DataView(outOfFile.buffer).setUint32(parsed.sectionOffset + 20, beyondFile, true);
  assert.throws(() => parsePE(outOfFile), /raw range is outside file data/);

  const overlapping = Uint8Array.from(fixture);
  new DataView(overlapping.buffer).setUint32(
    parsed.sectionOffset + 40 + 20,
    parsed.sections[0].rawPointer,
    true
  );
  assert.throws(() => parsePE(overlapping), /overlapping raw ranges/);

  const overlappingVirtual = Uint8Array.from(fixture);
  new DataView(overlappingVirtual.buffer).setUint32(
    parsed.sectionOffset + 40 + 12,
    parsed.sections[0].virtualAddress,
    true
  );
  assert.throws(() => parsePE(overlappingVirtual), /overlapping virtual ranges/);

  const overflowingVirtual = Uint8Array.from(fixture);
  const overflowingView = new DataView(overflowingVirtual.buffer);
  overflowingView.setUint32(parsed.sectionOffset + 8, 0x10000, true);
  overflowingView.setUint32(
    parsed.sectionOffset + 12,
    Math.floor(0xffffffff / parsed.sectionAlignment) * parsed.sectionAlignment,
    true
  );
  assert.throws(() => parsePE(overflowingVirtual), /virtual range overflows/);
});

test("PE parser rejects invalid section and file alignments", () => {
  const parsed = parsePE(fixture);
  const nonPowerOfTwo = Uint8Array.from(fixture);
  new DataView(nonPowerOfTwo.buffer).setUint32(parsed.optionalHeaderOffset + 36, 0x300, true);
  assert.throws(() => parsePE(nonPowerOfTwo), /alignments must be nonzero powers of two/);

  const inconsistent = Uint8Array.from(fixture);
  new DataView(inconsistent.buffer).setUint32(parsed.optionalHeaderOffset + 32, 0x100, true);
  assert.throws(() => parsePE(inconsistent), /alignments are inconsistent/);

  const unsupportedFileAlignment = Uint8Array.from(fixture);
  new DataView(unsupportedFileAlignment.buffer).setUint32(parsed.optionalHeaderOffset + 36, 0x100, true);
  assert.throws(() => parsePE(unsupportedFileAlignment), /outside the supported range/);
});

test("PE parser rejects misaligned section ranges and header sizes", () => {
  const parsed = parsePE(fixture);

  const unalignedVirtual = Uint8Array.from(fixture);
  new DataView(unalignedVirtual.buffer).setUint32(parsed.sectionOffset + 12,
    parsed.sections[0].virtualAddress + 1, true);
  assert.throws(() => parsePE(unalignedVirtual), /virtual address is not section-aligned/);

  const unalignedRaw = Uint8Array.from(fixture);
  new DataView(unalignedRaw.buffer).setUint32(parsed.sectionOffset + 20,
    parsed.sections[0].rawPointer + 1, true);
  assert.throws(() => parsePE(unalignedRaw), /raw range is not file-aligned/);

  const unalignedHeaders = Uint8Array.from(fixture);
  new DataView(unalignedHeaders.buffer).setUint32(parsed.optionalHeaderOffset + 60,
    parsed.sizeOfHeaders - 1, true);
  assert.throws(() => parsePE(unalignedHeaders), /sizes do not follow the declared alignments/);
});

test("assembly parser rejects ambiguous #~ and #- table streams", () => {
  const parsed = parseAssembly(fixture);
  const malformed = Uint8Array.from(fixture);
  const userStringNameOffset = Buffer.from(malformed).indexOf(Buffer.from("#US\0"));
  assert.ok(userStringNameOffset > parsed.metadataRoot.offset);
  malformed[userStringNameOffset + 1] = 0x2d;
  malformed[userStringNameOffset + 2] = 0;
  malformed[userStringNameOffset + 3] = 0;
  assert.throws(() => parseAssembly(malformed), /both #~ and #-/);
});

test("assembly parser validates metadata heap references across all tables", () => {
  const parsed = parseAssembly(fixture);
  const malformed = Uint8Array.from(fixture);
  const stringNameOffset = Buffer.from(malformed).indexOf(Buffer.from("#Strings\0"));
  assert.ok(stringNameOffset > parsed.metadataRoot.offset);
  new DataView(malformed.buffer).setUint32(stringNameOffset - 4, 1, true);
  assert.throws(() => parseAssembly(malformed), /outside #Strings/);
});

test("structural IL edits relocate method bodies and promote branches", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const method = assembly.methods.find((item) => item.name === "Dispose");
  const body = assembly.getMethodBody(method.rid);
  const branch = body.instructions.find((instruction) =>
    instruction.operand?.kind === "branch" &&
    instruction.opcode.operand === "branch1" &&
    instruction.operand.targetOffset > instruction.offset
  );
  assert.ok(branch, "fixture should contain a forward short branch");
  const targetOffset = branch.operand.targetOffset;
  const branchName = branch.opcode.name.replace(/\.s$/, "");
  assembly.insertInstruction(method.rid, targetOffset, "nop");
  const currentInstructions = assembly.getInstructions(method.rid);
  const currentBranch = currentInstructions.find((instruction) => instruction.opcode.name.replace(/\.s$/, "") === branchName);
  const stableTarget = currentInstructions.find((instruction) => instruction.offset === currentBranch.operand.targetOffset);
  for (let index = 1; index < 130; index++) {
    assembly.insertInstruction(method.rid, stableTarget.offset, "nop");
  }
  const rewritten = assembly.serialize();
  const reparsed = parseAssembly(rewritten);
  assert.equal(reparsed.pe.sectionCount, assembly.pe.sectionCount + 1);
  const rewrittenMethod = reparsed.methods.find((item) => item.name === "Dispose");
  const rewrittenBody = reparsed.getMethodBody(rewrittenMethod.rid);
  assert.equal(rewrittenBody.format, "fat");
  assert.ok(rewrittenBody.instructions.some((instruction) =>
    instruction.opcode.name === branchName &&
    instruction.opcode.operand === "branch4"
  ));
});

test("IL offset changes are refused when a PE debug directory is present", () => {
  const assembly = parseAssembly(fixture);
  assert.ok(assembly.pe.directories[6]?.size > 0);
  const method = assembly.methods.find((item) => item.name === "Answer");
  assert.throws(() => assembly.insertInstruction(method.rid, 0, "nop"),
    /Instruction-offset changes cannot be combined with PE debug information/);
  assert.equal(assembly.modified, false);
  assert.equal(Buffer.compare(assembly.serialize(), fixture), 0);
});

test("MemberRef additions append heap values and rebuild metadata with stable tokens", () => {
  const assembly = parseAssembly(fixture);
  const originalCount = assembly.memberRefs.length;
  const parent = assembly.tables.get("MemberRef").at(-1).Class.target;
  assert.ok(parent);
  const token = assembly.addMemberRef({
    parent: { table: parent.tableName, rid: parent.rid },
    name: "AddedMember",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  assert.equal(token, 0x0a000000 + originalCount + 1);
  const output = assembly.serialize();
  const reparsed = parseAssembly(output);
  assert.equal(reparsed.memberRefs.length, originalCount + 1);
  assert.equal(reparsed.memberRefs.at(-1).name, "AddedMember");
  assert.deepEqual([...reparsed.memberRefs.at(-1).signature], [0x20, 0x00, 0x0e]);
});

test("MemberRef replacement updates supported fields and preserves row identity", () => {
  const assembly = parseAssembly(fixture);
  const parent = assembly.memberRefs.at(-1).parent;
  const token = assembly.addMemberRef({
    parent: { table: parent.tableName, rid: parent.rid },
    name: "ReplaceMember",
    signature: Uint8Array.from([0x00, 0x00, 0x01])
  });
  const rid = token & 0x00ffffff;
  assembly.replaceMemberRef(rid, {
    name: "ReplacedMember",
    signature: Uint8Array.from([0x00, 0x00, 0x0e])
  });
  assert.throws(() => assembly.replaceMemberRef(rid, {
    signature: Uint8Array.from([0x0f])
  }), /Unsupported method calling convention/);
  assert.equal(assembly.memberRefs[rid - 1].name, "ReplacedMember");
  assert.deepEqual([...assembly.memberRefs[rid - 1].signature], [0x00, 0x00, 0x0e]);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.memberRefs[rid - 1].name, "ReplacedMember");
  assert.deepEqual([...reparsed.memberRefs[rid - 1].signature], [0x00, 0x00, 0x0e]);
  assert.equal(token, 0x0a000000 + reparsed.memberRefs[rid - 1].rid);
});

test("MemberRef removal rejects live references and remaps surviving tokens", () => {
  const referencedAssembly = parseAssembly(withoutDebugDirectory());
  const referenced = referencedAssembly.memberRefs.find((member) => member.name === ".ctor");
  assert.ok(referenced);
  assert.throws(() => referencedAssembly.removeMemberRef(referenced.rid), /is referenced by/);
  assert.equal(referencedAssembly.modified, false);

  const assembly = parseAssembly(withoutDebugDirectory());
  const parent = assembly.memberRefs.at(-1).parent;
  const firstToken = assembly.addMemberRef({
    parent: { table: parent.tableName, rid: parent.rid },
    name: "RemoveMember",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  const secondToken = assembly.addMemberRef({
    parent: { table: parent.tableName, rid: parent.rid },
    name: "KeepMember",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  const callSite = assembly.methods.flatMap((method) =>
    assembly.getInstructions(method.rid).map((instruction) => ({ method, instruction }))
  ).find(({ instruction }) =>
    instruction.opcode.name === "call" &&
    (instruction.operand.value >>> 24) === 0x0a
  );
  assert.ok(callSite);
  assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, secondToken);
  const tokenMap = assembly.removeMemberRef(firstToken & 0x00ffffff);
  assert.equal(tokenMap.get(secondToken), firstToken);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.memberRefs.some((member) => member.name === "RemoveMember"), false);
  assert.equal(reparsed.memberRefs.at(-1).name, "KeepMember");
  assert.equal(reparsed.getInstructions(callSite.method.rid).find((instruction) =>
    instruction.offset === callSite.instruction.offset
  ).operand.value, tokenMap.get(secondToken));
});

test("TypeRef additions append names and can parent a new MemberRef", () => {
  const assembly = parseAssembly(fixture);
  const scope = assembly.tables.get("TypeRef").at(-1).ResolutionScope.target;
  const typeToken = assembly.addTypeRef({
    scope: scope ? { table: scope.tableName, rid: scope.rid } : null,
    name: "AddedExternalType",
    namespace: "JsILNET.Added"
  });
  assert.equal(typeToken, 0x01000000 + assembly.typeRefs.length);
  const typeRid = typeToken & 0x00ffffff;
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeRef", rid: typeRid },
    name: "AddedMethod",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.typeRefs.at(-1).rid, typeRid);
  assert.equal(reparsed.typeRefs.at(-1).name, "AddedExternalType");
  assert.equal(reparsed.typeRefs.at(-1).namespace, "JsILNET.Added");
  assert.equal(reparsed.memberRefs.at(-1).rid, memberToken & 0x00ffffff);
  assert.deepEqual(reparsed.memberRefs.at(-1).parent, {
    table: 1,
    tableName: "TypeRef",
    rid: typeRid
  });
});

test("TypeRef replacement updates names and resolution scope without changing its token", () => {
  const assembly = parseAssembly(fixture);
  const typeRef = assembly.typeRefs.at(-1);
  const rid = typeRef.rid;
  const scope = { table: "AssemblyRef", rid: assembly.assemblyRefs[0].rid };
  assembly.replaceTypeRef(rid, {
    scope,
    name: "ReplacedType",
    namespace: "JsILNET.Replaced"
  });
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.typeRefs[rid - 1].name, "ReplacedType");
  assert.equal(reparsed.typeRefs[rid - 1].namespace, "JsILNET.Replaced");
  assert.deepEqual(reparsed.typeRefs[rid - 1].resolutionScope, {
    table: 35,
    tableName: "AssemblyRef",
    rid: scope.rid
  });
  assert.equal(reparsed.typeRefs[rid - 1].rid, typeRef.rid);
});

test("ModuleRef rows can be appended and used as TypeRef scopes", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const moduleToken = assembly.addModuleRef({ name: "NativeLibrary" });
  const moduleRid = moduleToken & 0x00ffffff;
  assert.equal(moduleToken >>> 24, 0x1a);
  const type = assembly.insertTypeRefSorted({
    scope: { table: "ModuleRef", rid: moduleRid },
    name: "NativeType",
    namespace: "Native"
  });
  assembly.replaceModuleRef(moduleRid, "NativeLibraryUpdated");
  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.moduleRefs.at(-1), { rid: moduleRid, name: "NativeLibraryUpdated" });
  assert.deepEqual(reparsed.typeRefs.find((item) => item.name === "NativeType").resolutionScope, {
    table: 26,
    tableName: "ModuleRef",
    rid: moduleRid
  });
  assert.equal(type.token >>> 24, 0x01);
});

test("ModuleRef removal rejects live scopes and remaps surviving scope RIDs", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.tables.sorted &= ~(1n << 1n);
  const firstToken = assembly.addModuleRef({ name: "FirstModule" });
  const secondToken = assembly.addModuleRef({ name: "SecondModule" });
  const typeToken = assembly.addTypeRef({
    scope: { table: "ModuleRef", rid: secondToken & 0x00ffffff },
    name: "ScopedType",
    namespace: "Native"
  });
  const tokenMap = assembly.removeModuleRef(firstToken & 0x00ffffff);
  assert.equal(tokenMap.get(secondToken), secondToken - 1);
  assert.throws(() => assembly.removeModuleRef(1), /referenced by TypeRef\.ResolutionScope/);
  const reparsed = parseAssembly(assembly.serialize());
  const typeRef = reparsed.typeRefs.find((item) => item.name === "ScopedType");
  assert.equal(typeRef.rid, typeToken & 0x00ffffff);
  assert.deepEqual(typeRef.resolutionScope, {
    table: 26,
    tableName: "ModuleRef",
    rid: 1
  });
  assert.deepEqual(reparsed.moduleRefs, [{ rid: 1, name: "SecondModule" }]);

  const sortedAssembly = parseAssembly(withoutDebugDirectory());
  const earlierModule = sortedAssembly.addModuleRef({ name: "EarlierModule" });
  const laterModule = sortedAssembly.addModuleRef({ name: "LaterModule" });
  sortedAssembly.insertTypeRefSorted({
    scope: { table: "ModuleRef", rid: laterModule & 0x00ffffff },
    name: "SortedScopeType",
    namespace: "Native"
  });
  assert.throws(() => sortedAssembly.removeModuleRef(earlierModule & 0x00ffffff),
    /would violate sorted TypeRef order/);
  assert.equal(sortedAssembly.moduleRefs.length, 2);
});

test("AssemblyRef additions append version and heap data and can scope TypeRefs", () => {
  const assembly = parseAssembly(fixture);
  const originalCount = assembly.assemblyRefs.length;
  const token = assembly.addAssemblyRef({
    name: "Added.Dependency",
    culture: "en-US",
    version: [1, 2, 3, 4],
    flags: 1,
    publicKeyOrToken: Uint8Array.from([0xaa, 0xbb]),
    hashValue: Uint8Array.from([0x11, 0x22])
  });
  const rid = originalCount + 1;
  assert.equal(token, 0x23000000 + rid);
  const typeToken = assembly.addTypeRef({
    scope: { table: "AssemblyRef", rid },
    name: "ExternalType",
    namespace: "Added"
  });

  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.assemblyRefs.at(-1), {
    rid,
    name: "Added.Dependency",
    culture: "en-US",
    version: [1, 2, 3, 4],
    publicKeyOrToken: Uint8Array.from([0xaa, 0xbb])
  });
  const addedType = reparsed.typeRefs.find((type) => type.rid === (typeToken & 0x00ffffff));
  assert.deepEqual(addedType.resolutionScope, { table: 35, tableName: "AssemblyRef", rid });
});

test("assembly processor and OS tables support validated CRUD and round trips", () => {
  const assembly = parseAssembly(fixture);
  const processorOne = assembly.addAssemblyProcessor({ processor: 0x14c });
  const processorTwo = assembly.addAssemblyProcessor({ processor: 0x8664 });
  assembly.replaceAssemblyProcessor(processorTwo, { processor: 0xaa64 });
  assembly.removeAssemblyProcessor(processorOne);

  const osOne = assembly.addAssemblyOS({ platformId: 1, majorVersion: 10, minorVersion: 0 });
  const osTwo = assembly.addAssemblyOS({ platformId: 2, majorVersion: 6, minorVersion: 3 });
  assembly.replaceAssemblyOS(osTwo, { majorVersion: 11 });
  assembly.removeAssemblyOS(osOne);

  const referenceProcessorOne = assembly.addAssemblyRefProcessor({
    processor: 0x14c,
    assemblyRefRid: 1
  });
  const referenceProcessorTwo = assembly.addAssemblyRefProcessor({
    processor: 0x8664,
    assemblyRefRid: 2
  });
  assembly.replaceAssemblyRefProcessor(referenceProcessorTwo, {
    processor: 0xaa64,
    assemblyRefRid: 1
  });
  assembly.removeAssemblyRefProcessor(referenceProcessorOne);

  const referenceOsOne = assembly.addAssemblyRefOS({
    platformId: 1,
    majorVersion: 10,
    minorVersion: 0,
    assemblyRefRid: 1
  });
  const referenceOsTwo = assembly.addAssemblyRefOS({
    platformId: 2,
    majorVersion: 6,
    minorVersion: 3,
    assemblyRefRid: 2
  });
  assembly.replaceAssemblyRefOS(referenceOsTwo, {
    platformId: 3,
    assemblyRefRid: 1
  });
  assembly.removeAssemblyRefOS(referenceOsOne);

  assert.throws(() => assembly.addAssemblyProcessor({ processor: -1 }), /unsigned 32-bit/);
  assert.throws(() => assembly.addAssemblyRefOS({
    platformId: 0,
    majorVersion: 0,
    minorVersion: 0,
    assemblyRefRid: 0
  }), /Invalid AssemblyRef row ID/);
  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.tables.get(33).map(({ Processor }) => Processor), [0xaa64]);
  assert.deepEqual(reparsed.tables.get(34).map(({ OSPlatformId, OSMajorVersion, OSMinorVersion }) =>
    [OSPlatformId, OSMajorVersion, OSMinorVersion]), [[2, 11, 3]]);
  assert.deepEqual(reparsed.tables.get(36).map(({ Processor, AssemblyRef }) =>
    [Processor, AssemblyRef.rid]), [[0xaa64, 1]]);
  assert.deepEqual(reparsed.tables.get(37).map(({ OSPlatformId, OSMajorVersion, OSMinorVersion, AssemblyRef }) =>
    [OSPlatformId, OSMajorVersion, OSMinorVersion, AssemblyRef.rid]), [[3, 6, 3, 1]]);

  const remapAssembly = parseAssembly(withoutDebugDirectory());
  const firstRefRid = (remapAssembly.addAssemblyRef({ name: "First.Platform.Ref" }) & 0x00ffffff);
  const secondRefRid = (remapAssembly.addAssemblyRef({ name: "Second.Platform.Ref" }) & 0x00ffffff);
  remapAssembly.addAssemblyRefProcessor({ processor: 0x8664, assemblyRefRid: secondRefRid });
  remapAssembly.addAssemblyRefOS({
    platformId: 1,
    majorVersion: 10,
    minorVersion: 0,
    assemblyRefRid: secondRefRid
  });
  remapAssembly.removeAssemblyRef(firstRefRid);
  const remapped = parseAssembly(remapAssembly.serialize());
  assert.equal(remapped.tables.get(36).at(-1).AssemblyRef.rid, secondRefRid - 1);
  assert.equal(remapped.tables.get(37).at(-1).AssemblyRef.rid, secondRefRid - 1);
});

test("AssemblyRef replacement updates manifest binding fields in place", () => {
  const assembly = parseAssembly(fixture);
  const token = assembly.addAssemblyRef({ name: "OriginalReference" });
  const rid = token & 0x00ffffff;
  assembly.replaceAssemblyRef(rid, {
    name: "UpdatedReference",
    culture: "en-US",
    version: [4, 5, 6, 7],
    flags: 1,
    publicKeyOrToken: Uint8Array.from([1, 2, 3]),
    hashValue: Uint8Array.from([4, 5])
  });
  assert.throws(() => assembly.replaceAssemblyRef(rid, { version: [1, 2, 3] }),
    /version must contain four/);
  assert.equal(assembly.assemblyRefs.at(-1).name, "UpdatedReference");
  assert.deepEqual(assembly.assemblyRefs.at(-1).version, [4, 5, 6, 7]);
  assert.deepEqual([...assembly.assemblyRefs.at(-1).publicKeyOrToken], [1, 2, 3]);
  const row = assembly.tables.row(35, rid);
  assert.equal(row.Flags, 1);
  assert.deepEqual([...assembly.heaps.getBlob(row.HashValue)], [4, 5]);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.assemblyRefs.at(-1).culture, "en-US");
  assert.deepEqual(reparsed.assemblyRefs.at(-1).version, [4, 5, 6, 7]);
  assert.deepEqual([...reparsed.assemblyRefs.at(-1).publicKeyOrToken], [1, 2, 3]);
  assert.deepEqual([...reparsed.heaps.getBlob(reparsed.tables.row(35, rid).HashValue)], [4, 5]);
});

test("AssemblyRef removal remaps later scopes and rejects referenced rows", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const firstRid = assembly.assemblyRefs.length + 1;
  const firstToken = assembly.addAssemblyRef({ name: "Unused.Dependency" });
  const secondToken = assembly.addAssemblyRef({ name: "Scoped.Dependency" });
  const secondRid = secondToken & 0x00ffffff;
  assembly.tables.sorted &= ~(1n << 1n);
  const typeToken = assembly.addTypeRef({
    scope: { table: "AssemblyRef", rid: secondRid },
    name: "ScopedType",
    namespace: "Added"
  });
  assembly.addManifestResource({
    name: "ScopedAssemblyResource",
    implementation: { table: "AssemblyRef", rid: secondRid }
  });

  const tokenMap = assembly.removeAssemblyRef(firstRid);
  assert.equal(firstToken, 0x23000000 + firstRid);
  assert.equal(tokenMap.get(secondToken), secondToken - 1);
  const typeRid = typeToken & 0x00ffffff;
  assert.deepEqual(assembly.typeRefs[typeRid - 1].resolutionScope, {
    table: 35,
    tableName: "AssemblyRef",
    rid: firstRid
  });
  assert.deepEqual(assembly.resources.at(-1).implementation, {
    table: 35,
    tableName: "AssemblyRef",
    rid: firstRid
  });
  assert.throws(() => assembly.removeAssemblyRef(firstRid), /referenced by TypeRef\.ResolutionScope/);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.assemblyRefs.at(-1).name, "Scoped.Dependency");
  assert.deepEqual(reparsed.typeRefs[typeRid - 1].resolutionScope, {
    table: 35,
    tableName: "AssemblyRef",
    rid: firstRid
  });
  assert.deepEqual(reparsed.resources.at(-1).implementation, {
    table: 35,
    tableName: "AssemblyRef",
    rid: firstRid
  });
});

test("TypeSpec additions validate signatures and can parent MemberRefs", () => {
  const assembly = parseAssembly(fixture);
  const typeRefRid = assembly.typeRefs.find((type) => type.name === "IDisposable").rid;
  const replacementTypeRefRid = assembly.typeRefs.find((type) => type.name === "Object").rid;
  const signature = Uint8Array.from([0x12, typeRefRid * 4 + 1]);
  const token = assembly.addTypeSpec({ signature });
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeSpec", rid: token & 0x00ffffff },
    name: "AddedOnTypeSpec",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  const replacementSignature = Uint8Array.from([0x12, replacementTypeRefRid * 4 + 1]);
  assembly.replaceTypeSpecSignature(token & 0x00ffffff, replacementSignature);
  assert.throws(() => assembly.replaceTypeSpecSignature(token & 0x00ffffff, Uint8Array.from([0x12, 0])),
    /cannot be nil/);
  assert.deepEqual(assembly.typeSpecs.at(-1).signature, replacementSignature);
  const reparsed = parseAssembly(assembly.serialize());
  const typeSpec = reparsed.typeSpecs.at(-1);
  assert.equal(token, 0x1b000000 + typeSpec.rid);
  assert.deepEqual(typeSpec.signature, replacementSignature);
  assert.deepEqual(typeSpec.parsedSignature, {
    kind: "class",
    type: { table: 1, tableName: "TypeRef", rid: replacementTypeRefRid }
  });
  assert.equal(reparsed.memberRefs.at(-1).parent.table, 27);
  assert.equal(memberToken, 0x0a000000 + reparsed.memberRefs.at(-1).rid);
  assert.throws(() => assembly.addTypeSpec({ signature: Uint8Array.from([0x12, 0]) }), /cannot be nil/);
});

test("TypeSpec generic contexts validate local arity and MemberRef variables", () => {
  const assembly = parseAssembly(fixture);
  const genericType = assembly.types.find((type) => type.name === "Sample`1");
  assert.ok(genericType);
  const genericTypeToken = encodeCodedIndex(2, genericType.rid, "TypeDefOrRef");
  const typeSpecSignature = Uint8Array.from([
    0x15, 0x12, ...appendCompressedUInt(genericTypeToken), 0x01, 0x13, 0x00
  ]);
  const typeSpecToken = assembly.addTypeSpec({ signature: typeSpecSignature });
  const typeSpecRid = typeSpecToken & 0x00ffffff;
  const validMemberSignature = Uint8Array.from([0x00, 0x00, 0x13, 0x00]);
  assembly.addMemberRef({
    parent: { table: "TypeSpec", rid: typeSpecRid },
    name: "GenericContext",
    signature: validMemberSignature
  });
  assert.throws(() => assembly.addMemberRef({
    parent: { table: "TypeSpec", rid: typeSpecRid },
    name: "InvalidGenericContext",
    signature: Uint8Array.from([0x00, 0x00, 0x13, 0x01])
  }), /Type generic variable !1 exceeds its declaring type's arity/);
  assert.throws(() => assembly.addTypeSpec({
    signature: Uint8Array.from([
      0x15, 0x12, ...appendCompressedUInt(genericTypeToken),
      0x02, 0x13, 0x00, 0x13, 0x00
    ])
  }), /arguments for TypeDef arity 1/);

  const incompatibleReplacement = Uint8Array.from([
    0x12, ...appendCompressedUInt(genericTypeToken)
  ]);
  assert.throws(() => assembly.replaceTypeSpecSignature(
    typeSpecRid,
    incompatibleReplacement
  ), /Type generic variable !0 exceeds its declaring type's arity/);
  assert.deepEqual(assembly.typeSpecs[typeSpecRid - 1]?.signature, typeSpecSignature);
});

test("TypeSpec generic variables are checked in TypeDef base-type context", () => {
  function serializedWithBaseTypeArgument(typeVariableIndex) {
    const assembly = parseAssembly(fixture);
    const genericType = assembly.types.find((type) => type.name === "Sample`1");
    const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
    assert.ok(genericType && typeRef);
    const signature = Uint8Array.from([
      0x15, 0x12, typeRef.rid * 4 + 1, 0x01, 0x13, typeVariableIndex
    ]);
    const typeSpecRid = assembly.addTypeSpec({ signature }) & 0x00ffffff;
    const target = { table: 27, tableName: "TypeSpec", rid: typeSpecRid };
    assembly.tables.row("TypeDef", genericType.rid).Extends = {
      raw: encodeCodedIndex(27, typeSpecRid, "TypeDefOrRef"),
      target
    };
    return assembly.serialize();
  }

  assert.doesNotThrow(() => parseAssembly(serializedWithBaseTypeArgument(0)));
  assert.throws(() => parseAssembly(serializedWithBaseTypeArgument(1)),
    /TypeSpec generic variable !1 exceeds its declaring type's arity/);
});

test("TypeSpec generic variables in constraints use the owning method context", () => {
  function serializeConstraintTypeSpec(methodVariableIndex) {
    const assembly = parseAssembly(fixture);
    assembly.replaceMethodSignature(9, Uint8Array.from([0x10, 0x01, 0x00, 0x01]));
    const genericParamToken = assembly.addGenericParam({
      owner: { table: "MethodDef", rid: 9 },
      name: "T"
    });
    const typeSpecToken = assembly.addTypeSpec({
      signature: Uint8Array.from([0x1e, methodVariableIndex])
    });
    assembly.addGenericParamConstraint({
      ownerRid: genericParamToken & 0x00ffffff,
      constraint: { table: "TypeSpec", rid: typeSpecToken & 0x00ffffff }
    });
    return assembly.serialize();
  }

  assert.doesNotThrow(() => parseAssembly(serializeConstraintTypeSpec(0)));
  assert.throws(() => parseAssembly(serializeConstraintTypeSpec(1)),
    /TypeSpec generic variable !!1 exceeds its declaring method's arity/);
});

test("TypeSpec generic variables in field signatures use their declaring type context", () => {
  const assembly = parseAssembly(fixture);
  const genericType = assembly.types.find((type) => type.name === "Sample`1");
  const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(genericType?.fields[0] && typeRef);
  const typeSpecToken = assembly.addTypeSpec({
    signature: Uint8Array.from([0x15, 0x12, typeRef.rid * 4 + 1, 0x01, 0x13, 0x01])
  });
  const field = genericType.fields[0];
  const originalSignature = field.signature;
  const typeSpecReference = encodeCodedIndex(27, typeSpecToken & 0x00ffffff, "TypeDefOrRef");
  assert.throws(() => assembly.replaceFieldSignature(field.rid, Uint8Array.from([
    0x06, 0x12, ...appendCompressedUInt(typeSpecReference)
  ])), /TypeSpec generic variable !1 exceeds its declaring type's arity/);
  assert.deepEqual(field.signature, originalSignature);
});

test("TypeSpec replacement revalidates nested generic-context use sites atomically", () => {
  const assembly = parseAssembly(fixture);
  const genericType = assembly.types.find((type) => type.name === "Sample`1");
  assert.ok(genericType?.fields[0]);
  const innerTypeSpecToken = assembly.addTypeSpec({ signature: Uint8Array.from([0x13, 0x00]) });
  const innerTypeSpecRid = innerTypeSpecToken & 0x00ffffff;
  const outerTypeSpecToken = assembly.addTypeSpec({
    signature: Uint8Array.from([
      0x12,
      ...appendCompressedUInt(encodeCodedIndex(27, innerTypeSpecRid, "TypeDefOrRef"))
    ])
  });
  const outerTypeSpecRid = outerTypeSpecToken & 0x00ffffff;
  assembly.replaceFieldSignature(genericType.fields[0].rid, Uint8Array.from([
    0x06,
    0x12,
    ...appendCompressedUInt(encodeCodedIndex(27, outerTypeSpecRid, "TypeDefOrRef"))
  ]));
  const fieldEditOutput = assembly.serialize();

  assert.throws(() => assembly.replaceTypeSpecSignature(
    innerTypeSpecRid,
    Uint8Array.from([0x13, 0x01])
  ), /TypeSpec generic variable !1 exceeds its declaring type's arity/);
  assert.deepEqual(assembly.typeSpecs[innerTypeSpecRid - 1].signature, Uint8Array.from([0x13, 0x00]));
  assert.deepEqual(assembly.serialize(), fieldEditOutput);

  const methodAssembly = parseAssembly(fixture);
  methodAssembly.replaceMethodSignature(9, Uint8Array.from([0x10, 0x01, 0x00, 0x01]));
  const genericParamToken = methodAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "T"
  });
  const methodTypeSpecToken = methodAssembly.addTypeSpec({
    signature: Uint8Array.from([0x1e, 0x00])
  });
  methodAssembly.addGenericParamConstraint({
    ownerRid: genericParamToken & 0x00ffffff,
    constraint: { table: "TypeSpec", rid: methodTypeSpecToken & 0x00ffffff }
  });
  const constraintEditOutput = methodAssembly.serialize();
  assert.throws(() => methodAssembly.replaceTypeSpecSignature(
    methodTypeSpecToken & 0x00ffffff,
    Uint8Array.from([0x1e, 0x01])
  ), /TypeSpec generic variable !!1 exceeds its declaring method's arity/);
  assert.deepEqual(methodAssembly.serialize(), constraintEditOutput);

  const callSiteAssembly = parseAssembly(fixture);
  const callerType = callSiteAssembly.types.find((type) => type.name === "Sample`1");
  const callSite = callerType?.methods.map((method) => ({
    method,
    instruction: callSiteAssembly.getInstructions(method.rid)
      .find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  const externalType = callSiteAssembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(callerType && callSite && externalType);
  const invalidCallTypeSpecToken = callSiteAssembly.addTypeSpec({
    signature: Uint8Array.from([0x13, 0x01])
  });
  const genericMethodToken = callSiteAssembly.addMemberRef({
    parent: { table: "TypeRef", rid: externalType.rid },
    name: "GenericMethod",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00])
  });
  const invalidMethodSpecToken = callSiteAssembly.addMethodSpec({
    method: { table: "MemberRef", rid: genericMethodToken & 0x00ffffff },
    instantiation: Uint8Array.from([
      0x0a,
      0x01,
      0x12,
      ...appendCompressedUInt(encodeCodedIndex(
        27, invalidCallTypeSpecToken & 0x00ffffff, "TypeDefOrRef"
      ))
    ])
  });
  const originalCallToken = callSite.instruction.operand.value;
  assert.throws(() => callSiteAssembly.setInstructionOperand(
    callSite.method.rid,
    callSite.instruction.offset,
    invalidMethodSpecToken
  ), /TypeSpec generic variable !1 exceeds its declaring type's arity/);
  assert.equal(callSite.instruction.operand.value, originalCallToken);

  const callTypeSpecToken = callSiteAssembly.addTypeSpec({
    signature: Uint8Array.from([0x13, 0x00])
  });
  const methodSpecToken = callSiteAssembly.addMethodSpec({
    method: { table: "MemberRef", rid: genericMethodToken & 0x00ffffff },
    instantiation: Uint8Array.from([
      0x0a,
      0x01,
      0x12,
      ...appendCompressedUInt(encodeCodedIndex(
        27, callTypeSpecToken & 0x00ffffff, "TypeDefOrRef"
      ))
    ])
  });
  callSiteAssembly.setInstructionOperand(
    callSite.method.rid,
    callSite.instruction.offset,
    methodSpecToken
  );
  const methodSpecCallOutput = callSiteAssembly.serialize();
  assert.throws(() => callSiteAssembly.replaceMethodSpecInstantiation(
    methodSpecToken & 0x00ffffff,
    Uint8Array.from([
      0x0a,
      0x01,
      0x12,
      ...appendCompressedUInt(encodeCodedIndex(
        27, invalidCallTypeSpecToken & 0x00ffffff, "TypeDefOrRef"
      ))
    ])
  ), /TypeSpec generic variable !1 exceeds its declaring type's arity/);
  assert.deepEqual(callSiteAssembly.serialize(), methodSpecCallOutput);
  assert.throws(() => callSiteAssembly.replaceTypeSpecSignature(
    callTypeSpecToken & 0x00ffffff,
    Uint8Array.from([0x13, 0x01])
  ), /TypeSpec generic variable !1 exceeds its declaring type's arity/);
  assert.deepEqual(callSiteAssembly.serialize(), methodSpecCallOutput);
});

test("TypeSpec removal rejects live references and remaps signatures and CIL tokens", () => {
  const referencedAssembly = parseAssembly(withoutDebugDirectory());
  const referencedTypeSpec = referencedAssembly.addTypeSpec({ signature: Uint8Array.from([0x08]) });
  const genericParam = referencedAssembly.genericParams.find((parameter) => parameter.owner.table === 2);
  assert.ok(genericParam);
  referencedAssembly.addGenericParamConstraint({
    ownerRid: genericParam.rid,
    constraint: { table: "TypeSpec", rid: referencedTypeSpec & 0x00ffffff }
  });
  assert.throws(() =>
    referencedAssembly.removeTypeSpec(referencedTypeSpec & 0x00ffffff),
  /is referenced by/);
  assert.equal(referencedAssembly.modified, true);

  const assembly = parseAssembly(withoutDebugDirectory());
  const typeRefRid = assembly.typeRefs[0].rid;
  const signature = Uint8Array.from([
    0x12,
    ...appendCompressedUInt(encodeCodedIndex(1, typeRefRid, "TypeDefOrRef"))
  ]);
  const removedToken = assembly.addTypeSpec({ signature });
  const survivingToken = assembly.addTypeSpec({ signature });
  const fieldSignature = Uint8Array.from([
    0x06,
    0x12,
    ...appendCompressedUInt(encodeCodedIndex(27, survivingToken & 0x00ffffff, "TypeDefOrRef"))
  ]);
  const fieldBlob = appendBlobHeap(assembly._heapStreams.get("#Blob"), fieldSignature);
  assembly._heapStreams.set("#Blob", fieldBlob.heap);
  assembly.heaps = new MetadataHeaps(new Map([...assembly._heapStreams].map(([name, bytes]) =>
    [name, { bytes }]
  )));
  assembly.tables.row(4, 2).Signature = fieldBlob.index;
  const castSite = assembly.methods.flatMap((method) =>
    assembly.getInstructions(method.rid).map((instruction) => ({ method, instruction }))
  ).find(({ instruction }) => instruction.opcode.name === "castclass");
  assert.ok(castSite);
  assembly.setInstructionOperand(castSite.method.rid, castSite.instruction.offset, survivingToken);
  const tokenMap = assembly.removeTypeSpec(removedToken & 0x00ffffff);
  assert.equal(tokenMap.get(survivingToken), removedToken);

  const reparsed = parseAssembly(assembly.serialize());
  const fieldType = parseSignature(reparsed.heaps.getBlob(reparsed.tables.row(4, 2).Signature)).type.type;
  assert.equal(fieldType.table, 27);
  assert.equal(fieldType.rid, tokenMap.get(survivingToken) & 0x00ffffff);
  assert.equal(reparsed.getInstructions(castSite.method.rid).find((instruction) =>
    instruction.offset === castSite.instruction.offset
  ).operand.value, tokenMap.get(survivingToken));
});

test("TypeSpec removal rejects and remaps catch-clause tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const removedToken = assembly.addTypeSpec({ signature: Uint8Array.from([0x08]) });
  const survivingToken = assembly.addTypeSpec({ signature: Uint8Array.from([0x09]) });
  setCatchClauseToken(assembly, removedToken);
  assert.throws(
    () => assembly.removeTypeSpec(removedToken & 0x00ffffff),
    /referenced by a catch clause/
  );

  setCatchClauseToken(assembly, survivingToken);
  const tokenMap = assembly.removeTypeSpec(removedToken & 0x00ffffff);
  const reparsed = parseAssembly(assembly.serialize());
  const method = reparsed.methods.find((candidate) => candidate.name === "Finally");
  assert.equal(
    reparsed.getMethodBody(method.rid).sections[0].clauses[0].classTokenOrFilterOffset,
    tokenMap.get(survivingToken)
  );
});

test("generic MemberRefs can receive MethodSpec instantiations and IL tokens", () => {
  const assembly = parseAssembly(fixture);
  const parent = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeRef", rid: parent.rid },
    name: "GenericMethod",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00])
  });
  const methodToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x08])
  });
  assert.throws(() => assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x02, 0x08, 0x08])
  }), /does not match its generic method signature/);
  const callSite = assembly.methods.map((method) => ({
    method,
    instruction: assembly.getInstructions(method.rid).find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, methodToken);

  const reparsed = parseAssembly(assembly.serialize());
  const methodSpec = reparsed.methodSpecs.at(-1);
  assert.equal(methodToken, 0x2b000000 + methodSpec.rid);
  assert.equal(methodSpec.method.table, 10);
  assert.equal(methodSpec.method.rid, memberToken & 0x00ffffff);
  assert.deepEqual(methodSpec.parsedInstantiation.arguments[0], { kind: "primitive", elementType: 0x08 });
  const rewrittenCall = reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset);
  assert.equal(rewrittenCall.operand.value, methodToken);
});

test("MethodSpec rows reject non-instantiation signatures during assembly parsing", () => {
  const assembly = parseAssembly(fixture);
  const parent = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeRef", rid: parent.rid },
    name: "GenericMethod",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00])
  });
  const methodSpecToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x08])
  });
  const output = assembly.serialize();
  const parsed = parseAssembly(output);
  const rid = methodSpecToken & 0x00ffffff;
  const instantiationIndex = parsed.tables.row(43, rid).Instantiation;
  const blobHeapOffset = parsed.metadataRoot.streams.get("#Blob").offset;

  output[blobHeapOffset + instantiationIndex + 1] = 0x07;
  assert.throws(
    () => parseAssembly(output),
    new RegExp(`MethodSpec row ${rid} does not contain a method-instantiation signature`)
  );
});

test("method-body parsing validates MethodSpec generic variables at CIL call sites", () => {
  const assembly = parseAssembly(fixture);
  const callerType = assembly.types.find((type) => type.name === "Sample`1");
  const callSite = callerType?.methods.map((method) => ({
    method,
    instruction: assembly.getInstructions(method.rid).find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  const parent = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(callerType && callSite && parent);

  const typeSpecToken = assembly.addTypeSpec({
    signature: Uint8Array.from([0x1e, 0x00])
  });
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeRef", rid: parent.rid },
    name: "GenericMethod",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00])
  });
  const methodSpecToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([
      0x0a,
      0x01,
      0x12,
      ...appendCompressedUInt(encodeCodedIndex(
        27, typeSpecToken & 0x00ffffff, "TypeDefOrRef"
      ))
    ])
  });
  const bytes = assembly.serialize();
  const parsed = parseAssembly(bytes);
  const parsedCall = parsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset);
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .setUint32(parsedCall.operandOffset, methodSpecToken, true);

  assert.throws(
    () => parseAssembly(bytes).getMethodBody(callSite.method.rid),
    /TypeSpec generic variable !!0 exceeds its declaring method's arity/
  );
});

test("MethodSpec removal remaps later metadata and CIL tokens and rejects live targets", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const initialMethodSpecCount = assembly.methodSpecs.length;
  const parent = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const memberToken = assembly.addMemberRef({
    parent: { table: "TypeRef", rid: parent.rid },
    name: "GenericMethod",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00])
  });
  const firstToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x08])
  });
  const secondToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: memberToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x0e])
  });
  const callSite = assembly.methods.map((method) => ({
    method,
    instruction: assembly.getInstructions(method.rid).find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, secondToken);

  const attribute = assembly.customAttributes[0];
  const attributeRow = assembly.tables.row(12, attribute.rid);
  const originalParent = {
    ...attributeRow.Parent,
    target: attributeRow.Parent.target ? { ...attributeRow.Parent.target } : null
  };
  assembly.tables.sorted &= ~(1n << 12n);
  attributeRow.Parent.raw = encodeCodedIndex(43, secondToken & 0x00ffffff, "HasCustomAttribute");
  attributeRow.Parent.target = {
    table: 43,
    tableName: "MethodSpec",
    rid: secondToken & 0x00ffffff
  };
  attribute.parent = attributeRow.Parent.target;

  const removedRid = firstToken & 0x00ffffff;
  const tokenMap = assembly.removeMethodSpec(removedRid);
  assert.equal(tokenMap.get(secondToken), secondToken - 1);
  assert.ok(assembly.methodSpecs.some((item) =>
    item.rid === removedRid && item.parsedInstantiation.arguments[0].elementType === 0x0e
  ));
  assert.deepEqual(attribute.parent, {
    table: 43,
    tableName: "MethodSpec",
    rid: removedRid
  });
  assert.throws(() => assembly.removeMethodSpec(removedRid), /referenced by CustomAttribute\.Parent/);
  const remappedParent = attributeRow.Parent;
  attributeRow.Parent = originalParent;
  attribute.parent = originalParent.target;
  assert.throws(() => assembly.removeMethodSpec(removedRid), /referenced by CIL/);
  attributeRow.Parent = remappedParent;
  attribute.parent = remappedParent.target;

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.methodSpecs.length, initialMethodSpecCount + 1);
  assert.equal(reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset).operand.value, secondToken - 1);
  assert.deepEqual(reparsed.customAttributes[0].parent, {
    table: 43,
    tableName: "MethodSpec",
    rid: removedRid
  });
});

test("StandAloneSig rows append method/local signatures and return stable tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const originalCount = assembly.tables.counts[17];
  assert.throws(() => assembly.addStandAloneSig({ signature: Uint8Array.of(0xff) }),
    /signature|calling convention/i);
  assert.equal(assembly.tables.counts[17], originalCount);

  const localToken = assembly.addStandAloneSig({
    signature: Uint8Array.of(0x07, 0x01, 0x08)
  });
  assert.throws(() => assembly.replaceStandAloneSig(localToken & 0x00ffffff, {
    signature: Uint8Array.of(0x00, 0x00, 0x01)
  }), /preserve its method or local-signature kind/);
  assembly.replaceStandAloneSig(localToken & 0x00ffffff, {
    signature: Uint8Array.of(0x07, 0x00)
  });
  const callSiteToken = assembly.addStandAloneSig({
    signature: Uint8Array.of(0x00, 0x00, 0x01)
  });
  assert.equal(localToken, 0x11000000 + originalCount + 1);
  assert.equal(callSiteToken, localToken + 1);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.standAloneSigs.at(-2).parsedSignature.kind, "locals");
  assert.deepEqual(reparsed.standAloneSigs.at(-2).signature, Uint8Array.of(0x07, 0x00));
  assert.equal(reparsed.standAloneSigs.at(-1).parsedSignature.kind, "method");
});

test("StandAloneSig removal protects live local-signature and CIL references", () => {
  const localReferenceAssembly = parseAssembly(withoutDebugDirectory());
  const initialCount = localReferenceAssembly.tables.counts[17];
  assert.throws(
    () => localReferenceAssembly.removeStandAloneSig(1),
    /referenced by MethodDef row \d+ local signature/
  );
  assert.equal(localReferenceAssembly.tables.counts[17], initialCount);
  assert.equal(localReferenceAssembly.tables.row(17, 1).rid, 1);
  assert.equal(localReferenceAssembly.modified, false);

  const cilAssembly = parseAssembly(withoutLocalSignatureTokens(withoutDebugDirectory()));
  const callSite = cilAssembly.methods.map((method) => ({
    method,
    instruction: cilAssembly.getInstructions(method.rid)
      .find((item) => item.operand?.kind === "token")
  })).find((entry) => entry.instruction);
  assert.ok(callSite);
  callSite.instruction.operand.value = 0x11000002;
  assert.throws(
    () => cilAssembly.removeStandAloneSig(2),
    /StandAloneSig row 2 is referenced by CIL/
  );
  assert.equal(cilAssembly.tables.counts[17], initialCount);
});

test("StandAloneSig removal remaps local-signature tokens and reparses", () => {
  const assembly = parseAssembly(withoutLocalSignatureTokens(withoutDebugDirectory()));
  const method = assembly.methods.find((item) => assembly.getMethodBody(item.rid)?.format === "fat");
  assert.ok(method);
  const body = assembly.getMethodBody(method.rid);
  body.localVarSigToken = 0x11000002;
  const callSite = assembly.methods.map((item) => ({
    method: item,
    instruction: assembly.getInstructions(item.rid)
      .find((candidate) => candidate.opcode.name === "call")
  })).find((entry) => entry.instruction);
  assert.ok(callSite);
  const calli = listOpcodes().find((opcode) => opcode.name === "calli");
  assert.ok(calli);
  callSite.instruction.opcode = calli;
  callSite.instruction.operand.value = 0x11000002;
  assembly._patches.push({
    offset: callSite.instruction.opcodeOffset,
    bytes: Uint8Array.of(calli.code)
  });
  const heapStreams = new Map([...assembly.metadataRoot.streams].map(([name, stream]) =>
    [name, stream.bytes.slice()]
  ));
  const callSiteSignature = appendBlobHeap(
    heapStreams.get("#Blob"),
    Uint8Array.of(0x00, 0x00, 0x01)
  );
  heapStreams.set("#Blob", callSiteSignature.heap);
  assembly._heapStreams = heapStreams;
  assembly.tables.row(17, 2).Signature = callSiteSignature.index;
  assembly._metadataDirty = true;
  const attributeRow = assembly.tables.row(12, 1);
  assembly.tables.sorted &= ~(1n << 12n);
  attributeRow.Parent = {
    raw: encodeCodedIndex(17, 2, "HasCustomAttribute"),
    target: { table: 17, tableName: "StandAloneSig", rid: 2 }
  };
  assembly.customAttributes[0].parent = attributeRow.Parent.target;
  assembly.tables.rows.set(31, [{
    table: 31,
    tableName: "ENCMap",
    rid: 1,
    Token: 0x11000002
  }]);
  assembly.tables.counts[31] = 1;
  assembly.tables.valid |= 1n << 31n;
  const survivingSignature = Uint8Array.of(0x00, 0x00, 0x01);
  const tokenMap = assembly.removeStandAloneSig(1);

  assert.equal(tokenMap.get(0x11000002), 0x11000001);
  assert.equal(assembly.tables.counts[17], 1);
  assert.equal(assembly.standAloneSigs.length, 1);
  assert.equal(assembly.standAloneSigs[0].rid, 1);
  assert.equal(assembly.tables.row(31, 1).Token, 0x11000001);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.row(31, 1).Token, 0x11000001);
  assert.equal(reparsed.getMethodBody(method.rid).localVarSigToken, 0x11000001);
  assert.equal(reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset).opcode.name, "calli");
  assert.equal(reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset).operand.value, 0x11000001);
  assert.deepEqual(reparsed.customAttributes[0].parent, {
    table: 17,
    tableName: "StandAloneSig",
    rid: 1
  });
  assert.deepEqual(
    reparsed.heaps.getBlob(reparsed.tables.row(17, 1).Signature),
    survivingSignature
  );
});

test("generic parameter constraints append and replace valid type references", () => {
  const assembly = parseAssembly(fixture);
  const genericParam = assembly.genericParams.find((parameter) => parameter.owner.table === 2);
  const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const typeDef = assembly.types.find((type) => type.rid > 1);
  assert.ok(genericParam && typeRef && typeDef);
  const rid = assembly.addGenericParamConstraint({
    ownerRid: genericParam.rid,
    constraint: { table: "TypeRef", rid: typeRef.rid }
  });
  assembly.replaceGenericParamConstraint(rid, {
    constraint: { table: "TypeDef", rid: typeDef.rid }
  });
  assert.throws(() => assembly.replaceGenericParamConstraint(rid, {
    constraint: { table: "TypeRef", rid: 0xffff }
  }), /missing or invalid type row/);
  const reparsed = parseAssembly(assembly.serialize());
  const constraint = reparsed.genericParamConstraints.find((item) => item.rid === rid);
  assert.equal(constraint.ownerRid, genericParam.rid);
  assert.deepEqual(constraint.constraint, { table: 2, tableName: "TypeDef", rid: typeDef.rid });
  assert.ok(reparsed.genericParams[genericParam.rid - 1].constraints.includes(constraint));
});

test("GenericParamConstraint removal remaps surviving metadata references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const genericParam = assembly.genericParams.find((parameter) => parameter.owner.table === 2);
  const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(genericParam && typeRef);
  assembly.tables.sorted &= ~(1n << 44n);
  const firstRid = assembly.addGenericParamConstraint({
    ownerRid: genericParam.rid,
    constraint: { table: "TypeRef", rid: typeRef.rid }
  });
  const secondRid = assembly.addGenericParamConstraint({
    ownerRid: genericParam.rid,
    constraint: { table: "TypeRef", rid: typeRef.rid }
  });
  const attribute = assembly.customAttributes[0];
  const attributeRow = assembly.tables.row(12, attribute.rid);
  assembly.tables.sorted &= ~(1n << 12n);
  attributeRow.Parent.raw = encodeCodedIndex(44, secondRid, "HasCustomAttribute");
  attributeRow.Parent.target = {
    table: 44,
    tableName: "GenericParamConstraint",
    rid: secondRid
  };
  attribute.parent = attributeRow.Parent.target;

  const tokenMap = assembly.removeGenericParamConstraint(firstRid);
  assert.equal(tokenMap.get(0x2c000000 + secondRid), 0x2c000000 + firstRid);
  assert.equal(assembly.genericParamConstraints.length, secondRid - 1);
  assert.equal(assembly.genericParamConstraints[firstRid - 1].rid, firstRid);
  assert.equal(attribute.parent.rid, firstRid);
  assert.throws(() => assembly.removeGenericParamConstraint(firstRid), /referenced by CustomAttribute\.Parent/);
  assert.throws(() => assembly.removeGenericParamConstraint(0), /Invalid GenericParamConstraint row ID/);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.genericParamConstraints.length, secondRid - 1);
  assert.deepEqual(reparsed.customAttributes[0].parent, {
    table: 44,
    tableName: "GenericParamConstraint",
    rid: firstRid
  });
});

test("generic parameters append sorted owner metadata and validate flags", () => {
  const gapAssembly = parseAssembly(fixture);
  gapAssembly.replaceMethodSignature(9, Uint8Array.of(0x10, 0x02, 0x00, 0x01));
  assert.throws(() => gapAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TSecond",
    number: 1
  }), /must be appended contiguously at 0/);
  assert.equal(gapAssembly.genericParams.filter((parameter) =>
    parameter.owner.table === 6 && parameter.owner.rid === 9
  ).length, 0);
  gapAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TFirst",
    number: 0
  });
  gapAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TSecond",
    number: 1
  });
  assert.equal(parseAssembly(gapAssembly.serialize()).methods[8].genericParams.length, 2);

  const assembly = parseAssembly(fixture);
  const owner = { table: "MethodDef", rid: 9 };
  assembly.replaceMethodSignature(9, Uint8Array.from([0x10, 0x01, 0x00, 0x01]));
  const token = assembly.addGenericParam({
    owner,
    name: "TAdded"
  });
  const reparsed = parseAssembly(assembly.serialize());
  const parameter = reparsed.genericParams.find((item) => item.rid === (token & 0x00ffffff));
  assert.equal(parameter.number, 0);
  assert.equal(parameter.name, "TAdded");
  assert.deepEqual(parameter.owner, { table: 6, tableName: "MethodDef", rid: owner.rid });
  assert.ok(reparsed.methods[owner.rid - 1].genericParams.includes(parameter));

  const invalidAssembly = parseAssembly(fixture);
  assert.throws(() => invalidAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: invalidAssembly.methods[0].rid },
    name: "TInvalid",
    flags: 1
  }), /method parameters cannot declare variance/);
  assert.throws(() => invalidAssembly.addGenericParam({
    owner: { table: "MethodDef", rid: invalidAssembly.methods[0].rid },
    name: "TInvalid"
  }), /exceeds the generic arity declared/);
  const classType = invalidAssembly.types.find((type) => (type.flags & 0x20) === 0);
  assert.ok(classType);
  assert.throws(() => invalidAssembly.addGenericParam({
    owner: { table: "TypeDef", rid: classType.rid },
    name: "TInvalid",
    flags: 1
  }), /only valid on interfaces and delegates/);
  assert.equal(invalidAssembly.modified, false);
});

test("generic parameters can update names and variance or constraint flags safely", () => {
  const assembly = parseAssembly(fixture);
  const parameter = assembly.genericParams[0];
  assembly.replaceGenericParam(parameter.rid, { name: "TUpdated", flags: 0 });
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.genericParams[0].name, "TUpdated");
  assert.equal(reparsed.genericParams[0].flags, 0);

  const invalidAssembly = parseAssembly(fixture);
  assert.throws(() => invalidAssembly.replaceGenericParam(parameter.rid, { flags: 1 }),
    /only valid on interfaces and delegates/);
  assert.equal(invalidAssembly.modified, false);
  assert.throws(() => invalidAssembly.replaceGenericParam(parameter.rid, { flags: 0x20 }),
    /reserved bits/);
  assert.equal(invalidAssembly.modified, false);
});

test("generic metadata rejects gaps in an owner's parameter numbers", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const parameter = assembly.genericParams.find((item) => item.owner.table === 2);
  assert.ok(parameter);
  const ownerParameters = assembly.genericParams.filter((item) =>
    item.owner.table === 2 && item.owner.rid === parameter.owner.rid
  );
  const nextMissingNumber = Math.max(...ownerParameters.map((item) => item.number)) + 1;
  assembly.tables.sorted &= ~(1n << 42n);
  assembly.tables.row(42, parameter.rid).Number = nextMissingNumber;
  assembly.replaceGenericParam(parameter.rid, { name: `${parameter.name}Changed` });

  assert.throws(() => parseAssembly(assembly.serialize()), /parameter numbers from zero without gaps/);
});

test("generic method signatures can be replaced before adding their parameter rows", () => {
  const invalidAssembly = parseAssembly(fixture);
  assert.throws(() => invalidAssembly.replaceMethodSignature(
    9,
    Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x01])
  ), /Method generic variable !!1 exceeds its method's arity/);
  assert.equal(invalidAssembly.modified, false);

  const assembly = parseAssembly(fixture);
  const signature = Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00]);
  assembly.replaceMethodSignature(9, signature);
  const parsed = parseSignature(assembly.methods[8].signature);
  assert.equal(parsed.generic, true);
  assert.equal(parsed.genericParameterCount, 1);
  assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "T"
  });
  assert.throws(() => assembly.replaceMethodSignature(9, Uint8Array.from([0x00, 0x00, 0x01])),
    /incompatible with its GenericParam rows/);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(parseSignature(reparsed.methods[8].signature).genericParameterCount, 1);
  assert.equal(reparsed.genericParams.at(-1).owner.table, 6);
  assert.equal(reparsed.genericParams.at(-1).owner.rid, 9);
  assert.ok(reparsed.methods[8].genericParams.includes(reparsed.genericParams.at(-1)));
});

test("GenericParam removal reduces method arity and remaps surviving tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const signature = Uint8Array.from([0x10, 0x01, 0x00, 0x01]);
  assembly.replaceMethodSignature(9, signature);
  assembly.replaceMethodSignature(11, signature);
  const removedToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TRemoved"
  });
  const survivingToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 11 },
    name: "TSurviving"
  });
  const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(typeRef);
  assembly.addGenericParamConstraint({
    ownerRid: survivingToken & 0x00ffffff,
    constraint: { table: "TypeRef", rid: typeRef.rid }
  });
  const attribute = assembly.customAttributes[0];
  const attributeRow = assembly.tables.row(12, attribute.rid);
  assert.ok(attributeRow);
  assembly.tables.sorted &= ~(1n << 12n);
  attributeRow.Parent = {
    raw: encodeCodedIndex(
      42,
      survivingToken & 0x00ffffff,
      "HasCustomAttribute"
    ),
    target: {
      table: 42,
      tableName: "GenericParam",
      rid: survivingToken & 0x00ffffff
    }
  };
  attribute.parent = attributeRow.Parent.target;

  const tokenMap = assembly.removeGenericParam(removedToken & 0x00ffffff);
  assert.equal(tokenMap.get(survivingToken), survivingToken - 1);
  assert.equal(parseSignature(assembly.methods[8].signature).generic, false);
  assert.equal(assembly.methods[8].genericParams.length, 0);
  assert.equal(assembly.methods[10].genericParams[0].rid, (survivingToken & 0x00ffffff) - 1);
  assert.equal(assembly.genericParamConstraints.at(-1).ownerRid, (survivingToken & 0x00ffffff) - 1);
  assert.equal(assembly.customAttributes[0].parent.rid, (survivingToken & 0x00ffffff) - 1);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(parseSignature(reparsed.methods[8].signature).generic, false);
  assert.equal(reparsed.methods[8].genericParams.length, 0);
  assert.equal(reparsed.methods[10].genericParams[0].name, "TSurviving");
  assert.equal(parseSignature(reparsed.methods[10].signature).genericParameterCount, 1);
  assert.equal(reparsed.genericParamConstraints.at(-1).ownerRid,
    reparsed.methods[10].genericParams[0].rid);
  assert.equal(reparsed.customAttributes[0].parent.rid,
    reparsed.methods[10].genericParams[0].rid);
});

test("GenericParam removal rejects non-trailing or constrained parameters without mutation", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.replaceMethodSignature(9, Uint8Array.from([0x10, 0x02, 0x00, 0x01]));
  const firstToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TFirst"
  });
  const secondToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "TSecond"
  });
  assert.throws(() => assembly.removeGenericParam(firstToken & 0x00ffffff),
    /trailing method generic parameter/);
  assert.equal(assembly.genericParams.filter((item) =>
    item.owner.table === 6 && item.owner.rid === 9
  ).length, 2);

  const typeRef = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(typeRef);
  assembly.addGenericParamConstraint({
    ownerRid: secondToken & 0x00ffffff,
    constraint: { table: "TypeRef", rid: typeRef.rid }
  });
  const before = Buffer.from(assembly.serialize());
  assert.throws(() => assembly.removeGenericParam(secondToken & 0x00ffffff),
    /live GenericParamConstraint/);
  assert.deepEqual(Buffer.from(assembly.serialize()), before);
});

test("metadata validation rejects GenericParam numbers beyond method signature arity", () => {
  const assembly = parseAssembly(fixture);
  assembly.replaceMethodSignature(9, Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00]));
  const token = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: 9 },
    name: "T"
  });
  assembly.tables.row(42, token & 0x00ffffff).Number = 1;
  assert.throws(() => assembly.serialize(), /GenericParam row 2 exceeds its method signature's generic arity/);
});

test("generic field signatures can be replaced with validated type-variable signatures", () => {
  const assembly = parseAssembly(fixture);
  const genericType = assembly.types.find((type) => type.name === "Sample`1");
  const fieldRid = genericType.fieldRids[0];
  assert.throws(() => assembly.replaceFieldSignature(fieldRid, Uint8Array.from([0x06, 0x13, 0x01])),
    /Type generic variable !1 exceeds its declaring type's arity/);
  assert.equal(assembly.modified, false);
  const signature = Uint8Array.from([0x06, 0x13, 0x00]);
  assembly.replaceFieldSignature(fieldRid, signature);
  assert.deepEqual(parseSignature(genericType.fields.find((field) => field.rid === fieldRid).signature), {
    kind: "field",
    type: { kind: "typeParameter", index: 0 }
  });

  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(parseSignature(reparsed.heaps.getBlob(reparsed.tables.row(4, fieldRid).Signature)), {
    kind: "field",
    type: { kind: "typeParameter", index: 0 }
  });
});

test("parameters append to the last MethodDef in optimized and pointer-table metadata", () => {
  for (const usePointerTable of [false, true]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    if (usePointerTable) {
      const tableStream = assembly.metadataRoot.streams.get("#~");
      assert.ok(tableStream);
      assembly.metadataRoot.streams.delete("#~");
      assembly.metadataRoot.streams.set("#-", tableStream);
      const paramRows = assembly.tables.get(8);
      const pointers = paramRows.map((param, index) => ({
        table: 7,
        tableName: "ParamPtr",
        rid: index + 1,
        Param: {
          raw: param.rid,
          table: 8,
          tableName: "Param",
          rid: param.rid
        }
      }));
      assembly.tables.rows.set(7, pointers);
      assembly.tables.counts[7] = pointers.length;
      assembly.tables.valid |= 1n << 7n;
      for (const methodRow of assembly.tables.get(6)) {
        methodRow.ParamList = {
          raw: methodRow.ParamList.rid,
          table: 7,
          tableName: "ParamPtr",
          rid: methodRow.ParamList.rid
        };
      }
    }

    const method = assembly.methods.at(-1);
    assert.equal(method.parameters.length, 0);
    assembly.replaceMethodSignature(method.rid, Uint8Array.from([0x20, 0x01, 0x01, 0x08]));
    assert.throws(() => assembly.addParam({
      owner: { table: "MethodDef", rid: method.rid },
      sequence: 2,
      name: "invalid"
    }), /exceeds the MethodDef signature parameter count/);
    const rid = assembly.addParam({
      owner: { table: "MethodDef", rid: method.rid },
      sequence: 1,
      name: "value",
      flags: 1
    });
    assert.equal(rid, assembly.tables.counts[8]);
    assert.deepEqual(method.parameters.at(-1), { rid, flags: 1, sequence: 1, name: "value" });
    assert.throws(() => assembly.replaceParam(rid, { flags: 0x10000 }),
      /unsigned 16-bit integer/);
    assembly.replaceParam(rid, { name: "renamedValue", flags: 2 });
    assert.deepEqual(method.parameters.at(-1), {
      rid,
      flags: 2,
      sequence: 1,
      name: "renamedValue"
    });

    const reparsed = parseAssembly(assembly.serialize());
    const parsedMethod = reparsed.methods[method.rid - 1];
    assert.deepEqual(parsedMethod.parameters.at(-1), {
      rid,
      flags: 2,
      sequence: 1,
      name: "renamedValue"
    });
    assert.equal(reparsed.metadataRoot.streams.has("#-"), usePointerTable);
    if (usePointerTable) {
      assert.equal(reparsed.tables.get(7).at(-1).Param.rid, rid);
    }
  }
});

test("abstract methods append to the last TypeDef in optimized and pointer-table metadata", () => {
  for (const usePointerTables of [false, true]) {
    const assembly = parseAssembly(fixture);
    if (usePointerTables) {
      const tableStream = assembly.metadataRoot.streams.get("#~");
      assert.ok(tableStream);
      assembly.metadataRoot.streams.delete("#~");
      assembly.metadataRoot.streams.set("#-", tableStream);
      const methodRows = assembly.tables.get(6);
      const methodPointers = methodRows.map((method, index) => ({
        table: 5,
        tableName: "MethodPtr",
        rid: index + 1,
        Method: {
          raw: method.rid,
          table: 6,
          tableName: "MethodDef",
          rid: method.rid
        }
      }));
      assembly.tables.rows.set(5, methodPointers);
      assembly.tables.counts[5] = methodPointers.length;
      assembly.tables.valid |= 1n << 5n;
      for (const typeRow of assembly.tables.get(2)) {
        typeRow.MethodList = {
          raw: typeRow.MethodList.rid,
          table: 5,
          tableName: "MethodPtr",
          rid: typeRow.MethodList.rid
        };
      }
      const ownerStart = assembly.tables.row(2, assembly.types.at(-1).rid).MethodList.rid - 1;
      [methodPointers[ownerStart].Method, methodPointers[ownerStart + 1].Method] =
        [methodPointers[ownerStart + 1].Method, methodPointers[ownerStart].Method];

      const paramRows = assembly.tables.get(8);
      const paramPointers = paramRows.map((param, index) => ({
        table: 7,
        tableName: "ParamPtr",
        rid: index + 1,
        Param: {
          raw: param.rid,
          table: 8,
          tableName: "Param",
          rid: param.rid
        }
      }));
      assembly.tables.rows.set(7, paramPointers);
      assembly.tables.counts[7] = paramPointers.length;
      assembly.tables.valid |= 1n << 7n;
      for (const methodRow of methodRows) {
        methodRow.ParamList = {
          raw: methodRow.ParamList.rid,
          table: 7,
          tableName: "ParamPtr",
          rid: methodRow.ParamList.rid
        };
      }
    }

    const owner = assembly.types.at(-1);
    owner.flags |= 0x0080;
    assembly.tables.row(2, owner.rid).Flags = owner.flags;
    const token = assembly.addMethod({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "AddedAbstract",
      flags: 0x0446,
      signature: Uint8Array.from([0x20, 0x01, 0x01, 0x08])
    });
    const rid = token & 0x00ffffff;
    assert.equal(token >>> 24, 0x06);
    const parameterRid = assembly.addParam({
      owner: { table: "MethodDef", rid },
      name: "value",
      sequence: 1
    });

    const reparsed = parseAssembly(assembly.serialize());
    const added = reparsed.methods[rid - 1];
    assert.equal(added.name, "AddedAbstract");
    assert.equal(added.rva, 0);
    assert.equal(added.parameters[0].rid, parameterRid);
    assert.equal(reparsed.types[owner.rid - 1].methods.at(-1).rid, rid);
    assert.equal(reparsed.getMethodBody(rid), null);
    assert.equal(reparsed.metadataRoot.streams.has("#-"), usePointerTables);
    if (usePointerTables) {
      assert.equal(reparsed.tables.get(5).at(-1).Method.rid, rid);
      assert.equal(reparsed.tables.get(7).at(-1).Param.rid, parameterRid);
    }
  }
});

test("method append supports validated IL bodies and generic signatures", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  assert.throws(() => assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "ConcreteWithoutBody",
    flags: 0x0006,
    signature: Uint8Array.from([0x00, 0x00, 0x01])
  }), /bodyless MethodDef must be an abstract virtual IL method/);
  assert.throws(() => assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "MalformedBody",
    flags: 0x0096,
    signature: Uint8Array.from([0x00, 0x00, 0x01]),
    body: Uint8Array.of(0x06, 0xff)
  }), /Unknown CIL opcode/);
  assert.throws(() => assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "InvalidTokenBody",
    flags: 0x0096,
    signature: Uint8Array.from([0x00, 0x00, 0x01]),
    body: Uint8Array.of(0x1e, 0xd0, 0xff, 0xff, 0xff, 0x02, 0x26, 0x2a)
  }), /references missing TypeDef row/);
  assert.throws(() => assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "InvalidHeaderBody",
    flags: 0x0096,
    signature: Uint8Array.from([0x00, 0x00, 0x01]),
    body: Uint8Array.of(0x23, 0x30, 0x08, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a)
  }), /unsupported header flags/);
  assert.throws(() => assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "InvalidGeneric",
    flags: 0x0096,
    signature: Uint8Array.of(0x10, 0x01, 0x00, 0x1e, 0x01),
    body: Uint8Array.of(0x06, 0x2a)
  }), /Method generic variable !!1 exceeds/);
  assert.equal(assembly.modified, false);

  const token = assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "Concrete",
    flags: 0x0096,
    signature: Uint8Array.from([0x00, 0x00, 0x01]),
    body: Uint8Array.of(0x12, 0x1f, 0x01, 0x26, 0x2a)
  });
  const rid = token & 0x00ffffff;
  assert.equal(assembly.methods[rid - 1].rva, 0);
  assert.equal(assembly.getMethodBody(rid).instructions[0].operand.value, 1);
  assembly.setInstructionOperand(rid, 0, 2);
  const fatToken = assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "FatConcrete",
    flags: 0x0096,
    signature: Uint8Array.of(0, 0, 1),
    body: Uint8Array.of(0x03, 0x30, 0x08, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a)
  });
  const fatRid = fatToken & 0x00ffffff;
  const reparsed = parseAssembly(assembly.serialize());
  assert.ok(reparsed.methods[rid - 1].rva > 0);
  assert.equal(reparsed.getMethodBody(rid).instructions[0].operand.value, 2);
  assert.equal(reparsed.getMethodBody(fatRid).format, "fat");
  reparsed.insertInstruction(rid, 0, "nop");
  const structurallyRewritten = parseAssembly(reparsed.serialize());
  assert.deepEqual(
    structurallyRewritten.getMethodBody(rid).instructions.map((instruction) => instruction.opcode.name),
    ["nop", "ldc.i4.s", "pop", "ret"]
  );
  assert.equal(structurallyRewritten.getMethodBody(rid).instructions[1].operand.value, 2);

  const genericToken = assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "Identity",
    flags: 0x0096,
    signature: Uint8Array.of(0x10, 0x01, 0x01, 0x1e, 0x00, 0x1e, 0x00),
    body: Uint8Array.of(0x0a, 0x02, 0x2a)
  });
  const genericRid = genericToken & 0x00ffffff;
  assembly.addGenericParam({
    owner: { table: "MethodDef", rid: genericRid },
    name: "T",
    number: 0
  });
  assert.equal(assembly.methods[genericRid - 1].genericParams[0].name, "T");
  const genericReparsed = parseAssembly(assembly.serialize());
  assert.equal(genericReparsed.methods[genericRid - 1].genericParams[0].name, "T");
  assert.equal(genericReparsed.getMethodBody(genericRid).instructions[0].opcode.name, "ldarg.0");
  assert.equal(assembly.tables.counts[6], assembly.methods.length);
  assert.equal(assembly.modified, true);
  const removableAssembly = parseAssembly(withoutDebugDirectory());
  const removableOwner = removableAssembly.types.at(-1);
  const removableToken = removableAssembly.addMethod({
    owner: { table: "TypeDef", rid: removableOwner.rid },
    name: "DisposableMethod",
    flags: 0x0096,
    signature: Uint8Array.of(0, 0, 1),
    body: Uint8Array.of(0x06, 0x2a)
  });
  assert.throws(() => removableAssembly.removeMethod(1), /RID remapping cannot be combined/);
  assert.equal(removableAssembly.removeMethod(removableToken & 0x00ffffff).size, 0);
  const withoutMethod = parseAssembly(removableAssembly.serialize());
  assert.equal(withoutMethod.methods.some((method) => method.name === "Concrete"), false);
  assert.equal(withoutMethod.methods.some((method) => method.name === "DisposableMethod"), false);
});

test("non-trailing MethodDef removal remaps later metadata and CIL tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const tableStream = assembly.metadataRoot.streams.get("#~");
  assert.ok(tableStream);
  assembly.metadataRoot.streams.delete("#~");
  assembly.metadataRoot.streams.set("#-", tableStream);
  const originalMethods = assembly.tables.get(6);
  assembly.tables.rows.set(5, originalMethods.map((method, index) => ({
    table: 5,
    tableName: "MethodPtr",
    rid: index + 1,
    Method: { raw: method.rid, table: 6, tableName: "MethodDef", rid: method.rid }
  })));
  assembly.tables.counts[5] = originalMethods.length;
  assembly.tables.valid |= 1n << 5n;
  for (const typeRow of assembly.tables.get(2)) {
    const pointerRid = typeRow.MethodList.rid;
    typeRow.MethodList = {
      raw: pointerRid,
      table: 5,
      tableName: "MethodPtr",
      rid: pointerRid
    };
  }
  const interfaceToken = assembly.addTypeDef({
    name: "GeneratedInterface",
    flags: 0x00a1
  });
  const ownerRid = interfaceToken & 0x00ffffff;
  const owner = { table: "TypeDef", rid: ownerRid };
  const firstToken = assembly.addMethod({
    owner,
    name: "Removed",
    flags: 0x0466,
    signature: Uint8Array.of(0, 0, 1)
  });
  const shiftedToken = assembly.addMethod({
    owner,
    name: "Shifted",
    flags: 0x0466,
    signature: Uint8Array.of(0x10, 0x01, 0, 1)
  });
  const shiftedRid = shiftedToken & 0x00ffffff;
  assembly.addGenericParam({
    owner: { table: "MethodDef", rid: shiftedRid },
    name: "T"
  });
  const methodSpecToken = assembly.addMethodSpec({
    method: { table: "MethodDef", rid: shiftedRid },
    instantiation: Uint8Array.of(0x0a, 0x01, 0x08)
  });
  const methodPointers = assembly.tables.get(5);
  const pointerIndex = methodPointers.length - 1;
  [methodPointers[pointerIndex - 1].Method, methodPointers[pointerIndex].Method] = [
    methodPointers[pointerIndex].Method,
    methodPointers[pointerIndex - 1].Method
  ];
  assert.ok(assembly.customAttributes.length > 0);
  const attributeRow = assembly.tables.get(12).at(-1);
  const attributeIndex = attributeRow.rid - 1;
  const attributeParent = {
    raw: encodeCodedIndex(6, shiftedRid, "HasCustomAttribute"),
    target: { table: 6, tableName: "MethodDef", rid: shiftedRid }
  };
  attributeRow.Parent = attributeParent;
  assembly.customAttributes[attributeIndex].parent = attributeParent.target;
  assert.ok(assembly.tables.get(12).slice(0, -1).every((row) =>
    row.Parent.raw <= attributeParent.raw
  ));
  assembly.tables.sorted |= 1n << 12n;
  assert.ok(assembly.memberRefs.length > 0);
  const memberRefIndex = assembly.memberRefs.length - 1;
  const memberRefRow = assembly.tables.get(10).at(-1);
  const memberRefParent = {
    raw: encodeCodedIndex(6, shiftedRid, "MemberRefParent"),
    target: { table: 6, tableName: "MethodDef", rid: shiftedRid }
  };
  memberRefRow.Class = memberRefParent;
  assembly.memberRefs[memberRefIndex].parent = memberRefParent.target;
  assembly.tables.sorted &= ~(1n << 10n);
  const caller = assembly.methods.find((method) =>
    assembly.getMethodBody(method.rid)?.instructions.some((instruction) =>
      ["call", "callvirt"].includes(instruction.opcode.name)
    )
  );
  assert.ok(caller);
  const call = assembly.getMethodBody(caller.rid).instructions.find((instruction) =>
    ["call", "callvirt"].includes(instruction.opcode.name)
  );
  assembly.setInstructionOperand(caller.rid, call.offset, shiftedToken);

  const tokenMap = assembly.removeMethod(firstToken & 0x00ffffff);
  assert.equal(tokenMap.get(shiftedToken), firstToken);
  const reparsed = parseAssembly(assembly.serialize());
  const shiftedMethod = reparsed.methods.find((method) => method.name === "Shifted");
  assert.equal(shiftedMethod.rid, shiftedRid - 1);
  assert.equal(shiftedMethod.genericParams[0].owner.rid, shiftedRid - 1);
  assert.equal(
    reparsed.methodSpecs[(methodSpecToken & 0x00ffffff) - 1].method.rid,
    shiftedRid - 1
  );
  assert.equal(reparsed.tables.get(5).at(-1).Method.rid, shiftedRid - 1);
  assert.equal(reparsed.customAttributes.at(-1).parent.rid, shiftedRid - 1);
  assert.equal(reparsed.memberRefs.at(-1).parent.rid, shiftedRid - 1);
  const reparsedCall = reparsed.getMethodBody(caller.rid).instructions.find((instruction) =>
    ["call", "callvirt"].includes(instruction.opcode.name) &&
    instruction.operand.value === (shiftedToken - 1)
  );
  assert.ok(reparsedCall);
});

test("trailing MethodDef removal preserves #- MethodPtr ownership", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const tableStream = assembly.metadataRoot.streams.get("#~");
  assert.ok(tableStream);
  assembly.metadataRoot.streams.delete("#~");
  assembly.metadataRoot.streams.set("#-", tableStream);
  const methodRows = assembly.tables.get(6);
  const pointerRows = methodRows.map((method, index) => ({
    table: 5,
    tableName: "MethodPtr",
    rid: index + 1,
    Method: { raw: method.rid, table: 6, tableName: "MethodDef", rid: method.rid }
  }));
  assembly.tables.rows.set(5, pointerRows);
  assembly.tables.counts[5] = pointerRows.length;
  assembly.tables.valid |= 1n << 5n;
  for (const typeRow of assembly.tables.get(2)) {
    const rid = typeRow.MethodList.rid;
    typeRow.MethodList = { raw: rid, table: 5, tableName: "MethodPtr", rid };
  }
  const originalPointerCount = pointerRows.length;
  const owner = assembly.types.at(-1);
  const token = assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "DisposableMethod",
    flags: 0x0096,
    signature: Uint8Array.of(0, 0, 1),
    body: Uint8Array.of(0x06, 0x2a)
  });
  assert.equal(assembly.removeMethod(token & 0x00ffffff).size, 0);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.metadataRoot.streams.has("#-"), true);
  assert.equal(reparsed.tables.counts[5], originalPointerCount);
  assert.equal(reparsed.methods.some((method) => method.name === "DisposableMethod"), false);
});

test("trailing MethodDef removal also removes owned Param rows", () => {
  for (const useParamPointerTable of [false, true]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    if (useParamPointerTable) {
      usePointerTable(assembly, {
        pointerId: 7,
        targetId: 8,
        column: "Param",
        listTableId: 6,
        listColumn: "ParamList",
        pointerName: "ParamPtr",
        targetName: "Param"
      });
    }
    const originalParamCount = assembly.tables.counts[8];
    const originalParamPointerCount = assembly.tables.counts[7] ?? 0;
    const owner = assembly.types.at(-1);
    const token = assembly.addMethod({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "MethodWithParameters",
      flags: 0x0096,
      signature: Uint8Array.of(0, 2, 1, 8, 8),
      body: Uint8Array.of(0x06, 0x2a)
    });
    const methodRid = token & 0x00ffffff;
    assembly.addParam({ owner: { table: "MethodDef", rid: methodRid }, sequence: 1 });
    assembly.addParam({ owner: { table: "MethodDef", rid: methodRid }, sequence: 2 });
    const pointerCountAfterAppend = assembly.tables.counts[7] ?? 0;

    assert.equal(assembly.removeMethod(methodRid).size, 0);
    assert.equal(assembly.tables.counts[8], originalParamCount);
    assert.equal(assembly.tables.counts[7] ?? 0,
      useParamPointerTable ? originalParamPointerCount : pointerCountAfterAppend);
    const reparsed = parseAssembly(assembly.serialize());
    assert.equal(reparsed.methods.some((method) => method.name === "MethodWithParameters"), false);
    assert.equal(reparsed.tables.counts[8], originalParamCount);
    assert.equal(reparsed.metadataRoot.streams.has("#-"), useParamPointerTable);
    if (useParamPointerTable) {
      assert.equal(reparsed.tables.counts[7], originalParamPointerCount);
    }
  }
});

test("MethodDef removal rejects referenced owned Param rows without mutation", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const token = assembly.addMethod({
    owner: { table: "TypeDef", rid: assembly.types.at(-1).rid },
    name: "ReferencedParameter",
    flags: 0x0096,
    signature: Uint8Array.of(0, 1, 1, 8),
    body: Uint8Array.of(0x06, 0x2a)
  });
  const methodRid = token & 0x00ffffff;
  const paramRid = assembly.addParam({
    owner: { table: "MethodDef", rid: methodRid },
    sequence: 1
  });
  assembly.addConstant({
    parent: { table: "Param", rid: paramRid },
    type: 0x08,
    value: Uint8Array.of(1, 0, 0, 0)
  });
  const methodCount = assembly.tables.counts[6];
  const paramCount = assembly.tables.counts[8];

  assert.throws(() => assembly.removeMethod(methodRid), /Param row .* referenced by Constant.Parent/);
  assert.equal(assembly.tables.counts[6], methodCount);
  assert.equal(assembly.tables.counts[8], paramCount);
  assert.equal(assembly.methods.at(-1).rid, methodRid);
});

test("trailing MethodDef removal removes trailing method-owned GenericParam rows", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const originalGenericParamCount = assembly.tables.counts[42] ?? 0;
  const token = assembly.addMethod({
    owner: { table: "TypeDef", rid: assembly.types.at(-1).rid },
    name: "GenericMethodToRemove",
    flags: 0x0096,
    signature: Uint8Array.of(0x10, 0x01, 0x01, 0x01, 0x1e, 0x00),
    body: Uint8Array.of(0x06, 0x2a)
  });
  const methodRid = token & 0x00ffffff;
  const genericParamToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: methodRid },
    name: "T",
    number: 0
  });

  assert.equal(assembly.removeMethod(methodRid).size, 0);
  assert.equal(assembly.tables.counts[42], originalGenericParamCount);
  assert.equal(assembly.genericParams.some((parameter) =>
    parameter.rid === (genericParamToken & 0x00ffffff)
  ), false);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.counts[42], originalGenericParamCount);
  assert.equal(reparsed.methods.some((method) => method.name === "GenericMethodToRemove"), false);
});

test("MethodDef removal deletes owned GenericParam constraints and remaps survivors", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const ownerRid = assembly.addTypeDef({
    name: "ConstraintOwner",
    flags: 0x0080
  }) & 0x00ffffff;
  const signature = Uint8Array.of(0x10, 0x01, 0x01, 0x01, 0x1e, 0x00);
  const initialConstraintCount = assembly.tables.counts[44] ?? 0;
  const token = assembly.addMethod({
    owner: { table: "TypeDef", rid: ownerRid },
    name: "ConstrainedMethodToRemove",
    flags: 0x0466,
    signature
  });
  const methodRid = token & 0x00ffffff;
  const genericParamToken = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: methodRid },
    name: "T",
    number: 0
  });
  const genericParamRid = genericParamToken & 0x00ffffff;
  assembly.addGenericParamConstraint({
    ownerRid: genericParamRid,
    constraint: { table: "TypeDef", rid: 2 }
  });
  const survivorToken = assembly.addMethod({
    owner: { table: "TypeDef", rid: ownerRid },
    name: "ConstrainedMethodToKeep",
    flags: 0x0466,
    signature
  });
  const survivorRid = survivorToken & 0x00ffffff;
  const survivorGenericParamRid = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: survivorRid },
    name: "U",
    number: 0
  }) & 0x00ffffff;
  const survivorConstraintRid = assembly.addGenericParamConstraint({
    ownerRid: survivorGenericParamRid,
    constraint: { table: "TypeDef", rid: 2 }
  });
  assembly.tables.sorted &= ~(1n << 12n);
  const attributeTemplate = assembly.customAttributes[1];
  const attributeValue = assembly.parseCustomAttribute(attributeTemplate.rid);
  assembly.addCustomAttribute({
    parent: { table: "GenericParamConstraint", rid: survivorConstraintRid },
    constructor: attributeTemplate.constructor,
    value: attributeValue
  });
  addEncToken(assembly, 31, 0x2c000000 + survivorConstraintRid);

  const tokenMap = assembly.removeMethod(methodRid);
  const remappedGenericParamToken = 0x2a000000 + survivorGenericParamRid - 1;
  const remappedConstraintToken = 0x2c000000 + survivorConstraintRid - 1;
  assert.equal(tokenMap.get(survivorToken), survivorToken - 1);
  assert.equal(tokenMap.get(0x2a000000 + survivorGenericParamRid), remappedGenericParamToken);
  assert.equal(tokenMap.get(0x2c000000 + survivorConstraintRid), remappedConstraintToken);
  assert.equal(assembly.methods.find((item) => item.name === "ConstrainedMethodToKeep").rid,
    survivorRid - 1);
  assert.equal(assembly.tables.counts[42], genericParamRid);
  assert.equal(assembly.tables.counts[44], initialConstraintCount + 1);
  assert.equal(assembly.genericParamConstraints.find((item) =>
    item.rid === survivorConstraintRid - 1
  ).ownerRid, survivorGenericParamRid - 1);
  assert.equal(assembly.tables.get(31).at(-1).Token, remappedConstraintToken);
  assert.equal(assembly.customAttributes.at(-1).parent.rid, survivorConstraintRid - 1);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.counts[44], initialConstraintCount + 1);
  assert.equal(reparsed.genericParamConstraints.find((item) =>
    item.rid === survivorConstraintRid - 1
  ).ownerRid, survivorGenericParamRid - 1);
  assert.equal(reparsed.customAttributes.at(-1).parent.rid, survivorConstraintRid - 1);
});

test("MethodDef removal rejects externally referenced owned constraints atomically", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const ownerRid = assembly.addTypeDef({
    name: "ReferencedConstraintOwner",
    flags: 0x0080
  }) & 0x00ffffff;
  const methodToken = assembly.addMethod({
    owner: { table: "TypeDef", rid: ownerRid },
    name: "ConstrainedMethod",
    flags: 0x0466,
    signature: Uint8Array.of(0x10, 0x01, 0x01, 0x01, 0x1e, 0x00)
  });
  const genericParamRid = assembly.addGenericParam({
    owner: { table: "MethodDef", rid: methodToken & 0x00ffffff },
    name: "T",
    number: 0
  }) & 0x00ffffff;
  const constraintRid = assembly.addGenericParamConstraint({
    ownerRid: genericParamRid,
    constraint: { table: "TypeDef", rid: 2 }
  });
  assembly.tables.sorted &= ~(1n << 12n);
  const attributeTemplate = assembly.customAttributes[1];
  assembly.addCustomAttribute({
    parent: { table: "GenericParamConstraint", rid: constraintRid },
    constructor: attributeTemplate.constructor,
    value: assembly.parseCustomAttribute(attributeTemplate.rid)
  });
  const methodCount = assembly.tables.counts[6];
  const genericParamCount = assembly.tables.counts[42];
  const constraintCount = assembly.tables.counts[44];

  assert.throws(() => assembly.removeMethod(methodToken & 0x00ffffff),
    /GenericParamConstraint row .* referenced by CustomAttribute\.Parent/);
  assert.equal(assembly.tables.counts[6], methodCount);
  assert.equal(assembly.tables.counts[42], genericParamCount);
  assert.equal(assembly.tables.counts[44], constraintCount);
  assert.equal(assembly.genericParamConstraints.some((item) => item.rid === constraintRid), true);
});

test("non-trailing MethodDef removal remaps owned Param and GenericParam rows", () => {
  for (const useParamPointerTable of [false, true]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    if (useParamPointerTable) {
      usePointerTable(assembly, {
        pointerId: 7,
        targetId: 8,
        column: "Param",
        listTableId: 6,
        listColumn: "ParamList",
        pointerName: "ParamPtr",
        targetName: "Param"
      });
    }
    const ownerRid = assembly.addTypeDef({ name: "RemovalOwner", flags: 0x0080 }) & 0x00ffffff;
    const signature = Uint8Array.of(0x10, 0x01, 0x01, 0x01, 0x1e, 0x00);
    const removedToken = assembly.addMethod({
      owner: { table: "TypeDef", rid: ownerRid },
      name: "Remove",
      flags: 0x0466,
      signature
    });
    const removedRid = removedToken & 0x00ffffff;
    assembly.addParam({
      owner: { table: "MethodDef", rid: removedRid },
      sequence: 1
    });
    assembly.addGenericParam({
      owner: { table: "MethodDef", rid: removedRid },
      name: "T",
      number: 0
    });
    const survivingToken = assembly.addMethod({
      owner: { table: "TypeDef", rid: ownerRid },
      name: "Keep",
      flags: 0x0466,
      signature
    });
    const survivingRid = survivingToken & 0x00ffffff;
    const survivingParamRid = assembly.addParam({
      owner: { table: "MethodDef", rid: survivingRid },
      sequence: 1
    });
    const survivingGenericParamRid = assembly.addGenericParam({
      owner: { table: "MethodDef", rid: survivingRid },
      name: "U",
      number: 0
    }) & 0x00ffffff;
    const constraintRid = assembly.addGenericParamConstraint({
      ownerRid: survivingGenericParamRid,
      constraint: { table: "TypeDef", rid: 2 }
    });
    assembly.addConstant({
      parent: { table: "Param", rid: survivingParamRid },
      type: 0x08,
      value: Uint8Array.of(7, 0, 0, 0)
    });
    addEncToken(assembly, 30, 0x08000000 + survivingParamRid);
    addEncToken(assembly, 31, 0x2a000000 + survivingGenericParamRid);

    const tokenMap = assembly.removeMethod(removedRid);
    const remappedMethodRid = survivingRid - 1;
    const remappedParamRid = survivingParamRid - 1;
    const remappedGenericParamRid = survivingGenericParamRid - 1;
    const remappedMethodToken = 0x06000000 + remappedMethodRid;
    const remappedParamToken = 0x08000000 + remappedParamRid;
    const remappedGenericParamToken = 0x2a000000 + remappedGenericParamRid;
    assert.equal(tokenMap.get(survivingToken), remappedMethodToken);
    assert.equal(tokenMap.get(0x08000000 + survivingParamRid), remappedParamToken);
    assert.equal(tokenMap.get(0x2a000000 + survivingGenericParamRid), remappedGenericParamToken);
    const survivingMethod = assembly.methods[remappedMethodRid - 1];
    assert.equal(survivingMethod.name, "Keep");
    assert.deepEqual(survivingMethod.parameterRids, [remappedParamRid]);
    assert.equal(survivingMethod.parameters[0].rid, remappedParamRid);
    const constant = assembly.tables.get(11).at(-1);
    assert.equal(constant.Parent.target.rid, remappedParamRid);
    assert.equal(constant.Parent.raw, encodeCodedIndex(8, remappedParamRid, "HasConstant"));
    assert.equal(assembly.tables.get(30).at(-1).Token, remappedParamToken);
    assert.equal(assembly.tables.get(31).at(-1).Token, remappedGenericParamToken);
    const survivingGenericParam = assembly.genericParams.find((parameter) =>
      parameter.owner.table === 6 && parameter.owner.rid === remappedMethodRid
    );
    assert.equal(survivingGenericParam.rid, remappedGenericParamRid);
    const constraint = assembly.genericParamConstraints.find((item) => item.rid === constraintRid);
    assert.equal(constraint.ownerRid, remappedGenericParamRid);
    if (useParamPointerTable) {
      assert.equal(assembly.tables.get(7).find((pointer) =>
        pointer.Param.rid === remappedParamRid
      ).Param.rid, remappedParamRid);
    }

    const reparsed = parseAssembly(assembly.serialize());
    assert.equal(reparsed.methods[remappedMethodRid - 1].name, "Keep");
    assert.equal(reparsed.methods[remappedMethodRid - 1].parameters[0].rid, remappedParamRid);
    assert.equal(reparsed.genericParams.find((parameter) =>
      parameter.owner.table === 6 && parameter.owner.rid === remappedMethodRid
    ).rid, remappedGenericParamRid);
    assert.equal(reparsed.genericParamConstraints.find((item) =>
      item.rid === constraintRid
    ).ownerRid, remappedGenericParamRid);
  }
});

test("MethodDef removal refuses live CIL references without mutating metadata", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const targetOwner = assembly.types.at(-1);
  const targetToken = assembly.addMethod({
    owner: { table: "TypeDef", rid: targetOwner.rid },
    name: "ReferencedMethod",
    flags: 0x0096,
    signature: Uint8Array.of(0, 0, 1),
    body: Uint8Array.of(0x06, 0x2a)
  });
  const caller = assembly.methods.find((method) =>
    assembly.getMethodBody(method.rid)?.instructions.some((instruction) =>
      ["call", "callvirt"].includes(instruction.opcode.name)
    )
  );
  assert.ok(caller);
  const call = assembly.getMethodBody(caller.rid).instructions.find((instruction) =>
    ["call", "callvirt"].includes(instruction.opcode.name)
  );
  assembly.setInstructionOperand(caller.rid, call.offset, targetToken);
  const methodCount = assembly.tables.counts[6];
  assert.throws(() => assembly.removeMethod(targetToken & 0x00ffffff),
    /referenced by CIL/);
  assert.equal(assembly.tables.counts[6], methodCount);
});

test("Constant rows append and replace encoded values without changing their parent", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= 1n << 11n;
  const integerField = assembly.types.flatMap((type) => type.fields)
    .find((field) => parseSignature(field.signature).type.elementType === 0x08);
  assert.ok(integerField);
  const token = assembly.addConstant({
    parent: { table: "Field", rid: integerField.rid },
    type: 0x08,
    value: Uint8Array.of(42, 0, 0, 0)
  });
  const rid = token & 0x00ffffff;
  assert.equal(token >>> 24, 0x0b);
  assembly.replaceConstant(rid, { value: Uint8Array.of(43, 0, 0, 0) });
  assert.equal(assembly.tables.row(11, rid).Parent.raw, encodeCodedIndex(
    4, integerField.rid, "HasConstant"
  ));
  assert.throws(() => assembly.addConstant({
    parent: { table: "Field", rid: integerField.rid },
    type: 0x08,
    value: Uint8Array.of(0, 0, 0, 0)
  }), /already has a value/);
  assert.throws(() => assembly.addConstant({
    parent: { table: "Field", rid: integerField.rid },
    type: 0x02,
    value: Uint8Array.of(2)
  }), /Boolean constants must be encoded/);
  assert.throws(() => assembly.addConstant({
    parent: { table: "Param", rid: 1 },
    type: 0x08,
    value: Uint8Array.of(1, 0, 0, 0)
  }), /violate declared Parent ordering/);

  const reparsed = parseAssembly(assembly.serialize());
  const constant = reparsed.tables.row(11, rid);
  assert.equal(constant.Type, 0x08);
  assert.deepEqual(constant.Parent.target, {
    table: 4,
    tableName: "Field",
    rid: integerField.rid
  });
  assert.deepEqual(reparsed.heaps.getBlob(constant.Value), Uint8Array.of(43, 0, 0, 0));
  reparsed.removeConstant(rid);
  const withoutConstant = parseAssembly(reparsed.serialize());
  assert.equal(withoutConstant.tables.counts[11], 0);
});

test("MethodDef names and flags can be replaced without changing row identity", () => {
  const assembly = parseAssembly(fixture);
  const method = assembly.methods[0];
  const originalFlags = method.flags;
  const originalImplFlags = method.implFlags;
  assert.throws(() => assembly.replaceMethod(method.rid, { name: "" }), /non-empty null-free/);
  assert.equal(assembly.modified, false);
  assembly.replaceMethod(method.rid, {
    name: "TierTwoRenamedMethod",
    flags: originalFlags ^ 0x0080
  });
  const reparsed = parseAssembly(assembly.serialize());
  const updated = reparsed.methods[method.rid - 1];
  assert.equal(updated.rid, method.rid);
  assert.equal(updated.name, "TierTwoRenamedMethod");
  assert.equal(updated.flags, originalFlags ^ 0x0080);
  assert.equal(updated.implFlags, originalImplFlags);
});

test("TypeDef names, flags, and base types can be replaced without changing row identity", () => {
  const assembly = parseAssembly(fixture);
  const type = assembly.types[1];
  assert.throws(() => assembly.replaceTypeDef(type.rid, {
    extends: { table: "TypeDef", rid: type.rid }
  }), /cannot extend itself/);
  assert.equal(assembly.modified, false);
  const baseType = assembly.typeRefs[0];
  assert.ok(baseType);
  assembly.replaceTypeDef(type.rid, {
    name: "TierTwoType",
    namespace: "TierTwo.Tests",
    extends: { table: "TypeRef", rid: baseType.rid }
  });
  const reparsed = parseAssembly(assembly.serialize());
  const updated = reparsed.types[type.rid - 1];
  assert.equal(updated.rid, type.rid);
  assert.equal(updated.name, "TierTwoType");
  assert.equal(updated.namespace, "TierTwo.Tests");
  assert.deepEqual(updated.extends, {
    table: 1,
    tableName: "TypeRef",
    rid: baseType.rid
  });
});

test("TypeDefs append with stable tokens and can receive fields before serialization", () => {
  const assembly = parseAssembly(fixture);
  const typeCount = assembly.tables.counts[2];
  assert.throws(() => assembly.addTypeDef({
    name: "InvalidBase",
    extends: { table: "TypeRef", rid: assembly.tables.counts[1] + 1 }
  }), /existing TypeDef, TypeRef, or TypeSpec/);
  assert.equal(assembly.tables.counts[2], typeCount);

  const token = assembly.addTypeDef({
    name: "GeneratedType",
    namespace: "JsILNET.Generated",
    flags: 0x00100001,
    extends: { table: "TypeDef", rid: 2 }
  });
  const typeRid = token & 0x00ffffff;
  assert.equal(token >>> 24, 2);
  assert.equal(typeRid, typeCount + 1);
  assembly.addField({
    owner: { table: "TypeDef", rid: typeRid },
    name: "Value",
    signature: Uint8Array.of(0x06, 0x08)
  });

  const reparsed = parseAssembly(assembly.serialize());
  const generated = reparsed.types[typeRid - 1];
  assert.equal(generated.name, "GeneratedType");
  assert.equal(generated.namespace, "JsILNET.Generated");
  assert.equal(generated.extends.rid, 2);
  assert.equal(generated.fields.length, 1);
  assert.equal(generated.fields[0].name, "Value");
});

test("TypeDef append initializes #- pointer-table ownership boundaries", () => {
  const assembly = parseAssembly(fixture);
  const tableStream = assembly.metadataRoot.streams.get("#~");
  assert.ok(tableStream);
  assembly.metadataRoot.streams.delete("#~");
  assembly.metadataRoot.streams.set("#-", tableStream);
  for (const [pointerId, targetId, listName, targetName] of [
    [3, 4, "FieldList", "Field"],
    [5, 6, "MethodList", "Method"]
  ]) {
    const targetRows = assembly.tables.get(targetId);
    const pointerRows = targetRows.map((target, index) => ({
      table: pointerId,
      tableName: assembly.tables.get(pointerId)?.[0]?.tableName ??
        (pointerId === 3 ? "FieldPtr" : "MethodPtr"),
      rid: index + 1,
      [targetName]: {
        raw: target.rid,
        table: targetId,
        tableName: target.tableName,
        rid: target.rid
      }
    }));
    assembly.tables.rows.set(pointerId, pointerRows);
    assembly.tables.counts[pointerId] = pointerRows.length;
    assembly.tables.valid |= 1n << BigInt(pointerId);
    for (const row of assembly.tables.get(2)) {
      const index = row[listName].rid;
      row[listName] = {
        raw: index,
        table: pointerId,
        tableName: pointerRows[0]?.tableName ?? (pointerId === 3 ? "FieldPtr" : "MethodPtr"),
        rid: index
      };
    }
  }
  const rid = assembly.tables.counts[2] + 1;
  assembly.addTypeDef({ name: "PointerBackedType", extends: { table: "TypeDef", rid: 2 } });
  assembly.addField({
    owner: { table: "TypeDef", rid },
    name: "Value",
    signature: Uint8Array.of(0x06, 0x08)
  });

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.metadataRoot.streams.has("#-"), true);
  assert.equal(reparsed.types[rid - 1].fields[0].name, "Value");
  assert.equal(reparsed.tables.row(3, reparsed.tables.counts[3]).Field.rid,
    reparsed.tables.counts[4]);
});

test("TypeDef removal supports unreferenced empty types and protects owned rows", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const token = assembly.addTypeDef({
    name: "DisposableType",
    extends: { table: "TypeDef", rid: 2 }
  });
  const rid = token & 0x00ffffff;
  assert.equal(assembly.removeTypeDef(rid), assembly);
  assert.equal(assembly.tables.counts[2], rid - 1);
  assert.equal(parseAssembly(assembly.serialize()).types.at(-1).name,
    assembly.types.at(-1).name);

  const owned = parseAssembly(withoutDebugDirectory());
  const ownedToken = owned.addTypeDef({
    name: "NonEmptyType",
    extends: { table: "TypeDef", rid: 2 }
  });
  const ownedRid = ownedToken & 0x00ffffff;
  owned.addField({
    owner: { table: "TypeDef", rid: ownedRid },
    name: "Value",
    signature: Uint8Array.of(0x06, 0x08)
  });
  assert.throws(() => owned.removeTypeDef(ownedRid), /no fields, methods, events/);
  assert.equal(owned.tables.counts[2], ownedRid);

  const referenced = parseAssembly(withoutDebugDirectory());
  const referencedRid = referenced.addTypeDef({
    name: "ReferencedType",
    extends: { table: "TypeDef", rid: 2 }
  }) & 0x00ffffff;
  referenced.addTypeDef({
    name: "DerivedType",
    extends: { table: "TypeDef", rid: referencedRid }
  });
  assert.throws(() => referenced.removeTypeDef(referencedRid), /referenced by TypeDef.Extends/);
  assert.equal(referenced.tables.counts[2], referencedRid + 1);

  const withAddedBody = parseAssembly(withoutDebugDirectory());
  const bodyVictimRid = withAddedBody.addTypeDef({
    name: "BodyVictim",
    extends: { table: "TypeDef", rid: 2 }
  }) & 0x00ffffff;
  const bodyOwnerRid = withAddedBody.addTypeDef({
    name: "BodyOwner",
    extends: { table: "TypeDef", rid: 2 }
  }) & 0x00ffffff;
  withAddedBody.addMethod({
    owner: { table: "TypeDef", rid: bodyOwnerRid },
    name: "Body",
    flags: 0x0006,
    signature: Uint8Array.of(0x00, 0x00, 0x01),
    body: Uint8Array.of(0x0a, 0x14, 0x2a)
  });
  assert.throws(() => withAddedBody.removeTypeDef(bodyVictimRid), /added method bodies/);
  assert.equal(withAddedBody.tables.counts[2], bodyOwnerRid);
});

test("non-trailing TypeDef removal remaps metadata, signatures, and CIL tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const removedToken = assembly.addTypeDef({
    name: "DisposableBeforeSurvivor",
    extends: { table: "TypeDef", rid: 2 }
  });
  const removedRid = removedToken & 0x00ffffff;
  const survivorToken = assembly.addTypeDef({
    name: "Survivor`1",
    extends: { table: "TypeDef", rid: 2 }
  });
  const survivorRid = survivorToken & 0x00ffffff;
  const interfaceType = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assembly.addInterfaceImplementation({
    owner: { table: "TypeDef", rid: survivorRid },
    interfaceType: { table: "TypeRef", rid: interfaceType.rid }
  });
  const signature = Uint8Array.from([
    0x12,
    ...appendCompressedUInt(encodeCodedIndex(2, survivorRid, "TypeDefOrRef"))
  ]);
  assembly.addField({
    owner: { table: "TypeDef", rid: survivorRid },
    name: "Self",
    signature: Uint8Array.from([0x06, ...signature])
  });
  const typeSpec = assembly.addTypeSpec({ signature });
  const genericParamToken = assembly.addGenericParam({
    owner: { table: "TypeDef", rid: survivorRid },
    name: "T",
    number: 0
  });
  const castSite = assembly.methods.flatMap((method) =>
    assembly.getInstructions(method.rid).map((instruction) => ({ method, instruction }))
  ).find(({ instruction }) => instruction.opcode.name === "castclass");
  assert.ok(castSite);
  assembly.setInstructionOperand(
    castSite.method.rid,
    castSite.instruction.offset,
    survivorToken
  );
  const finallyMethod = assembly.methods.find((method) => method.name === "Finally");
  const finallyBody = assembly.getMethodBody(finallyMethod.rid);
  const exceptionSection = finallyBody.sections[0];
  const catchClause = exceptionSection.clauses[0];
  const exceptionView = new DataView(
    assembly.bytes.buffer,
    assembly.bytes.byteOffset,
    assembly.bytes.byteLength
  );
  if (exceptionSection.fat) {
    exceptionView.setUint32(exceptionSection.offset + 4, 0, true);
  } else {
    exceptionView.setUint16(exceptionSection.offset + 4, 0, true);
  }
  const exceptionTokenOffset = exceptionSection.offset + 4 +
    (exceptionSection.fat ? 20 : 8);
  exceptionView.setUint32(exceptionTokenOffset, survivorToken, true);
  catchClause.flags = 0;
  catchClause.classTokenOrFilterOffset = survivorToken;

  const tokenMap = assembly.removeTypeDef(removedRid);
  assert.equal(tokenMap.get(survivorToken), survivorToken - 1);
  const reparsed = parseAssembly(assembly.serialize());
  const nextSurvivorRid = survivorRid - 1;
  assert.equal(reparsed.types[nextSurvivorRid - 1].name, "Survivor`1");
  assert.equal(reparsed.tables.get(9).at(-1).Class.rid, nextSurvivorRid);
  const parsedField = parseSignature(
    reparsed.heaps.getBlob(reparsed.tables.row(4, reparsed.types[nextSurvivorRid - 1].fieldRids[0]).Signature)
  );
  assert.deepEqual(parsedField.type.type, {
    table: 2,
    tableName: "TypeDef",
    rid: nextSurvivorRid
  });
  assert.deepEqual(reparsed.typeSpecs.find((entry) => entry.rid === (typeSpec & 0x00ffffff))
    .parsedSignature.type, {
    table: 2,
    tableName: "TypeDef",
    rid: nextSurvivorRid
  });
  assert.equal(reparsed.genericParams.find((parameter) =>
    parameter.rid === (genericParamToken & 0x00ffffff)
  )
    .owner.rid, nextSurvivorRid);
  assert.equal(reparsed.getInstructions(castSite.method.rid).find((instruction) =>
    instruction.offset === castSite.instruction.offset
  ).operand.value, tokenMap.get(survivorToken));
  const reparsedFinally = reparsed.getMethodBody(finallyMethod.rid);
  assert.equal(reparsedFinally.sections[0].clauses[0].classTokenOrFilterOffset,
    tokenMap.get(survivorToken));
});

test("TypeDef removal refuses sorted-key reordering without mutation", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const removableRid = assembly.addTypeDef({
    name: "RemovableType",
    extends: { table: "TypeDef", rid: 2 }
  }) & 0x00ffffff;
  const survivorRid = assembly.addTypeDef({
    name: "SortedOwner",
    extends: { table: "TypeDef", rid: 2 }
  }) & 0x00ffffff;
  const genericRows = assembly.tables.get(42);
  const methodOwnerRid = survivorRid - 1;
  genericRows.push({
    table: 42,
    tableName: "GenericParam",
    rid: genericRows.length + 1,
    Number: 0,
    Flags: 0,
    Owner: {
      raw: encodeCodedIndex(6, methodOwnerRid, "TypeOrMethodDef"),
      target: { table: 6, tableName: "MethodDef", rid: methodOwnerRid }
    },
    Name: 0
  });
  genericRows.push({
    table: 42,
    tableName: "GenericParam",
    rid: genericRows.length + 1,
    Number: 0,
    Flags: 0,
    Owner: {
      raw: encodeCodedIndex(2, survivorRid, "TypeOrMethodDef"),
      target: { table: 2, tableName: "TypeDef", rid: survivorRid }
    },
    Name: 0
  });
  assembly.tables.rows.set(42, genericRows);
  assembly.tables.counts[42] = genericRows.length;
  assembly.tables.valid |= 1n << 42n;
  assembly.tables.sorted |= 1n << 42n;
  const beforeCount = assembly.tables.counts[2];
  const beforeOwner = genericRows.at(-1).Owner.raw;

  assert.throws(() => assembly.removeTypeDef(removableRid), /would violate sorted GenericParam order/);
  assert.equal(assembly.tables.counts[2], beforeCount);
  assert.equal(assembly.tables.row(42, genericRows.length).Owner.raw, beforeOwner);
  assert.equal(assembly.types[survivorRid - 1].rid, survivorRid);
});

test("FieldMarshal rows append, replace, and remove with parent ordering preserved", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= 1n << 13n;
  assembly.addFieldMarshal({
    parent: { table: "Field", rid: 1 },
    nativeType: Uint8Array.of(0x20)
  });
  assembly.addFieldMarshal({
    parent: { table: "Param", rid: 1 },
    nativeType: Uint8Array.of(0x07)
  });
  assert.throws(() => assembly.addFieldMarshal({
    parent: { table: "Field", rid: 1 },
    nativeType: Uint8Array.of(0x20)
  }), /already has a descriptor/);
  assembly.replaceFieldMarshal(1, Uint8Array.of(0x21));
  assembly.removeFieldMarshal(1);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.counts[13], 1);
  const row = reparsed.tables.row(13, 1);
  assert.deepEqual(row.Parent.target, { table: 8, tableName: "Param", rid: 1 });
  assert.deepEqual(reparsed.heaps.getBlob(row.NativeType), Uint8Array.of(0x07));
});

test("ClassLayout and FieldLayout rows support validated in-place metadata edits", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= (1n << 15n) | (1n << 16n);
  const owner = assembly.types.find((type) =>
    !assembly.tables.rows.get(15)?.some((row) => row.Parent.rid === type.rid)
  );
  const field = assembly.types.flatMap((type) => type.fields).find((item) =>
    !assembly.tables.rows.get(16)?.some((row) => row.Field.rid === item.rid)
  );
  assert.ok(owner);
  assert.ok(field);
  const classLayoutRid = assembly.addClassLayout({
    owner: { table: "TypeDef", rid: owner.rid },
    packingSize: 4,
    classSize: 16
  });
  const fieldLayoutRid = assembly.addFieldLayout({ fieldRid: field.rid, offset: 0 });
  assembly.replaceClassLayout(classLayoutRid, { packingSize: 8, classSize: 24 });
  assembly.replaceFieldLayout(fieldLayoutRid, 4);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.row(15, classLayoutRid).PackingSize, 8);
  assert.equal(reparsed.tables.row(15, classLayoutRid).ClassSize, 24);
  assert.equal(reparsed.tables.row(15, classLayoutRid).Parent.rid, owner.rid);
  assert.equal(reparsed.tables.row(16, fieldLayoutRid).Offset, 4);
  assert.equal(reparsed.tables.row(16, fieldLayoutRid).Field.rid, field.rid);
  reparsed.removeClassLayout(classLayoutRid);
  reparsed.removeFieldLayout(fieldLayoutRid);
  const withoutLayouts = parseAssembly(reparsed.serialize());
  assert.equal(withoutLayouts.tables.counts[15], assembly.tables.counts[15] - 1);
  assert.equal(withoutLayouts.tables.counts[16], assembly.tables.counts[16] - 1);
});

test("FieldRVA rows validate static primitive fields and round-trip add/replace/remove", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.at(-1);
  const fieldToken = assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "RvaValue",
    flags: 0x10,
    signature: Uint8Array.of(0x06, 0x08)
  });
  const fieldRid = fieldToken & 0x00ffffff;
  const dataSection = assembly.pe.sections.find((section) => section.rawSize >= 8);
  assert.ok(dataSection);
  const firstRva = dataSection.virtualAddress;
  const nextRva = firstRva + 4;

  assert.throws(() => assembly.addFieldRva(fieldRid, 0), /non-zero unsigned 32-bit RVA/);
  assert.throws(() => assembly.addFieldRva(
    fieldRid,
    dataSection.virtualAddress + dataSection.rawSize - 1
  ), /not backed by file data/);
  const rowRid = assembly.addFieldRva(fieldRid, firstRva);
  assert.equal(assembly.types.at(-1).fields.at(-1).rva, firstRva);
  assembly.replaceFieldRva(rowRid, nextRva);
  assert.equal(assembly.types.at(-1).fields.at(-1).rva, nextRva);
  assert.throws(() => assembly.replaceField(fieldRid, { flags: 0 }), /must remain static/);
  assert.throws(() => assembly.replaceFieldSignature(fieldRid, Uint8Array.of(0x06, 0x0e)),
    /must retain a fixed-width primitive signature/);
  const instanceFieldToken = assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "InstanceValue",
    signature: Uint8Array.of(0x06, 0x08)
  });
  assert.throws(() => assembly.addFieldRva(instanceFieldToken & 0x00ffffff, firstRva),
    /requires a static Field/);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.row(29, rowRid).RVA, nextRva);
  assert.equal(reparsed.types.at(-1).fields.find((field) => field.rid === fieldRid).rva, nextRva);
  reparsed.removeFieldRva(rowRid);
  assert.equal(reparsed.types.at(-1).fields.find((field) => field.rid === fieldRid).rva, null);
  assert.equal(parseAssembly(reparsed.serialize()).tables.counts[29], 0);
});

test("MethodSemantics rows validate owners and round-trip add/replace/remove", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.find((type) =>
    type.propertyRids.length > 0 && type.methodRids.length > 1
  );
  assert.ok(owner);
  assembly.tables.sorted &= ~(1n << 24n);
  const associationRid = owner.propertyRids.at(-1);
  const originalCount = assembly.tables.counts[24];
  const foreignOwner = assembly.types.find((type) =>
    type.rid !== owner.rid && type.methodRids.length > 0
  );
  assert.ok(foreignOwner);
  assert.throws(() => assembly.addMethodSemantics({
    methodRid: foreignOwner.methodRids[0],
    association: { table: "Property", rid: associationRid },
    semantics: 0x04
  }), /same TypeDef/);
  assert.equal(assembly.tables.counts[24], originalCount);
  const rid = assembly.addMethodSemantics({
    methodRid: owner.methodRids[0],
    association: { table: "Property", rid: associationRid },
    semantics: 0x04
  });
  assert.throws(() => assembly.addMethodSemantics({
    methodRid: owner.methodRids[0],
    association: { table: "Property", rid: associationRid },
    semantics: 0x08
  }), /not valid for the association/);

  const reparsed = parseAssembly(assembly.serialize());
  const row = reparsed.tables.row(24, rid);
  assert.equal(row.Method.rid, owner.methodRids[0]);
  assert.equal(row.Association.target.table, 23);
  assert.equal(row.Association.target.rid, associationRid);
  reparsed.replaceMethodSemantics(rid, { methodRid: owner.methodRids[1] });
  assert.equal(parseAssembly(reparsed.serialize()).tables.row(24, rid).Method.rid, owner.methodRids[1]);
  reparsed.removeMethodSemantics(rid);
  assert.equal(parseAssembly(reparsed.serialize()).tables.counts[24], originalCount);
});

test("NestedClass rows preserve ordering and reject cyclic TypeDef relationships", () => {
  const assembly = parseAssembly(fixture);
  const rid = assembly.addNestedClass({
    nestedType: { table: "TypeDef", rid: 3 },
    enclosingType: { table: "TypeDef", rid: 1 }
  });
  assembly.replaceNestedClass(rid, {
    enclosingType: { table: "TypeDef", rid: 2 }
  });
  assert.throws(() => assembly.addNestedClass({
    nestedType: { table: "TypeDef", rid: 2 },
    enclosingType: { table: "TypeDef", rid: 3 }
  }), /violate declared NestedClass ordering/);
  assembly.tables.sorted &= ~(1n << 41n);
  assert.throws(() => assembly.addNestedClass({
    nestedType: { table: "TypeDef", rid: 2 },
    enclosingType: { table: "TypeDef", rid: 3 }
  }), /create a TypeDef cycle/);

  const reparsed = parseAssembly(assembly.serialize());
  const row = reparsed.tables.row(41, rid);
  assert.equal(row.NestedClass.rid, 3);
  assert.equal(row.EnclosingClass.rid, 2);
  reparsed.removeNestedClass(rid);
  assert.equal(parseAssembly(reparsed.serialize()).tables.counts[41], 0);
});

test("DeclSecurity rows preserve parent/action uniqueness and allow safe removal", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= 1n << 14n;
  const methodRid = 1;
  const typeRid = 1;
  assembly.addDeclSecurity({
    parent: { table: "TypeDef", rid: typeRid },
    action: 2,
    permissionSet: Uint8Array.of(0x2e, 0)
  });
  const methodSecurityRid = assembly.addDeclSecurity({
    parent: { table: "MethodDef", rid: methodRid },
    action: 2,
    permissionSet: Uint8Array.of(0x2e, 0)
  });
  assembly.replaceDeclSecurity(methodSecurityRid, {
    action: 3,
    permissionSet: Uint8Array.of(0x2e, 1)
  });
  const updatedPermissionSet = assembly.tables.row(14, methodSecurityRid).PermissionSet;
  assert.throws(() => assembly.replaceDeclSecurity(methodSecurityRid, {
    permissionSet: new Uint8Array()
  }), /non-empty Uint8Array/);
  assert.equal(assembly.tables.row(14, methodSecurityRid).PermissionSet, updatedPermissionSet);
  assert.throws(() => assembly.addDeclSecurity({
    parent: { table: "MethodDef", rid: methodRid },
    action: 3,
    permissionSet: Uint8Array.of(0x2e, 0)
  }), /Duplicate DeclSecurity action/);

  const reparsed = parseAssembly(assembly.serialize());
  const row = reparsed.tables.row(14, methodSecurityRid);
  assert.equal(row.Action, 3);
  assert.equal(row.Parent.target.table, 6);
  assert.equal(row.Parent.target.rid, methodRid);
  assert.deepEqual(reparsed.heaps.getBlob(row.PermissionSet), Uint8Array.of(0x2e, 1));
  reparsed.removeDeclSecurity(methodSecurityRid);
  const withoutMethodSecurity = parseAssembly(reparsed.serialize());
  assert.equal(withoutMethodSecurity.tables.counts[14], 1);
  assert.equal(withoutMethodSecurity.tables.row(14, 1).Parent.target.table, 2);
});

test("MethodImpl rows validate method references and round-trip replacement/removal", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= 1n << 25n;
  const owner = assembly.types.find((type) => type.methodRids.length > 0);
  const bodyRid = owner.methodRids[0];
  const memberRef = assembly.memberRefs.find((reference) =>
    parseSignature(reference.signature, { counts: assembly.tables.counts }).kind === "method"
  );
  const otherMethodRid = assembly.methods.find((method) => method.rid !== bodyRid).rid;
  assert.ok(memberRef);
  const rid = assembly.addMethodImpl({
    owner: { table: "TypeDef", rid: owner.rid },
    body: { table: "MethodDef", rid: bodyRid },
    declaration: { table: "MemberRef", rid: memberRef.rid }
  });
  assert.throws(() => assembly.addMethodImpl({
    owner: { table: "TypeDef", rid: owner.rid },
    body: { table: "MethodDef", rid: bodyRid },
    declaration: { table: "MemberRef", rid: memberRef.rid }
  }), /already contains this implementation/);
  assembly.replaceMethodImpl(rid, {
    declaration: { table: "MethodDef", rid: otherMethodRid }
  });

  const reparsed = parseAssembly(assembly.serialize());
  const row = reparsed.tables.row(25, rid);
  assert.equal(row.Class.rid, owner.rid);
  assert.equal(row.MethodBody.target.rid, bodyRid);
  assert.equal(row.MethodDeclaration.target.table, 6);
  assert.equal(row.MethodDeclaration.target.rid, otherMethodRid);
  reparsed.removeMethodImpl(rid);
  assert.equal(parseAssembly(reparsed.serialize()).tables.counts[25], 0);
});

test("ImplMap rows bind PInvoke fields to ModuleRefs and clear flags on removal", () => {
  const assembly = parseAssembly(fixture);
  assembly.tables.sorted |= 1n << 28n;
  const field = assembly.types.flatMap((type) => type.fields)[0];
  assembly.replaceField(field.rid, { flags: field.flags | 0x2000 });
  const moduleRefToken = assembly.addModuleRef({ name: "native.dll" });
  const rid = assembly.addImplMap({
    member: { table: "Field", rid: field.rid },
    moduleRefRid: moduleRefToken & 0x00ffffff,
    importName: "NativeEntry"
  });
  assert.throws(() => assembly.addImplMap({
    member: { table: "Field", rid: field.rid },
    moduleRefRid: moduleRefToken & 0x00ffffff,
    importName: "NativeEntry"
  }), /already has a mapping/);
  assembly.replaceImplMap(rid, { importName: "RenamedEntry", mappingFlags: 0x40 });

  const reparsed = parseAssembly(assembly.serialize());
  const row = reparsed.tables.row(28, rid);
  assert.equal(row.ImportName && reparsed.heaps.getString(row.ImportName), "RenamedEntry");
  assert.equal(row.MappingFlags, 0x40);
  assert.equal(row.ImportScope.rid, moduleRefToken & 0x00ffffff);
  assert.ok(reparsed.types.flatMap((type) => type.fields)
    .find((item) => item.rid === field.rid).flags & 0x2000);
  reparsed.removeImplMap(rid);
  const withoutMap = parseAssembly(reparsed.serialize());
  assert.equal(withoutMap.tables.counts[28], 0);
  assert.equal(withoutMap.tables.row(4, field.rid).Flags & 0x2000, 0);
});

test("Param removal rejects live references and remaps surviving rows in #~ and #-", () => {
  for (const usePointerTable of [false, true]) {
    const assembly = parseAssembly(fixture);
    if (usePointerTable) {
      const tableStream = assembly.metadataRoot.streams.get("#~");
      assert.ok(tableStream);
      assembly.metadataRoot.streams.delete("#~");
      assembly.metadataRoot.streams.set("#-", tableStream);
      const paramRows = assembly.tables.get(8);
      const pointers = paramRows.map((param, index) => ({
        table: 7,
        tableName: "ParamPtr",
        rid: index + 1,
        Param: {
          raw: param.rid,
          table: 8,
          tableName: "Param",
          rid: param.rid
        }
      }));
      assembly.tables.rows.set(7, pointers);
      assembly.tables.counts[7] = pointers.length;
      assembly.tables.valid |= 1n << 7n;
      for (const methodRow of assembly.tables.get(6)) {
        methodRow.ParamList = {
          raw: methodRow.ParamList.rid,
          table: 7,
          tableName: "ParamPtr",
          rid: methodRow.ParamList.rid
        };
      }
    }

    const method = assembly.methods.at(-1);
    assembly.replaceMethodSignature(method.rid, Uint8Array.from([0x20, 0x02, 0x01, 0x08, 0x08]));
    const firstRid = assembly.addParam({
      owner: { table: "MethodDef", rid: method.rid },
      sequence: 1,
      name: "first"
    });
    const secondRid = assembly.addParam({
      owner: { table: "MethodDef", rid: method.rid },
      sequence: 2,
      name: "second"
    });
    const parent = {
      raw: encodeCodedIndex(8, firstRid, "HasConstant"),
      target: { table: 8, tableName: "Param", rid: firstRid }
    };
    assembly.tables.rows.set(11, [{
      table: 11,
      tableName: "Constant",
      rid: 1,
      Type: 8,
      Padding: 0,
      Parent: parent,
      Value: 0
    }]);
    assembly.tables.counts[11] = 1;
    assembly.tables.valid |= 1n << 11n;
    assert.throws(() => assembly.removeParam(firstRid), /referenced by Constant.Parent/);
    assert.equal(assembly.tables.row(8, firstRid).rid, firstRid);
    const laterParent = {
      raw: encodeCodedIndex(8, secondRid, "HasConstant"),
      target: { table: 8, tableName: "Param", rid: secondRid }
    };
    assembly.tables.rows.set(11, [{
      table: 11,
      tableName: "Constant",
      rid: 1,
      Type: 8,
      Padding: 0,
      Parent: laterParent,
      Value: 0
    }]);

    const remap = assembly.removeParam(firstRid);
    assert.equal(remap.get(secondRid), secondRid - 1);
    assert.equal(assembly.tables.row(11, 1).Parent.target.rid, secondRid - 1);
    assert.equal(assembly.tables.row(11, 1).Parent.raw,
      encodeCodedIndex(8, secondRid - 1, "HasConstant"));
    assembly.tables.rows.delete(11);
    assembly.tables.counts[11] = 0;
    assembly.tables.valid &= ~(1n << 11n);
    assert.deepEqual(method.parameters.at(-1), {
      rid: secondRid - 1,
      flags: 0,
      sequence: 2,
      name: "second"
    });
    const reparsed = parseAssembly(assembly.serialize());
    const parsedMethod = reparsed.methods[method.rid - 1];
    assert.deepEqual(parsedMethod.parameters.at(-1), {
      rid: secondRid - 1,
      flags: 0,
      sequence: 2,
      name: "second"
    });
    if (usePointerTable) {
      assert.equal(reparsed.tables.get(7).length, reparsed.tables.get(8).length);
      assert.equal(reparsed.tables.get(7).at(-1).Param.rid, secondRid - 1);
    }
  }
});

test("Field names and flags can be replaced without changing the token", () => {
  const assembly = parseAssembly(fixture);
  const field = assembly.types.flatMap((type) => type.fields)[0];
  const token = 0x04000000 + field.rid;
  assert.throws(() => assembly.replaceField(field.rid, { flags: 0x10000 }),
    /unsigned 16-bit integer/);
  assert.equal(assembly.modified, false);

  assembly.replaceField(field.rid, { name: "RenamedField", flags: 6 });
  assert.equal(field.name, "RenamedField");
  assert.equal(field.flags, 6);
  assert.equal(assembly.tables.row(4, field.rid).Flags, 6);
  const reparsed = parseAssembly(assembly.serialize());
  const updated = reparsed.types.flatMap((type) => type.fields).find((item) => item.rid === field.rid);
  assert.equal(updated.name, "RenamedField");
  assert.equal(updated.flags, 6);
  assert.equal(0x04000000 + updated.rid, token);
});

test("fields append to the last TypeDef in optimized and pointer-table metadata", () => {
  for (const usePointerTable of [false, true]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    if (usePointerTable) {
      const tableStream = assembly.metadataRoot.streams.get("#~");
      assert.ok(tableStream);
      assembly.metadataRoot.streams.delete("#~");
      assembly.metadataRoot.streams.set("#-", tableStream);
      const fieldRows = assembly.tables.get(4);
      const pointerTargets = fieldRows.map((field) => field.rid);
      [pointerTargets[1], pointerTargets[2]] = [pointerTargets[2], pointerTargets[1]];
      const pointers = pointerTargets.map((fieldRid, index) => ({
        table: 3,
        tableName: "FieldPtr",
        rid: index + 1,
        Field: {
          raw: fieldRid,
          table: 4,
          tableName: "Field",
          rid: fieldRid
        }
      }));
      assembly.tables.rows.set(3, pointers);
      assembly.tables.counts[3] = pointers.length;
      assembly.tables.valid |= 1n << 3n;
      for (const typeRow of assembly.tables.get(2)) {
        typeRow.FieldList = {
          raw: typeRow.FieldList.rid,
          table: 3,
          tableName: "FieldPtr",
          rid: typeRow.FieldList.rid
        };
      }
    }

    const owner = assembly.types.at(-1);
    const token = assembly.addField({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "AppendedField",
      flags: 6,
      signature: Uint8Array.from([0x06, 0x08])
    });
    assert.equal(token, 0x04000000 + assembly.tables.counts[4]);
    assert.throws(() => assembly.addField({
      owner: { table: "TypeDef", rid: 1 },
      name: "NotLast",
      signature: Uint8Array.from([0x06, 0x08])
    }), /last TypeDef/);

    const reparsed = parseAssembly(assembly.serialize());
    const appended = reparsed.types[owner.rid - 1].fields.at(-1);
    assert.equal(appended.name, "AppendedField");
    assert.equal(appended.flags, 6);
    assert.deepEqual(parseSignature(appended.signature), {
      kind: "field",
      type: { kind: "primitive", elementType: 0x08 }
    });
    if (usePointerTable) {
      assert.equal(reparsed.metadataRoot.streams.has("#-"), true);
      assert.deepEqual(reparsed.types[owner.rid - 1].fieldRids.slice(0, 2), [3, 2]);
      assert.equal(reparsed.types[owner.rid - 1].fieldRids.at(-1), appended.rid);
      assert.equal(reparsed.tables.get(3).at(-1).Field.rid, appended.rid);
      const survivorToken = reparsed.addField({
        owner: { table: "TypeDef", rid: owner.rid },
        name: "SurvivingPointerField",
        flags: 6,
        signature: Uint8Array.of(0x06, 0x08)
      });
      const tokenMap = reparsed.removeField(appended.rid);
      assert.equal(tokenMap.get(survivorToken), token);
      const afterRemoval = parseAssembly(reparsed.serialize());
      assert.equal(afterRemoval.types[owner.rid - 1].fields.at(-1).name, "SurvivingPointerField");
      assert.equal(afterRemoval.tables.get(3).at(-1).Field.rid, token & 0x00ffffff);
    }
  }
});

test("field append refuses a non-bijective FieldPtr table without mutation", () => {
  const assembly = parseAssembly(fixture);
  const tableStream = assembly.metadataRoot.streams.get("#~");
  assert.ok(tableStream);
  assembly.metadataRoot.streams.delete("#~");
  assembly.metadataRoot.streams.set("#-", tableStream);
  const fieldRows = assembly.tables.get(4);
  const pointers = fieldRows.map((field, index) => ({
    table: 3,
    tableName: "FieldPtr",
    rid: index + 1,
    Field: {
      raw: field.rid,
      table: 4,
      tableName: "Field",
      rid: field.rid
    }
  }));
  pointers[1].Field = { ...pointers[1].Field, rid: pointers[0].Field.rid, raw: pointers[0].Field.rid };
  assembly.tables.rows.set(3, pointers);
  assembly.tables.counts[3] = pointers.length;
  assembly.tables.valid |= 1n << 3n;
  for (const typeRow of assembly.tables.get(2)) {
    typeRow.FieldList = {
      raw: typeRow.FieldList.rid,
      table: 3,
      tableName: "FieldPtr",
      rid: typeRow.FieldList.rid
    };
  }
  const before = Buffer.from(assembly.serialize());
  const owner = assembly.types.at(-1);
  assert.throws(() => assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "RejectedField",
    signature: Uint8Array.from([0x06, 0x08])
  }), /one-to-one FieldPtr table/);
  assert.equal(assembly.modified, false);
  assert.deepEqual(Buffer.from(assembly.serialize()), before);
});

test("Field removal rejects live metadata references without mutation", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  const fieldToken = assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "ReferencedField",
    signature: Uint8Array.from([0x06, 0x08])
  });
  const fieldRid = fieldToken & 0x00ffffff;
  const parent = {
    raw: encodeCodedIndex(4, fieldRid, "HasConstant"),
    target: { table: 4, tableName: "Field", rid: fieldRid }
  };
  assembly.tables.rows.set(11, [{
    table: 11,
    tableName: "Constant",
    rid: 1,
    Type: 8,
    Padding: 0,
    Parent: parent,
    Value: 0
  }]);
  assembly.tables.counts[11] = 1;
  assembly.tables.valid |= 1n << 11n;
  assert.throws(() => assembly.removeField(fieldRid), /referenced by Constant.Parent/);
  assert.equal(assembly.tables.row(4, fieldRid).rid, fieldRid);
  assert.equal(assembly.types.at(-1).fields.at(-1).name, "ReferencedField");
});

test("Field removal rejects live CIL references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  const fieldToken = assembly.addField({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "ReferencedFromCil",
    signature: Uint8Array.from([0x06, 0x08])
  });
  const method = assembly.methods.find((item) => assembly.getMethodBody(item.rid));
  assert.ok(method);
  const body = assembly.getMethodBody(method.rid);
  body.instructions.push({ operand: { kind: "token", value: fieldToken } });
  assert.throws(() => assembly.removeField(fieldToken & 0x00ffffff), /referenced by CIL/);
  assert.equal(assembly.tables.row(4, fieldToken & 0x00ffffff).rid, fieldToken & 0x00ffffff);
});

test("Field removal remaps later metadata tokens and preserves ownership in #~ and #-", () => {
  for (const usePointerTable of [false, true]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    if (usePointerTable) {
      const tableStream = assembly.metadataRoot.streams.get("#~");
      assert.ok(tableStream);
      assembly.metadataRoot.streams.delete("#~");
      assembly.metadataRoot.streams.set("#-", tableStream);
      const fieldRows = assembly.tables.get(4);
      const pointers = fieldRows.map((field, index) => ({
        table: 3,
        tableName: "FieldPtr",
        rid: index + 1,
        Field: {
          raw: field.rid,
          table: 4,
          tableName: "Field",
          rid: field.rid
        }
      }));
      assembly.tables.rows.set(3, pointers);
      assembly.tables.counts[3] = pointers.length;
      assembly.tables.valid |= 1n << 3n;
      for (const typeRow of assembly.tables.get(2)) {
        typeRow.FieldList = {
          raw: typeRow.FieldList.rid,
          table: 3,
          tableName: "FieldPtr",
          rid: typeRow.FieldList.rid
        };
      }
    }

    const owner = assembly.types.at(-1);
    const firstToken = assembly.addField({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "RemovedField",
      signature: Uint8Array.from([0x06, 0x08])
    });
    const secondToken = assembly.addField({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "SurvivingField",
      signature: Uint8Array.from([0x06, 0x08])
    });
    const secondRid = secondToken & 0x00ffffff;
    const parent = {
      raw: encodeCodedIndex(4, secondRid, "HasConstant"),
      target: { table: 4, tableName: "Field", rid: secondRid }
    };
    assembly.tables.rows.set(11, [{
      table: 11,
      tableName: "Constant",
      rid: 1,
      Type: 8,
      Padding: 0,
      Parent: parent,
      Value: 0
    }]);
    assembly.tables.counts[11] = 1;
    assembly.tables.valid |= 1n << 11n;
    if (usePointerTable) {
      const pointerRows = assembly.tables.get(3);
      const firstPointer = pointerRows.find((pointer) => pointer.Field.rid === (firstToken & 0x00ffffff));
      const secondPointer = pointerRows.find((pointer) => pointer.Field.rid === secondRid);
      [firstPointer.Field, secondPointer.Field] = [secondPointer.Field, firstPointer.Field];
    }

    const tokenMap = assembly.removeField(firstToken & 0x00ffffff);
    assert.equal(tokenMap.get(secondToken), secondToken - 1);
    assert.equal(assembly.tables.row(11, 1).Parent.target.rid, secondRid - 1);
    assert.equal(assembly.tables.row(11, 1).Parent.raw,
      encodeCodedIndex(4, secondRid - 1, "HasConstant"));
    assembly.tables.rows.delete(11);
    assembly.tables.counts[11] = 0;
    assembly.tables.valid &= ~(1n << 11n);
    const reparsed = parseAssembly(assembly.serialize());
    const surviving = reparsed.types[owner.rid - 1].fields.at(-1);
    assert.equal(surviving.name, "SurvivingField");
    assert.equal(surviving.rid, secondRid - 1);
    if (usePointerTable) {
      assert.equal(reparsed.tables.get(3).length, reparsed.tables.get(4).length);
      assert.equal(reparsed.tables.get(3).at(-1).Field.rid, surviving.rid);
    }
  }
});

test("parsed field and method signatures validate generic variables against their owners", () => {
  const invalidCases = [
    { table: 4, column: "Signature", blob: Uint8Array.from([0x06, 0x13, 0x00]), pattern: /Type generic variable !0/ },
    { table: 6, column: "Signature", blob: Uint8Array.from([0x00, 0x01, 0x08, 0x1e, 0x00]), pattern: /Method generic variable !!0/ },
    { table: 23, column: "Type", blob: Uint8Array.from([0x08, 0x00, 0x13, 0x00]), pattern: /Type generic variable !0/ }
  ];
  for (const invalidCase of invalidCases) {
    const assembly = parseAssembly(fixture);
    const owner = assembly.types.find((type) =>
      type.genericParams.length === 0 &&
      (invalidCase.table === 4
        ? type.fields.length > 0
        : invalidCase.table === 6
          ? type.methods.length > 0
          : type.propertyRids.length > 0)
    );
    const rid = invalidCase.table === 4
      ? owner.fields[0].rid
      : invalidCase.table === 6
        ? owner.methods[0].rid
        : owner.propertyRids[0];
    const streams = new Map([...assembly.metadataRoot.streams].map(([name, stream]) =>
      [name, stream.bytes.slice()]
    ));
    const appended = appendBlobHeap(streams.get("#Blob"), invalidCase.blob);
    streams.set("#Blob", appended.heap);
    assembly._heapStreams = streams;
    assembly.tables.row(invalidCase.table, rid)[invalidCase.column] = appended.index;
    assembly._metadataDirty = true;
    assert.throws(() => assembly.serialize(), invalidCase.pattern);
  }
});

test("property signature replacement validates generic variables and accessors", () => {
  const assembly = parseAssembly(fixture);
  const propertyType = assembly.types.find((type) => type.properties.length > 0);
  assert.ok(propertyType);
  const property = propertyType.properties[0];
  assert.equal(assembly.replacePropertySignature(property.rid, property.signature), assembly);
  assert.equal(assembly.modified, false);

  const invalidVariable = Uint8Array.from([
    0x08, 0x00, 0x13, ...appendCompressedUInt(propertyType.genericParams.length)
  ]);
  assert.throws(() => assembly.replacePropertySignature(property.rid, invalidVariable),
    /Type generic variable/);
  assert.equal(assembly.modified, false);

  const accessorAssociation = assembly.tables.get(24).find((row) =>
    row.Association.target?.table === 23 && row.Association.target.rid === property.rid
  );
  if (accessorAssociation) {
    const current = parseSignature(property.signature);
    const replacementElement = current.returnType.kind === "primitive" &&
      current.returnType.elementType === 0x0e ? 0x08 : 0x0e;
    const incompatible = Uint8Array.from([0x08, 0x00, replacementElement]);
    assert.throws(() => assembly.replacePropertySignature(property.rid, incompatible),
      /incompatible with its getter|incompatible with its setter/);
    assert.deepEqual(property.signature, assembly.heaps.getBlob(
      assembly.tables.row(23, property.rid).Type
    ));
    assert.equal(assembly.modified, false);
  }

  const updatedAssembly = parseAssembly(fixture);
  const updatedProperty = updatedAssembly.types
    .find((type) => type.name === "MarkerAttribute").properties[0];
  const getterRow = updatedAssembly.tables.get(24).find((row) =>
    row.Association.target?.table === 23 &&
    row.Association.target.rid === updatedProperty.rid &&
    (row.Semantics & 0x02) !== 0
  );
  assert.ok(getterRow);
  const getter = updatedAssembly.methods[getterRow.Method.rid - 1];
  const getterSignature = parseSignature(getter.signature);
  const propertySignature = parseSignature(updatedProperty.signature);
  const stringType = { kind: "primitive", elementType: 0x0e };
  updatedAssembly.replaceMethodSignature(getter.rid, encodeSignature({
    ...getterSignature,
    returnType: stringType
  }));
  updatedAssembly.replacePropertySignature(updatedProperty.rid, encodeSignature({
    ...propertySignature,
    returnType: stringType
  }));
  const reparsed = parseAssembly(updatedAssembly.serialize());
  const reparsedProperty = reparsed.types
    .find((type) => type.name === "MarkerAttribute").properties[0];
  assert.deepEqual(parseSignature(reparsedProperty.signature).returnType, stringType);
});

test("Property names and flags can be replaced without changing row identity", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.find((type) => type.properties.length > 0);
  assert.ok(owner);
  const property = owner.properties[0];
  const originalRid = property.rid;
  const nextName = `${property.name}Renamed`;
  const nextFlags = property.flags | 1;
  assert.equal(assembly.replaceProperty(originalRid, { name: nextName, flags: nextFlags }), assembly);
  assert.equal(property.name, nextName);
  assert.equal(property.flags, nextFlags);
  assert.equal(assembly.tables.row(23, originalRid).Flags, nextFlags);
  assert.throws(() => assembly.replaceProperty(originalRid, { name: "" }),
    /Property name must be a non-empty null-free string/);
  assert.equal(property.name, nextName);
  const reparsed = parseAssembly(assembly.serialize());
  const reparsedProperty = reparsed.types.flatMap((type) => type.properties)
    .find((item) => item.rid === originalRid);
  assert.equal(reparsedProperty.name, nextName);
  assert.equal(reparsedProperty.flags, nextFlags);

  const constantAssembly = parseAssembly(fixture);
  const constantProperty = constantAssembly.types.flatMap((type) => type.properties)
    .find((item) => parseSignature(item.signature).returnType.elementType === 0x08);
  assert.ok(constantProperty);
  constantAssembly.addConstant({
    parent: { table: "Property", rid: constantProperty.rid },
    type: 0x08,
    value: Uint8Array.of(42, 0, 0, 0)
  });
  const originalFlags = constantProperty.flags;
  assert.throws(() => constantAssembly.replaceProperty(constantProperty.rid, {
    flags: originalFlags & ~0x1000
  }), /must retain the HasDefault flag/);
  assert.equal(constantProperty.flags, originalFlags);
});

test("event replacement preserves identity and validates add/remove accessors", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.find((type) => type.events.length > 0);
  assert.ok(owner);
  const event = owner.events[0];
  const originalName = event.name;
  const token = 0x14000000 + event.rid;
  assembly.replaceEvent(event.rid, { name: `${originalName}Updated`, flags: event.flags | 1 });
  assert.equal(owner.events[0].name, `${originalName}Updated`);
  assert.equal(assembly.tables.row(20, event.rid).EventFlags, event.flags | 1);
  assert.throws(() => assembly.replaceEvent(event.rid, {
    eventType: { table: "TypeDef", rid: 1 }
  }), /incompatible with its add\/remove accessor/);
  assert.equal(assembly.types.flatMap((type) => type.events)
    .find((item) => item.rid === event.rid).eventType.rid, event.eventType.rid);

  const reparsed = parseAssembly(assembly.serialize());
  const reparsedEvent = reparsed.types.flatMap((type) => type.events)
    .find((item) => item.rid === event.rid);
  assert.equal(reparsedEvent.name, `${originalName}Updated`);
  assert.equal(reparsedEvent.flags, event.flags | 1);
  assert.equal(token, 0x14000000 + reparsedEvent.rid);
});

test("properties and events append to the last TypeDef and rebuild ownership maps", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.at(-1);
  const eventType = assembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(owner && eventType);
  const propertyRid = assembly.addProperty({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "AddedProperty",
    flags: 0,
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const eventRid = assembly.addEvent({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "AddedEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  assert.equal(assembly.heaps.getString(assembly.tables.row(23, propertyRid).Name), "AddedProperty");
  const reparsed = parseAssembly(assembly.serialize());
  const parsedOwner = reparsed.types[owner.rid - 1];
  assert.equal(parsedOwner.properties.at(-1).name, "AddedProperty");
  assert.deepEqual(parsedOwner.properties.at(-1).signature, Uint8Array.from([0x08, 0x00, 0x08]));
  assert.equal(parsedOwner.events.at(-1).name, "AddedEvent");
  assert.deepEqual(parsedOwner.events.at(-1).eventType, {
    table: 1,
    tableName: "TypeRef",
    rid: eventType.rid
  });
});

test("InterfaceImpl rows append and remove with validation and reference remapping", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  const firstType = assembly.typeRefs.find((type) => type.name === "EventArgs");
  const secondType = assembly.typeRefs.find((type) => type.name === "EventHandler");
  const replacementType = assembly.typeRefs.find((type) => type.name === "AttributeTargets");
  assert.ok(owner && firstType && secondType && replacementType);
  const initialCount = assembly.tables.counts[9];
  const firstRid = assembly.addInterfaceImplementation({
    owner: { table: "TypeDef", rid: owner.rid },
    interfaceType: { table: "TypeRef", rid: firstType.rid }
  });
  const secondRid = assembly.addInterfaceImplementation({
    owner: { table: "TypeDef", rid: owner.rid },
    interfaceType: { table: "TypeRef", rid: secondType.rid }
  });
  assert.equal(firstRid, initialCount + 1);
  assert.equal(secondRid, initialCount + 2);
  assert.throws(() => assembly.addInterfaceImplementation({
    owner: { table: "TypeDef", rid: owner.rid },
    interfaceType: { table: "TypeRef", rid: firstType.rid }
  }), /already exists/);
  assembly.replaceInterfaceImplementation(secondRid, {
    interfaceType: { table: "TypeRef", rid: replacementType.rid }
  });
  assert.equal(assembly.tables.row(9, secondRid).Interface.target.rid, replacementType.rid);
  assert.throws(() => assembly.replaceInterfaceImplementation(secondRid, {
    interfaceType: { table: "TypeRef", rid: firstType.rid }
  }), /already exists/);
  assert.equal(assembly.tables.row(9, secondRid).Interface.target.rid, replacementType.rid);

  const typeSpecRid = assembly.addTypeSpec({
    signature: Uint8Array.from([0x13, 0x01])
  }) & 0x00ffffff;
  assert.throws(() => assembly.addInterfaceImplementation({
    owner: { table: "TypeDef", rid: owner.rid },
    interfaceType: { table: "TypeSpec", rid: typeSpecRid }
  }), /TypeSpec generic variable !1 exceeds its declaring type's arity/);

  const attributeRows = assembly.tables.rows.get(12);
  assert.ok(attributeRows?.length);
  const attributeParent = {
    table: 9,
    tableName: "InterfaceImpl",
    rid: secondRid
  };
  const precedingAttributeParent = {
    table: 1,
    tableName: "TypeRef",
    rid: 3
  };
  const precedingAttribute = {
    ...attributeRows[0],
    rid: 1,
    Parent: {
      raw: encodeCodedIndex(1, precedingAttributeParent.rid, "HasCustomAttribute"),
      target: precedingAttributeParent
    }
  };
  const referencedAttribute = {
    ...attributeRows[0],
    rid: 2,
    Parent: {
      raw: encodeCodedIndex(9, secondRid, "HasCustomAttribute"),
      target: attributeParent
    }
  };
  assembly.tables.rows.set(12, [precedingAttribute, referencedAttribute]);
  assembly.tables.counts[12] = 2;
  assembly.tables.valid |= 1n << 12n;
  assert.throws(() => assembly.removeInterfaceImplementation(firstRid),
    /would violate sorted CustomAttribute order/);
  assert.equal(assembly.tables.counts[9], initialCount + 2);
  assembly.tables.rows.set(12, [{ ...referencedAttribute, rid: 1 }]);
  assembly.tables.counts[12] = 1;

  const rowMap = assembly.removeInterfaceImplementation(firstRid);
  assert.equal(rowMap.get(secondRid), firstRid);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.row(12, 1).Parent.target.rid, firstRid);
  const lastOwnerInterfaces = reparsed.tables.get(9)
    .filter((row) => row.Class.rid === owner.rid)
    .map((row) => row.Interface.target.rid);
  assert.ok(lastOwnerInterfaces.includes(replacementType.rid));
  assert.ok(!lastOwnerInterfaces.includes(secondType.rid));
  assert.ok(!lastOwnerInterfaces.includes(firstType.rid));
});

test("property and event append support bijective pointer-table layouts", () => {
  const withPointerTable = (pointerTableId, targetTableId, targetName) => {
    const assembly = parseAssembly(withoutDebugDirectory());
    const tablesStream = assembly.metadataRoot.streams.get("#~");
    assert.ok(tablesStream);
    assembly.metadataRoot.streams.delete("#~");
    assembly.metadataRoot.streams.set("#-", tablesStream);
    const targets = assembly.tables.get(targetTableId);
    const pointers = targets.map((target, index) => ({
      table: pointerTableId,
      tableName: targetName,
      rid: index + 1,
      [targetName.slice(0, -3)]: {
        raw: target.rid,
        table: targetTableId,
        tableName: target.tableName,
        rid: target.rid
      }
    }));
    assembly.tables.rows.set(pointerTableId, pointers);
    assembly.tables.counts[pointerTableId] = pointers.length;
    assembly.tables.valid |= 1n << BigInt(pointerTableId);
    return assembly;
  };
  const propertyAssembly = withPointerTable(22, 23, "PropertyPtr");
  const propertyOwner = propertyAssembly.types.at(-1);
  const propertyBeforeA = propertyAssembly.addProperty({
    owner: { table: "TypeDef", rid: propertyOwner.rid },
    name: "PointerOrderA",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const propertyBeforeB = propertyAssembly.addProperty({
    owner: { table: "TypeDef", rid: propertyOwner.rid },
    name: "PointerOrderB",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const initialPropertyPointerRows = propertyAssembly.tables.get(22);
  const propertyOrder = initialPropertyPointerRows.map((row) => row.Property.rid);
  const propertyIndexA = propertyOrder.indexOf(propertyBeforeA);
  const propertyIndexB = propertyOrder.indexOf(propertyBeforeB);
  const duplicatePropertyOrder = [...propertyOrder];
  duplicatePropertyOrder[0] = duplicatePropertyOrder[1];
  assert.throws(
    () => propertyAssembly.reorderPointerTable("PropertyPtr", duplicatePropertyOrder),
    /every target row exactly once/
  );
  const otherPropertyOwner = propertyAssembly.types.find((type) =>
    type.rid !== propertyOwner.rid && type.propertyRids.length > 0
  );
  assert.ok(otherPropertyOwner);
  const crossOwnerPropertyOrder = [...propertyOrder];
  const firstOwnedProperty = propertyOwner.propertyRids[0];
  const otherOwnedProperty = otherPropertyOwner.propertyRids[0];
  const firstOwnedIndex = crossOwnerPropertyOrder.indexOf(firstOwnedProperty);
  const otherOwnedIndex = crossOwnerPropertyOrder.indexOf(otherOwnedProperty);
  [crossOwnerPropertyOrder[firstOwnedIndex], crossOwnerPropertyOrder[otherOwnedIndex]] =
    [crossOwnerPropertyOrder[otherOwnedIndex], crossOwnerPropertyOrder[firstOwnedIndex]];
  assert.throws(
    () => propertyAssembly.reorderPointerTable("PropertyPtr", crossOwnerPropertyOrder),
    /cannot change row ownership/
  );
  [propertyOrder[propertyIndexA], propertyOrder[propertyIndexB]] =
    [propertyOrder[propertyIndexB], propertyOrder[propertyIndexA]];
  propertyAssembly.reorderPointerTable("PropertyPtr", propertyOrder);
  const propertyCount = propertyAssembly.tables.counts[23];
  const propertyRid = propertyAssembly.addProperty({
    owner: { table: "TypeDef", rid: propertyAssembly.types.at(-1).rid },
    name: "PointerProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  assert.equal(propertyAssembly.tables.counts[23], propertyCount + 1);
  assert.equal(propertyAssembly.tables.counts[22], propertyCount + 1);
  assert.equal(propertyAssembly.tables.row(22, propertyCount + 1).Property.rid, propertyRid);
  const survivingPropertyRid = propertyAssembly.addProperty({
    owner: { table: "TypeDef", rid: propertyAssembly.types.at(-1).rid },
    name: "SurvivingPointerProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const propertyTokenMap = propertyAssembly.removeProperty(propertyRid);
  assert.equal(propertyTokenMap.get(0x17000000 + survivingPropertyRid), 0x17000000 + propertyRid);
  assert.equal(propertyAssembly.tables.counts[22], propertyCount + 1);
  const reparsedPropertyAssembly = parseAssembly(propertyAssembly.serialize());
  assert.equal(reparsedPropertyAssembly.types.at(-1).properties.at(-1).name, "SurvivingPointerProperty");

  const eventAssembly = withPointerTable(19, 20, "EventPtr");
  const eventOwner = eventAssembly.types.at(-1);
  const eventType = eventAssembly.typeRefs.find((type) => type.name === "IDisposable");
  const eventBeforeA = eventAssembly.addEvent({
    owner: { table: "TypeDef", rid: eventOwner.rid },
    name: "PointerOrderA",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  const eventBeforeB = eventAssembly.addEvent({
    owner: { table: "TypeDef", rid: eventOwner.rid },
    name: "PointerOrderB",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  const eventPointers = eventAssembly.tables.get(19);
  const eventOrder = eventPointers.map((row) => row.Event.rid);
  const eventIndexA = eventOrder.indexOf(eventBeforeA);
  const eventIndexB = eventOrder.indexOf(eventBeforeB);
  [eventOrder[eventIndexA], eventOrder[eventIndexB]] =
    [eventOrder[eventIndexB], eventOrder[eventIndexA]];
  eventAssembly.reorderPointerTable("EventPtr", eventOrder);
  const eventCount = eventAssembly.tables.counts[20];
  const eventRid = eventAssembly.addEvent({
    owner: { table: "TypeDef", rid: eventAssembly.types.at(-1).rid },
    name: "PointerEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  assert.equal(eventAssembly.tables.counts[20], eventCount + 1);
  assert.equal(eventAssembly.tables.counts[19], eventCount + 1);
  assert.equal(eventAssembly.tables.row(19, eventCount + 1).Event.rid, eventRid);
  const survivingEventRid = eventAssembly.addEvent({
    owner: { table: "TypeDef", rid: eventAssembly.types.at(-1).rid },
    name: "SurvivingPointerEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  const eventTokenMap = eventAssembly.removeEvent(eventRid);
  assert.equal(eventTokenMap.get(0x14000000 + survivingEventRid), 0x14000000 + eventRid);
  assert.equal(eventAssembly.tables.counts[19], eventCount + 1);
  const reparsedEventAssembly = parseAssembly(eventAssembly.serialize());
  assert.equal(reparsedEventAssembly.types.at(-1).events.at(-1).name, "SurvivingPointerEvent");

  const invalidAssembly = withPointerTable(22, 23, "PropertyPtr");
  const invalidPropertyCount = invalidAssembly.tables.counts[23];
  const propertyPointers = invalidAssembly.tables.get(22);
  propertyPointers.at(-1).Property.rid = propertyPointers[0].Property.rid;
  assert.throws(() => invalidAssembly.addProperty({
    owner: { table: "TypeDef", rid: invalidAssembly.types.at(-1).rid },
    name: "InvalidPointerProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  }), /one-to-one mapping/);
  assert.equal(invalidAssembly.tables.counts[23], invalidPropertyCount);
});

test("reorderPointerTable supports FieldPtr, MethodPtr, and ParamPtr", () => {
  for (const definition of [
    {
      pointerId: 3,
      targetId: 4,
      column: "Field",
      listTableId: 2,
      listColumn: "FieldList",
      pointerName: "FieldPtr",
      targetName: "Field",
      ownerList: "fieldRids",
      records: "fields"
    },
    {
      pointerId: 5,
      targetId: 6,
      column: "Method",
      listTableId: 2,
      listColumn: "MethodList",
      pointerName: "MethodPtr",
      targetName: "MethodDef",
      ownerList: "methodRids",
      records: "methods"
    },
    {
      pointerId: 7,
      targetId: 8,
      column: "Param",
      listTableId: 6,
      listColumn: "ParamList",
      pointerName: "ParamPtr",
      targetName: "Param",
      ownerList: "parameterRids",
      records: "parameters"
    }
  ]) {
    const assembly = parseAssembly(withoutDebugDirectory());
    usePointerTable(assembly, definition);
    if (definition.pointerId === 7) {
      const methodToken = assembly.addMethod({
        owner: { table: "TypeDef", rid: assembly.types.at(-1).rid },
        name: "TwoParameters",
        flags: 0x0096,
        signature: Uint8Array.of(0x00, 0x02, 0x01, 0x08, 0x08),
        body: Uint8Array.of(0x06, 0x2a)
      });
      assembly.addParam({ owner: { table: "MethodDef", rid: methodToken & 0x00ffffff }, sequence: 1 });
      assembly.addParam({ owner: { table: "MethodDef", rid: methodToken & 0x00ffffff }, sequence: 2 });
    }
    const owners = definition.pointerId === 7 ? assembly.methods : assembly.types;
    const owner = owners.find((candidate) => candidate[definition.ownerList].length > 1);
    assert.ok(owner);
    const ownerIndex = owners.indexOf(owner);
    const offset = owners.slice(0, ownerIndex).reduce(
      (total, candidate) => total + candidate[definition.ownerList].length,
      0
    );
    const order = assembly.tables.get(definition.pointerId).map((row) =>
      row[definition.column].rid
    );
    const nextGroup = order.slice(offset, offset + owner[definition.ownerList].length).reverse();
    order.splice(offset, nextGroup.length, ...nextGroup);

    assert.equal(assembly.reorderPointerTable(definition.pointerName, order), assembly);
    assert.deepEqual(owner[definition.ownerList], nextGroup);
    assert.deepEqual(owner[definition.records].map((record) => record.rid), nextGroup);
    const reparsed = parseAssembly(assembly.serialize());
    const reparsedOwner = (definition.pointerId === 7 ? reparsed.methods : reparsed.types)[ownerIndex];
    assert.deepEqual(reparsedOwner[definition.ownerList], nextGroup);
  }
});

test("Property and Event removal rejects live references and remaps surviving rows", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  const eventType = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const propertyToRemove = assembly.addProperty({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "RemovedProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const propertyToKeep = assembly.addProperty({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "KeptProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const eventToRemove = assembly.addEvent({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "RemovedEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  const eventToKeep = assembly.addEvent({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "KeptEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  const customAttributeRow = (tableId, rowRid) => ({
    table: 12,
    tableName: "CustomAttribute",
    rid: 1,
    Parent: {
      raw: encodeCodedIndex(tableId, rowRid, "HasCustomAttribute"),
      target: { table: tableId, tableName: tableId === 23 ? "Property" : "Event", rid: rowRid }
    },
    Type: { raw: 0, target: null },
    Value: 0
  });
  assembly.tables.rows.set(12, [customAttributeRow(23, propertyToRemove)]);
  assembly.tables.counts[12] = 1;
  assembly.tables.valid |= 1n << 12n;
  assert.throws(() => assembly.removeProperty(propertyToRemove),
    /Property row .*referenced by CustomAttribute\.Parent/);
  assert.equal(assembly.tables.row(23, propertyToRemove).rid, propertyToRemove);
  assembly.tables.rows.set(12, [customAttributeRow(20, eventToRemove)]);
  assert.throws(() => assembly.removeEvent(eventToRemove),
    /Event row .*referenced by CustomAttribute\.Parent/);
  assert.equal(assembly.tables.row(20, eventToRemove).rid, eventToRemove);
  assembly.tables.rows.delete(12);
  assembly.tables.counts[12] = 0;
  assembly.tables.valid &= ~(1n << 12n);

  const propertyMap = assembly.removeProperty(propertyToRemove);
  const eventMap = assembly.removeEvent(eventToRemove);
  assert.equal(propertyMap.get(0x17000000 + propertyToKeep), 0x17000000 + propertyToKeep - 1);
  assert.equal(eventMap.get(0x14000000 + eventToKeep), 0x14000000 + eventToKeep - 1);
  const reparsed = parseAssembly(assembly.serialize());
  const reparsedOwner = reparsed.types[owner.rid - 1];
  assert.equal(reparsedOwner.properties.at(-1).name, "KeptProperty");
  assert.equal(reparsedOwner.properties.at(-1).rid, propertyToKeep - 1);
  assert.equal(reparsedOwner.events.at(-1).name, "KeptEvent");
  assert.equal(reparsedOwner.events.at(-1).rid, eventToKeep - 1);
});

test("Property and Event RID removal refuses debug data that may reference tokens", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.at(-1);
  const eventType = assembly.typeRefs.find((type) => type.name === "IDisposable");
  const propertyRid = assembly.addProperty({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "DebugSensitiveProperty",
    signature: Uint8Array.from([0x08, 0x00, 0x08])
  });
  const eventRid = assembly.addEvent({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "DebugSensitiveEvent",
    eventType: { table: "TypeRef", rid: eventType.rid }
  });
  assert.throws(() => assembly.removeProperty(propertyRid), /PE debug directory is present/);
  assert.throws(() => assembly.removeEvent(eventRid), /PE debug directory is present/);
  assert.equal(assembly.tables.row(23, propertyRid).rid, propertyRid);
  assert.equal(assembly.tables.row(20, eventRid).rid, eventRid);
});

test("MemberRef signatures validate generic variables for direct TypeDef parents", () => {
  const assembly = parseAssembly(fixture);
  const owner = assembly.types.find((type) => type.genericParams.length === 0);
  const memberRef = assembly.tables.row(10, 1);
  const parent = { table: 2, tableName: "TypeDef", rid: owner.rid };
  memberRef.Class = {
    raw: encodeCodedIndex(parent.table, parent.rid, "MemberRefParent"),
    target: parent
  };
  assembly.tables.sorted &= ~(1n << 10n);

  const streams = new Map([...assembly.metadataRoot.streams].map(([name, stream]) =>
    [name, stream.bytes.slice()]
  ));
  const appended = appendBlobHeap(streams.get("#Blob"), Uint8Array.from([0x06, 0x13, 0x00]));
  streams.set("#Blob", appended.heap);
  assembly._heapStreams = streams;
  memberRef.Signature = appended.index;
  assembly._metadataDirty = true;
  assert.throws(() => assembly.serialize(), /Type generic variable !0/);
});

test("MemberRef signatures validate generic variables for external generic TypeRefs", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const typeRef = assembly.insertTypeRefSorted({
    scope: { table: "Module", rid: 1 },
    name: "External`1",
    namespace: "Tests"
  });
  const memberRef = assembly.insertMemberRefSorted({
    parent: { table: "TypeRef", rid: typeRef.token & 0x00ffffff },
    name: "GetValue",
    signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x13, 0x00])
  });
  const original = assembly.serialize();

  assert.throws(() => assembly.replaceMemberRef(
    memberRef.token & 0x00ffffff,
    { signature: Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x13, 0x01]) }
  ), /Type generic variable !1 exceeds its declaring type's arity/);
  assert.throws(() => assembly.replaceTypeRef(
    typeRef.token & 0x00ffffff,
    { name: "External" }
  ), /Type generic variable !0 exceeds its declaring type's arity/);
  assert.equal(assembly.typeRefs[(typeRef.token & 0x00ffffff) - 1].name, "External`1");
  assert.deepEqual(assembly.serialize(), original);
});

test("MemberRef append rejects sorted-table order changes before mutating state", () => {
  const assembly = parseAssembly(fixture);
  const memberRows = assembly.tables.get("MemberRef");
  const originalCount = memberRows.length;
  const originalLast = memberRows.at(-1).Class.raw;
  assembly.tables.sorted |= 1n << 10n;
  const earlierParent = memberRows[0].Class.target;
  assert.throws(() => assembly.addMemberRef({
    parent: { table: earlierParent.tableName, rid: earlierParent.rid },
    name: "OutOfOrderMember",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  }), /sorted Class order/);
  assert.equal(assembly.modified, false);
  assert.equal(memberRows.length, originalCount);
  assert.equal(memberRows.at(-1).Class.raw, originalLast);
});

test("sorted MemberRef insertion remaps table, IL, and returned tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const memberRows = assembly.tables.get("MemberRef");
  assert.ok(memberRows.length > 1);
  assembly.tables.sorted |= 1n << 10n;
  const firstParent = memberRows.reduce((left, right) =>
    left.Class.raw <= right.Class.raw ? left : right
  ).Class.target;
  const lastParent = memberRows.reduce((left, right) =>
    left.Class.raw >= right.Class.raw ? left : right
  ).Class.target;
  const attributeConstructorToken = 0x0a000000 + assembly.customAttributes[0].constructor.rid;
  const customAttributeTargetRid = memberRows.length;
  const customAttributeRid = assembly.customAttributes.at(-1).rid;
  const customAttributeRow = assembly.tables.row(12, customAttributeRid);
  customAttributeRow.Parent.raw = encodeCodedIndex(10, customAttributeTargetRid, "HasCustomAttribute");
  customAttributeRow.Parent.target = {
    table: 10,
    tableName: "MemberRef",
    rid: customAttributeTargetRid
  };
  assembly.customAttributes.at(-1).parent = customAttributeRow.Parent.target;
  assert.ok(encodeCodedIndex(firstParent.table, firstParent.rid, "MemberRefParent") <
    encodeCodedIndex(lastParent.table, lastParent.rid, "MemberRefParent"));
  const genericSignature = Uint8Array.from([0x10, 0x01, 0x01, 0x01, 0x1e, 0x00]);
  const originalToken = assembly.addMemberRef({
    parent: { table: lastParent.tableName, rid: lastParent.rid },
    name: "GenericSorted",
    signature: genericSignature
  });
  const methodSpecToken = assembly.addMethodSpec({
    method: { table: "MemberRef", rid: originalToken & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x08])
  });
  addEncToken(assembly, 30, originalToken);
  addEncToken(assembly, 31, originalToken);
  const callSite = assembly.methods.map((method) => ({
    method,
    instruction: assembly.getInstructions(method.rid).find((item) => item.opcode.name === "call")
  })).find((entry) => entry.instruction);
  assembly.setInstructionOperand(callSite.method.rid, callSite.instruction.offset, originalToken);

  const insertion = assembly.insertMemberRefSorted({
    parent: { table: firstParent.tableName, rid: firstParent.rid },
    name: "EarlierSorted",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  assert.equal(insertion.tokenMap.get(originalToken), originalToken + 1);
  assert.equal(assembly.tables.get(30)[0].Token, insertion.tokenMap.get(originalToken));
  assert.equal(assembly.tables.get(31)[0].Token, insertion.tokenMap.get(originalToken));
  const expectedConstructorToken = insertion.tokenMap.get(attributeConstructorToken) ?? attributeConstructorToken;
  assert.equal(assembly.customAttributes[0].constructor.rid, expectedConstructorToken & 0x00ffffff);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.get(30)[0].Token, insertion.tokenMap.get(originalToken));
  assert.equal(reparsed.tables.get(31)[0].Token, insertion.tokenMap.get(originalToken));
  assert.equal(reparsed.customAttributes[0].constructor.rid, expectedConstructorToken & 0x00ffffff);
  const rewrittenRows = reparsed.tables.get("MemberRef");
  for (let index = 1; index < rewrittenRows.length; index++) {
    assert.ok(rewrittenRows[index - 1].Class.raw <= rewrittenRows[index].Class.raw);
  }
  const shiftedMember = reparsed.memberRefs.find((reference) => reference.name === "GenericSorted");
  assert.equal(shiftedMember.rid, (originalToken & 0x00ffffff) + 1);
  assert.equal(
    reparsed.customAttributes.at(-1).parent.rid,
    insertion.tokenMap.get(0x0a000000 + customAttributeTargetRid) & 0x00ffffff
  );
  assert.equal(reparsed.methodSpecs.at(-1).method.rid, shiftedMember.rid);
  const rewrittenCall = reparsed.getInstructions(callSite.method.rid)
    .find((instruction) => instruction.offset === callSite.instruction.offset);
  assert.equal(rewrittenCall.operand.value, originalToken + 1);
  assert.equal(reparsed.memberRefs.find((reference) => reference.rid === (insertion.token & 0x00ffffff)).name, "EarlierSorted");
});

test("sorted TypeRef insertion remaps metadata references and signature blobs", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const originalNames = new Map(assembly.typeRefs.map((type) => [type.rid, type.name]));
  const fieldRow = assembly.tables.row(4, 2);
  const originalFieldSignature = parseSignature(assembly.heaps.getBlob(fieldRow.Signature));
  assembly.addTypeSpec({ signature: Uint8Array.from([0x12, 0x05]) });
  const originalTypeOperands = [];
  for (const method of assembly.methods) {
    for (const instruction of assembly.getInstructions(method.rid)) {
      if (instruction.operand?.kind === "token" && (instruction.operand.value >>> 24) === 1) {
        originalTypeOperands.push([method.rid, instruction.offset, instruction.operand.value]);
      }
    }
  }
  const customAttributeRow = assembly.tables.row(12, 1);
  setCatchClauseToken(assembly, 0x01000005);
  addEncToken(assembly, 30, 0x01000005);
  addEncToken(assembly, 31, 0x01000005);
  customAttributeRow.Parent.raw = encodeCodedIndex(1, 5, "HasCustomAttribute");
  customAttributeRow.Parent.target = { table: 1, tableName: "TypeRef", rid: 5 };
  assembly.customAttributes[0].parent = customAttributeRow.Parent.target;
  assembly.tables.sorted &= ~(1n << 12n);
  const result = assembly.insertTypeRefSorted({
    scope: { table: "TypeRef", rid: 3 },
    name: "InsertedTypeRef",
    namespace: "Example"
  });
  assert.ok(result.tokenMap.size > 0);
  assert.equal(
    assembly.customAttributes[0].parent.rid,
    result.tokenMap.get(0x01000005) & 0x00ffffff
  );

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(
    reparsed.customAttributes[0].parent.rid,
    result.tokenMap.get(0x01000005) & 0x00ffffff
  );
  const finallyMethod = reparsed.methods.find((method) => method.name === "Finally");
  assert.equal(
    reparsed.getMethodBody(finallyMethod.rid).sections[0].clauses[0].classTokenOrFilterOffset,
    result.tokenMap.get(0x01000005)
  );
  assert.equal(reparsed.tables.get(30)[0].Token, result.tokenMap.get(0x01000005));
  assert.equal(reparsed.tables.get(31)[0].Token, result.tokenMap.get(0x01000005));
  assert.equal(reparsed.typeRefs[(result.token & 0x00ffffff) - 1].name, "InsertedTypeRef");
  assert.equal(
    reparsed.typeRefs[(result.token & 0x00ffffff) - 1].resolutionScope.rid,
    (result.tokenMap.get(0x01000003) ?? 0x01000003) & 0x00ffffff
  );
  for (const [oldToken, newToken] of result.tokenMap) {
    const oldRid = oldToken & 0x00ffffff;
    const newRid = newToken & 0x00ffffff;
    assert.equal(reparsed.typeRefs[newRid - 1].name, originalNames.get(oldRid));
  }
  const typeRefRows = reparsed.tables.get("TypeRef");
  for (let index = 1; index < typeRefRows.length; index++) {
    assert.ok(typeRefRows[index - 1].ResolutionScope.raw <= typeRefRows[index].ResolutionScope.raw);
  }
  for (const row of typeRefRows) {
    if (row.ResolutionScope.target?.table === 1) {
      assert.ok(reparsed.typeRefs[row.ResolutionScope.target.rid - 1]);
    }
  }
  for (const [methodRid, offset, oldToken] of originalTypeOperands) {
    const newToken = result.tokenMap.get(oldToken) ?? oldToken;
    const instruction = reparsed.getInstructions(methodRid).find((item) => item.offset === offset);
    assert.equal(instruction.operand.value, newToken);
  }
  const expectedFieldSignature = remapTypeReferences(originalFieldSignature, (rid) => {
    const newToken = result.tokenMap.get(0x01000000 + rid);
    return newToken ? newToken & 0x00ffffff : rid;
  });
  assert.deepEqual(
    parseSignature(reparsed.heaps.getBlob(reparsed.tables.row(4, 2).Signature)),
    expectedFieldSignature
  );
  const expectedTypeSpecRid = result.tokenMap.get(0x01000001)
    ? result.tokenMap.get(0x01000001) & 0x00ffffff
    : 1;
  assert.equal(reparsed.typeSpecs.at(-1).parsedSignature.type.rid, expectedTypeSpecRid);
});

test("metadata token remapping refuses added method bodies", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const owner = assembly.types.at(-1);
  assembly.addMethod({
    owner: { table: "TypeDef", rid: owner.rid },
    name: "AddedBody",
    flags: 0x0096,
    signature: Uint8Array.of(0x00, 0x00, 0x01),
    body: Uint8Array.of(0x06, 0x2a)
  });
  const typeSpecCount = assembly.typeSpecs.length;
  const typeSpec = assembly.addTypeSpec({ signature: Uint8Array.of(0x08) });
  const typeRef = assembly.addTypeRef({
    scope: assembly.typeRefs.at(-1).resolutionScope,
    name: "AddedBodyReference",
    namespace: "Example"
  });
  const typeRefCount = assembly.typeRefs.length;
  assert.throws(() => assembly.insertTypeRefSorted({
    scope: { table: "TypeRef", rid: 3 },
    name: "InsertedTypeRef",
    namespace: "Example"
  }), /added method bodies/);
  assert.equal(assembly.typeRefs.length, typeRefCount);
  assert.throws(
    () => assembly.removeTypeRef(typeRef & 0x00ffffff),
    /added method bodies/
  );
  assert.throws(
    () => assembly.removeTypeSpec(typeSpec & 0x00ffffff),
    /added method bodies/
  );
  assert.equal(assembly.typeSpecs.length, typeSpecCount + 1);
  assert.throws(() => assembly.removeField(1), /added method bodies/);
  assert.throws(() => assembly.removeMemberRef(1), /added method bodies/);
  assert.throws(() => assembly.removeStandAloneSig(1), /added method bodies/);
  assert.throws(() => assembly.removeMethodSpec(1), /added method bodies/);
});

test("TypeRef removal rejects live references and remaps surviving tokens", () => {
  const referencedAssembly = parseAssembly(withoutDebugDirectory());
  const referenced = referencedAssembly.typeRefs.find((type) => type.name === "IDisposable");
  assert.ok(referenced);
  assert.throws(() => referencedAssembly.removeTypeRef(referenced.rid), /is referenced by/);
  assert.equal(referencedAssembly.modified, false);

  const assembly = parseAssembly(withoutDebugDirectory());
  const scope = assembly.typeRefs.at(-1).resolutionScope;
  const removedToken = assembly.addTypeRef({ scope, name: "RemoveMe", namespace: "JsILNET.Test" });
  const survivingToken = assembly.addTypeRef({ scope, name: "KeepMe", namespace: "JsILNET.Test" });
  const castSite = assembly.methods.flatMap((method) =>
    assembly.getInstructions(method.rid).map((instruction) => ({ method, instruction }))
  ).find(({ instruction }) =>
    instruction.opcode.name === "castclass" &&
    (instruction.operand.value >>> 24) === 0x01
  );
  assert.ok(castSite);
  assembly.setInstructionOperand(castSite.method.rid, castSite.instruction.offset, survivingToken);
  const fieldRow = assembly.tables.row(4, 2);
  const signature = Uint8Array.from([
    0x06,
    0x12,
    ...appendCompressedUInt(encodeCodedIndex(1, survivingToken & 0x00ffffff, "TypeDefOrRef"))
  ]);
  const streams = new Map([...assembly._heapStreams].map(([name, bytes]) => [name, bytes.slice()]));
  const blob = appendBlobHeap(streams.get("#Blob"), signature);
  streams.set("#Blob", blob.heap);
  assembly._heapStreams = streams;
  assembly.heaps = new MetadataHeaps(new Map([...streams].map(([name, bytes]) => [name, { bytes }])));
  fieldRow.Signature = blob.index;
  assembly._metadataDirty = true;
  const tokenMap = assembly.removeTypeRef(removedToken & 0x00ffffff);
  assert.equal(tokenMap.get(survivingToken), removedToken);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.typeRefs.some((type) => type.name === "RemoveMe"), false);
  assert.equal(reparsed.typeRefs.at(-1).name, "KeepMe");
  assert.equal(reparsed.typeRefs.at(-1).rid, tokenMap.get(survivingToken) & 0x00ffffff);
  assert.equal(parseSignature(reparsed.heaps.getBlob(reparsed.tables.row(4, 2).Signature)).type.type.rid,
    tokenMap.get(survivingToken) & 0x00ffffff);
  assert.equal(
    reparsed.getInstructions(castSite.method.rid).find((instruction) =>
      instruction.offset === castSite.instruction.offset
    ).operand.value,
    tokenMap.get(survivingToken)
  );
});

test("TypeRef removal rejects and remaps catch-clause tokens", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const scope = assembly.typeRefs.at(-1).resolutionScope;
  const removedToken = assembly.addTypeRef({ scope, name: "RemoveCatch", namespace: "JsILNET.Test" });
  const survivingToken = assembly.addTypeRef({ scope, name: "KeepCatch", namespace: "JsILNET.Test" });
  setCatchClauseToken(assembly, removedToken);
  assert.throws(
    () => assembly.removeTypeRef(removedToken & 0x00ffffff),
    /referenced by a catch clause/
  );

  setCatchClauseToken(assembly, survivingToken);
  const tokenMap = assembly.removeTypeRef(removedToken & 0x00ffffff);
  const reparsed = parseAssembly(assembly.serialize());
  const method = reparsed.methods.find((candidate) => candidate.name === "Finally");
  assert.equal(
    reparsed.getMethodBody(method.rid).sections[0].clauses[0].classTokenOrFilterOffset,
    tokenMap.get(survivingToken)
  );
});

test("sorted MethodSpec insertion preserves method references and serializes its instantiation", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const existing = assembly.methodSpecs[0];
  const oldMethodSpecRid = existing?.rid;
  const genericMember = assembly.memberRefs.find((reference) => reference.name === "CompareExchange");
  assert.ok(existing && genericMember);
  const callSites = [];
  for (const method of assembly.methods) {
    for (const instruction of assembly.getInstructions(method.rid)) {
      if (instruction.operand?.kind === "token" && instruction.operand.value === 0x2b000000 + existing.rid) {
        callSites.push([method.rid, instruction.offset]);
      }
    }
  }
  const memberInsertion = assembly.insertMemberRefSorted({
    parent: { table: "TypeRef", rid: 1 },
    name: "EarlierGenericMethod",
    signature: genericMember.signature
  });
  addEncToken(assembly, 30, 0x2b000000 + oldMethodSpecRid);
  addEncToken(assembly, 31, 0x2b000000 + oldMethodSpecRid);
  const customAttributeRow = assembly.tables.row(12, 1);
  customAttributeRow.Parent.raw = encodeCodedIndex(43, oldMethodSpecRid, "HasCustomAttribute");
  customAttributeRow.Parent.target = {
    table: 43,
    tableName: "MethodSpec",
    rid: oldMethodSpecRid
  };
  assembly.customAttributes[0].parent = customAttributeRow.Parent.target;
  assembly.tables.sorted &= ~(1n << 12n);
  const result = assembly.insertMethodSpecSorted({
    method: { table: "MemberRef", rid: memberInsertion.token & 0x00ffffff },
    instantiation: Uint8Array.from([0x0a, 0x01, 0x08])
  });
  const replacementInstantiation = Uint8Array.from([0x0a, 0x01, 0x0e]);
  const newMethodSpecRid = result.token & 0x00ffffff;
  assembly.replaceMethodSpecInstantiation(newMethodSpecRid, replacementInstantiation);
  assert.throws(() => assembly.replaceMethodSpecInstantiation(
    newMethodSpecRid,
    Uint8Array.from([0x0a, 0x02, 0x08, 0x08])
  ), /does not match its generic method signature/);
  assert.deepEqual(assembly.methodSpecs[newMethodSpecRid - 1].instantiation, replacementInstantiation);
  assert.equal(
    result.tokenMap.get(0x2b000000 + oldMethodSpecRid),
    0x2b000000 + oldMethodSpecRid + 1
  );
  assert.equal(assembly.tables.get(30)[0].Token, result.tokenMap.get(0x2b000000 + oldMethodSpecRid));
  assert.equal(assembly.tables.get(31)[0].Token, result.tokenMap.get(0x2b000000 + oldMethodSpecRid));
  assert.equal(assembly.customAttributes[0].parent.rid, oldMethodSpecRid + 1);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.get(30)[0].Token, result.tokenMap.get(0x2b000000 + oldMethodSpecRid));
  assert.equal(reparsed.tables.get(31)[0].Token, result.tokenMap.get(0x2b000000 + oldMethodSpecRid));
  assert.equal(reparsed.customAttributes[0].parent.rid, oldMethodSpecRid + 1);
  assert.equal(reparsed.methodSpecs.length, 2);
  assert.equal(reparsed.methodSpecs[1].rid, oldMethodSpecRid + 1);
  assert.deepEqual(reparsed.methodSpecs[0].parsedInstantiation.arguments[0], {
    kind: "primitive",
    elementType: 0x0e
  });
  assert.equal(result.token, 0x2b000000 + reparsed.methodSpecs[0].rid);
  for (const [methodRid, offset] of callSites) {
    const instruction = reparsed.getInstructions(methodRid).find((item) => item.offset === offset);
    assert.equal(instruction.operand.value, 0x2b000000 + oldMethodSpecRid + 1);
  }
});

test("embedded manifest resource replacement relocates data and updates its directory", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.tables.rows.set(40, [1, 2].map((rid) => ({
    table: 40,
    tableName: "ManifestResource",
    rid,
    Offset: 0,
    Flags: 1,
    Name: 0,
    Implementation: { raw: 0, target: null }
  })));
  assembly.tables.valid |= 1n << 40n;
  assembly.tables.counts[40] = 2;
  assembly.resources.push(
    { rid: 1, name: "First", flags: 1, implementation: null, data: Uint8Array.from([1, 2]) },
    { rid: 2, name: "Second", flags: 1, implementation: null, data: Uint8Array.from([3]) }
  );
  assembly.replaceManifestResource(2, Uint8Array.from([9, 8, 7, 6]));
  const method = assembly.methods.find((item) => item.name === "Answer");
  assembly.insertInstruction(method.rid, 0, "nop");

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.cli.resources.size, 16);
  assert.deepEqual(reparsed.resources[0].data, Uint8Array.from([1, 2]));
  assert.deepEqual(reparsed.resources[1].data, Uint8Array.from([9, 8, 7, 6]));
  assert.equal(reparsed.tables.row(40, 1).Offset, 0);
  assert.equal(reparsed.tables.row(40, 2).Offset, 8);
  assert.equal(reparsed.getInstructions(method.rid)[0].opcode.name, "nop");
});

test("manifest resources can append embedded and linked rows", () => {
  const assembly = parseAssembly(fixture);
  const payload = Uint8Array.from([4, 8, 15, 16, 23, 42]);
  const embeddedToken = assembly.addManifestResource({
    name: "AddedPayload",
    flags: 1,
    data: payload
  });
  const linkedToken = assembly.addManifestResource({
    name: "LinkedAssemblyResource",
    flags: 2,
    implementation: { table: "AssemblyRef", rid: 1 }
  });
  assert.equal(embeddedToken, 0x28000001);
  assert.equal(linkedToken, 0x28000002);

  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.resources[0].data, payload);
  assert.equal(reparsed.resources[0].name, "AddedPayload");
  assert.deepEqual(reparsed.resources[1].implementation, {
    table: 35,
    tableName: "AssemblyRef",
    rid: 1
  });
  assert.equal(reparsed.resources[1].data, null);
});

test("File rows can be appended and link manifest resources", () => {
  const assembly = parseAssembly(fixture);
  const hashValue = Uint8Array.from([1, 3, 3, 7]);
  const fileToken = assembly.addFile({
    name: "Library.netmodule",
    flags: 1,
    hashValue
  });
  const resourceToken = assembly.addManifestResource({
    name: "LinkedModuleResource",
    implementation: { table: "File", rid: fileToken & 0x00ffffff }
  });
  assert.equal(fileToken >>> 24, 0x26);
  assert.equal(resourceToken, 0x28000001);
  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.files.at(-1), {
    rid: fileToken & 0x00ffffff,
    flags: 1,
    name: "Library.netmodule",
    hashValue
  });
  assert.deepEqual(reparsed.resources[0].implementation, {
    table: 38,
    tableName: "File",
    rid: fileToken & 0x00ffffff
  });

  const invalidAssembly = parseAssembly(fixture);
  assert.throws(() => invalidAssembly.addFile({ name: "Bad.netmodule", flags: 2 }),
    /only specify ContainsNoMetaData/);
  assert.equal(invalidAssembly.modified, false);
});

test("ManifestResource metadata edits preserve embedded data and update linked targets", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const payload = Uint8Array.of(9, 8, 7);
  const embeddedToken = assembly.addManifestResource({
    name: "OriginalEmbedded",
    flags: 1,
    data: payload
  });
  const fileToken = assembly.addFile({ name: "OriginalLinked.netmodule" });
  const linkedToken = assembly.addManifestResource({
    name: "OriginalLinked",
    implementation: { table: "File", rid: fileToken & 0x00ffffff }
  });
  const linkedRid = linkedToken & 0x00ffffff;
  assert.throws(() => assembly.replaceManifestResourceMetadata(linkedRid, {
    implementation: null
  }), /cannot convert between embedded and linked/);
  assembly.replaceManifestResourceMetadata(embeddedToken & 0x00ffffff, {
    name: "RenamedEmbedded",
    flags: 2
  });
  assembly.replaceManifestResourceMetadata(linkedRid, {
    name: "RenamedLinked",
    flags: 3,
    implementation: { table: "AssemblyRef", rid: assembly.assemblyRefs[0].rid }
  });

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.resources[0].name, "RenamedEmbedded");
  assert.equal(reparsed.resources[0].flags, 2);
  assert.deepEqual(reparsed.resources[0].data, payload);
  assert.equal(reparsed.resources[1].name, "RenamedLinked");
  assert.equal(reparsed.resources[1].flags, 3);
  assert.deepEqual(reparsed.resources[1].implementation, {
    table: 35,
    tableName: "AssemblyRef",
    rid: assembly.assemblyRefs[0].rid
  });
});

test("ExportedType rows can append File or AssemblyRef implementations", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const assemblyRefRid = assembly.assemblyRefs[0].rid;
  const token = assembly.addExportedType({
    name: "ForwardedType",
    namespace: "Example",
    flags: 0,
    implementation: { table: "AssemblyRef", rid: assemblyRefRid }
  });
  assert.equal(token >>> 24, 0x27);
  const rid = token & 0x00ffffff;
  assert.throws(() => assembly.replaceExportedType(rid, {
    implementation: { table: "ExportedType", rid }
  }), /cannot create a cycle/);
  const fileToken = assembly.addFile({ name: "Forwarded.netmodule" });
  assembly.replaceExportedType(rid, {
    name: "RenamedType",
    namespace: "Example.Renamed",
    implementation: { table: "File", rid: fileToken & 0x00ffffff }
  });
  const reparsed = parseAssembly(assembly.serialize());
  const exported = reparsed.exportedTypes[rid - 1];
  assert.equal(exported.name, "RenamedType");
  assert.equal(exported.namespace, "Example.Renamed");
  assert.equal(exported.flags, 0);
  assert.deepEqual(exported.implementation, {
    table: 38,
    tableName: "File",
    rid: fileToken & 0x00ffffff
  });
  reparsed.removeExportedType(rid);
  assert.equal(parseAssembly(reparsed.serialize()).tables.counts[39], 0);

  const referencedAssembly = parseAssembly(withoutDebugDirectory());
  const referencedToken = referencedAssembly.addExportedType({
    name: "ReferencedType",
    implementation: { table: "AssemblyRef", rid: referencedAssembly.assemblyRefs[0].rid }
  });
  referencedAssembly.addManifestResource({
    name: "ForwardedResource",
    implementation: { table: "ExportedType", rid: referencedToken & 0x00ffffff }
  });
  assert.throws(() => referencedAssembly.removeExportedType(referencedToken & 0x00ffffff),
    /referenced by ManifestResource\.Implementation/);
  assert.equal(referencedAssembly.tables.counts[39], 1);
});

test("non-trailing ExportedType removal remaps surviving metadata references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const implementation = { table: "AssemblyRef", rid: assembly.assemblyRefs[0].rid };
  const removedToken = assembly.addExportedType({ name: "RemoveExported", implementation });
  const survivingToken = assembly.addExportedType({ name: "KeepExported", implementation });
  const nestedToken = assembly.addExportedType({
    name: "NestedExported",
    implementation: { table: "ExportedType", rid: survivingToken & 0x00ffffff }
  });
  const attributeParent = assembly.tables.row(12, 1).Parent;
  attributeParent.raw = encodeCodedIndex(
    39,
    nestedToken & 0x00ffffff,
    "HasCustomAttribute"
  );
  attributeParent.target = {
    table: 39,
    tableName: "ExportedType",
    rid: nestedToken & 0x00ffffff
  };
  assembly.customAttributes[0].parent = attributeParent.target;

  assert.throws(
    () => assembly.removeExportedType(removedToken & 0x00ffffff),
    /sorted CustomAttribute order/
  );
  assert.equal(assembly.tables.counts[39], 3);
  assembly.tables.sorted &= ~(1n << 12n);
  const tokenMap = assembly.removeExportedType(removedToken & 0x00ffffff);
  assert.equal(tokenMap.get(survivingToken), removedToken);
  assert.equal(assembly.customAttributes[0].parent.rid, tokenMap.get(nestedToken) & 0x00ffffff);
  assert.equal(
    assembly.exportedTypes.at(-1).implementation.rid,
    tokenMap.get(survivingToken) & 0x00ffffff
  );
  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.exportedTypes.slice(-2).map((type) => type.name), [
    "KeepExported",
    "NestedExported"
  ]);
  assert.equal(
    reparsed.exportedTypes.at(-1).implementation.rid,
    tokenMap.get(survivingToken) & 0x00ffffff
  );
  assert.equal(
    reparsed.customAttributes[0].parent.rid,
    tokenMap.get(nestedToken) & 0x00ffffff
  );
});

test("File replacement updates module identity and hash without changing its token", () => {
  const assembly = parseAssembly(fixture);
  const fileToken = assembly.addFile({ name: "Original.netmodule" });
  const rid = fileToken & 0x00ffffff;
  assembly.addManifestResource({
    name: "LinkedFileResource",
    implementation: { table: "File", rid }
  });
  assembly.replaceFile(rid, {
    name: "Updated.netmodule",
    flags: 1,
    hashValue: Uint8Array.from([9, 8, 7])
  });
  assert.throws(() => assembly.replaceFile(rid, { flags: 2 }),
    /only specify ContainsNoMetaData/);
  assert.equal(assembly.files[rid - 1].name, "Updated.netmodule");
  assert.equal(assembly.files[rid - 1].flags, 1);
  assert.deepEqual([...assembly.files[rid - 1].hashValue], [9, 8, 7]);

  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.files.at(-1), {
    rid,
    flags: 1,
    name: "Updated.netmodule",
    hashValue: Uint8Array.from([9, 8, 7])
  });
  assert.deepEqual(reparsed.resources[0].implementation, { table: 38, tableName: "File", rid });
  assert.equal(fileToken, 0x26000000 + reparsed.files.at(-1).rid);
});

test("File removal rejects live links and remaps surviving resource references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const firstToken = assembly.addFile({ name: "First.netmodule" });
  const secondToken = assembly.addFile({ name: "Second.netmodule" });
  assembly.addManifestResource({
    name: "LinkedPayload",
    implementation: { table: "File", rid: secondToken & 0x00ffffff }
  });
  assert.throws(() => assembly.removeFile(secondToken & 0x00ffffff),
    /referenced by ManifestResource\.Implementation/);
  assert.equal(assembly.files.length, 2);

  const tokenMap = assembly.removeFile(firstToken & 0x00ffffff);
  assert.equal(tokenMap.get(secondToken), secondToken - 1);
  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.files, [{
    rid: 1,
    flags: 0,
    name: "Second.netmodule",
    hashValue: new Uint8Array()
  }]);
  assert.deepEqual(reparsed.resources[0].implementation, {
    table: 38,
    tableName: "File",
    rid: 1
  });
});

test("manifest resource removal remaps references and clears a removed payload directory", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.addManifestResource({
    name: "RemovedPayload",
    data: Uint8Array.from([1, 2, 3])
  });
  assembly.addManifestResource({
    name: "RemainingLinked",
    implementation: { table: "AssemblyRef", rid: 1 }
  });
  const attributeRow = assembly.tables.row(12, 1);
  attributeRow.Parent.raw = encodeCodedIndex(40, 2, "HasCustomAttribute");
  attributeRow.Parent.target = { table: 40, tableName: "ManifestResource", rid: 2 };
  assembly.customAttributes[0].parent = attributeRow.Parent.target;
  assembly.tables.sorted &= ~(1n << 12n);

  const tokenMap = assembly.removeManifestResource(1);
  assert.equal(tokenMap.get(0x28000002), 0x28000001);
  assert.equal(assembly.customAttributes[0].parent.rid, 1);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.resources.length, 1);
  assert.equal(reparsed.resources[0].name, "RemainingLinked");
  assert.equal(reparsed.cli.resources.rva, 0);
  assert.equal(reparsed.cli.resources.size, 0);
  assert.equal(reparsed.customAttributes[0].parent.rid, 1);
});

test("manifest resource removal relocates surviving embedded payloads", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.addManifestResource({
    name: "FirstPayload",
    data: Uint8Array.from([1])
  });
  assembly.addManifestResource({
    name: "SecondPayload",
    data: Uint8Array.from([2, 3, 4])
  });

  assembly.removeManifestResource(1);
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.resources.length, 1);
  assert.equal(reparsed.resources[0].name, "SecondPayload");
  assert.deepEqual(reparsed.resources[0].data, Uint8Array.from([2, 3, 4]));
  assert.equal(reparsed.tables.row(40, 1).Offset, 0);
});

test("manifest resource removal rejects rows with live metadata references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.addManifestResource({
    name: "ReferencedPayload",
    data: Uint8Array.from([1])
  });
  const attributeRow = assembly.tables.row(12, 1);
  attributeRow.Parent.raw = encodeCodedIndex(40, 1, "HasCustomAttribute");
  attributeRow.Parent.target = { table: 40, tableName: "ManifestResource", rid: 1 };
  assembly.tables.sorted &= ~(1n << 12n);

  assert.throws(() => assembly.removeManifestResource(1), /referenced by CustomAttribute\.Parent/);
  assert.equal(assembly.resources.length, 1);
  assert.equal(assembly.tables.counts[40], 1);
});

test("manifest resource removal refuses to mix with structural method edits", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  assembly.addManifestResource({
    name: "Payload",
    data: Uint8Array.from([1])
  });
  const method = assembly.methods.find((item) => item.name === "Answer");
  assembly.insertInstruction(method.rid, 0, "nop");
  assert.throws(() => assembly.removeManifestResource(1), /cannot be combined with structural method edits/);
  assert.equal(assembly.resources.length, 1);
});

test("custom attributes with supported constructor types parse and replace round-trip", () => {
  const assembly = parseAssembly(fixture);
  const original = assembly.parseCustomAttribute(2);
  assert.deepEqual(original, { fixedArguments: [0], namedArguments: [] });
  assert.throws(() => assembly.parseCustomAttribute(7), /enum DebuggingModes is not defined/);
  let externalEnumName;
  const externalEnum = assembly.parseCustomAttribute(7, {
    resolveEnum(name) {
      externalEnumName = name;
      return 0x08;
    }
  });
  assert.match(externalEnumName, /DebuggingModes/);
  assert.throws(() => assembly.parseCustomAttribute(7, { resolveEnum: () => 0x0c }), /underlying type/);
  assembly.replaceCustomAttribute(7, externalEnum, { resolveEnum: () => 0x08 });
  assembly.replaceCustomAttribute(2, { fixedArguments: [9], namedArguments: [] });
  const named = assembly.parseCustomAttribute(8);
  assert.equal(named.namedArguments[0].name, "FrameworkDisplayName");
  named.namedArguments[0].value = "Runtime display";
  assembly.replaceCustomAttribute(8, named);

  const reparsed = parseAssembly(assembly.serialize());
  assert.deepEqual(reparsed.parseCustomAttribute(2), {
    fixedArguments: [9],
    namedArguments: []
  });
  assert.deepEqual(
    reparsed.parseCustomAttribute(7, { resolveEnum: () => 0x08 }),
    externalEnum
  );
  assert.equal(reparsed.parseCustomAttribute(8).namedArguments[0].value, "Runtime display");
});

test("custom attributes can append when their parent preserves table ordering", () => {
  const assembly = parseAssembly(fixture);
  const originalCount = assembly.customAttributes.length;
  const template = assembly.customAttributes[1];
  const value = assembly.parseCustomAttribute(template.rid);
  const token = assembly.addCustomAttribute({
    parent: { table: "MethodDef", rid: 6 },
    constructor: template.constructor,
    value
  });
  assert.equal(token, 0x0c000000 + originalCount + 1);
  const rejected = parseAssembly(fixture);
  const rejectedTemplate = rejected.customAttributes[1];
  const rejectedValue = rejected.parseCustomAttribute(rejectedTemplate.rid);
  assert.throws(() => rejected.addCustomAttribute({
    parent: { table: "Assembly", rid: 1 },
    constructor: rejectedTemplate.constructor,
    value: rejectedValue
  }), /sorted Parent order/);
  assert.equal(rejected.modified, false);
  assert.equal(rejected.customAttributes.length, originalCount);

  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.customAttributes.length, originalCount + 1);
  assert.deepEqual(reparsed.parseCustomAttribute(originalCount + 1), value);
});

test("CustomAttribute removal compacts rows and rejects live CIL references", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const originalCount = assembly.customAttributes.length;
  assert.ok(originalCount > 1);
  const tokenMap = assembly.removeCustomAttribute(1);
  assert.equal(tokenMap.get(0x0c000002), 0x0c000001);
  assert.equal(assembly.customAttributes.length, originalCount - 1);
  assert.ok(assembly.customAttributes.every((attribute, index) => attribute.rid === index + 1));
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.customAttributes.length, originalCount - 1);

  const source = parseAssembly(withoutDebugDirectory());
  const tokenInstruction = source.methods.map((method) => ({
    method,
    instruction: source.getInstructions(method.rid).find((item) =>
      item.operand?.kind === "token" && item.patchOffsets.length === 1
    )
  })).find((entry) => entry.instruction);
  assert.ok(tokenInstruction);
  const referencedBytes = source.bytes;
  new DataView(referencedBytes.buffer).setUint32(
    tokenInstruction.instruction.patchOffsets[0],
    0x0c000001,
    true
  );
  const referencedAssembly = parseAssembly(referencedBytes);
  assert.throws(() => referencedAssembly.removeCustomAttribute(1), /referenced by CIL/);
  assert.equal(referencedAssembly.customAttributes.length, originalCount);
  assert.equal(referencedAssembly.modified, false);
});

test("sorted MemberRef insertion refuses to mix with structural method edits", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const method = assembly.methods.find((item) => item.name === "Answer");
  assembly.insertInstruction(method.rid, 0, "nop");
  const memberCount = assembly.memberRefs.length;
  const parent = assembly.tables.get("MemberRef")[0].Class.target;
  assert.throws(() => assembly.insertMemberRefSorted({
    parent: { table: parent.tableName, rid: parent.rid },
    name: "RejectedSorted",
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  }), /cannot be combined with structural method edits/);
  assert.equal(assembly.memberRefs.length, memberCount);
});

test("metadata rewrite recomputes heap index widths after heap growth", () => {
  const assembly = parseAssembly(fixture);
  const parent = assembly.tables.get("MemberRef").at(-1).Class.target;
  const longName = "x".repeat(0x10000);
  assembly.addMemberRef({
    parent: { table: parent.tableName, rid: parent.rid },
    name: longName,
    signature: Uint8Array.from([0x20, 0x00, 0x0e])
  });
  const reparsed = parseAssembly(assembly.serialize());
  assert.equal(reparsed.tables.heapSizes & 1, 1);
  assert.equal(reparsed.memberRefs.at(-1).name.length, longName.length);
});

test("instruction insertion/removal keeps exception-handler regions synchronized", () => {
  const assembly = parseAssembly(withoutDebugDirectory());
  const method = assembly.methods.find((item) => item.name === "Finally");
  assert.ok(method);
  const body = assembly.getMethodBody(method.rid);
  const clause = body.sections.flatMap((section) => section.clauses)[0];
  assert.ok(clause);
  const insideTry = body.instructions.find((instruction) =>
    instruction.offset > clause.tryOffset &&
    instruction.offset < clause.tryOffset + clause.tryLength
  );
  assert.ok(insideTry);
  const originalCodeSize = body.codeSize;
  const originalHandlerOffset = clause.handlerOffset;

  const inserted = assembly.insertInstruction(method.rid, insideTry.offset, "nop");
  const editedClause = assembly.getMethodBody(method.rid).sections[0].clauses[0];
  assert.equal(editedClause.tryLength, clause.tryLength + 1);
  assert.equal(editedClause.handlerOffset, originalHandlerOffset + 1);
  assembly.removeInstruction(method.rid, inserted.offset);
  const restoredClause = assembly.getMethodBody(method.rid).sections[0].clauses[0];
  assert.equal(assembly.getMethodBody(method.rid).codeSize, originalCodeSize);
  assert.equal(restoredClause.tryLength, clause.tryLength);
  assert.equal(restoredClause.handlerOffset, originalHandlerOffset);

  const reparsed = parseAssembly(assembly.serialize());
  const finalMethod = reparsed.methods.find((item) => item.name === "Finally");
  assert.equal(reparsed.getMethodBody(finalMethod.rid).sections[0].clauses[0].tryLength, clause.tryLength);
});

test("tiny/fat body format switches follow size and maxStack constraints", () => {
  const assembly = parseAssembly(fixture);
  const method = assembly.methods.find((item) => item.name === "Answer");
  assert.equal(assembly.getMethodBody(method.rid).format, "tiny");
  assembly.setMethodMaxStack(method.rid, 9);
  let reparsed = parseAssembly(assembly.serialize());
  let reparsedMethod = reparsed.methods.find((item) => item.name === "Answer");
  assert.equal(reparsed.getMethodBody(reparsedMethod.rid).format, "fat");
  assert.equal(reparsed.getMethodBody(reparsedMethod.rid).maxStack, 9);

  assembly.setMethodMaxStack(method.rid, 8);
  reparsed = parseAssembly(assembly.serialize());
  reparsedMethod = reparsed.methods.find((item) => item.name === "Answer");
  assert.equal(reparsed.getMethodBody(reparsedMethod.rid).format, "tiny");
});

test("failed structural edits do not mark the assembly modified", () => {
  const assembly = parseAssembly(fixture);
  const method = assembly.methods.find((item) => item.name === "Answer");
  assert.throws(() => assembly.insertInstruction(method.rid, 0, "missing.opcode"), /Unknown CIL opcode/);
  assert.throws(() => assembly.removeInstruction(method.rid, 0xffff), /No instruction begins/);
  assert.equal(assembly.modified, false);
  assert.equal(Buffer.compare(assembly.serialize(), fixture), 0);
});
