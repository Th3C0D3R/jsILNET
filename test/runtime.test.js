import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodePortablePdbSequencePoints,
  encodeCodedIndex,
  encodePortablePdbSequencePoints,
  parseAssembly,
  parseClassicPdb,
  parsePE,
  replaceEmbeddedPortablePdbDocumentName,
  insertEmbeddedPortablePdbDocument,
  replaceClassicPdbStringTableName,
  insertClassicPdbFileChecksum,
  removeClassicPdbFileChecksum,
  replaceClassicPdbFileChecksum,
  insertClassicPdbLineBlock,
  removeClassicPdbLineBlock,
  replaceClassicPdbLineBlock,
  replaceClassicPdbLineInfo,
  replaceClassicPdbSymbolName,
  replaceEmbeddedPortablePdbLocalScope,
  replaceEmbeddedPortablePdbLocalVariable,
  replaceEmbeddedPortablePdbLocalConstant,
  replaceEmbeddedPortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbSequencePoints,
  replaceEmbeddedPortablePdbSourceLink,
  addEmbeddedPortablePdbSourceLink,
  removeEmbeddedPortablePdbSourceLink,
  removeEmbeddedPortablePdbSource,
  removeEmbeddedPortablePdbCustomDebugInformation,
  addEmbeddedPortablePdbSource,
  replaceEmbeddedPortablePdbSource,
  serializeEmbeddedPortablePdb
} from "../src/index.js";
import { parseEmbeddedPortablePdbData } from "../src/pe/headers.js";
import {
  decodePortablePdbCustomDebugInformation,
  removeEmbeddedPortablePdbMethod,
  refreshEmbeddedPortablePdbId,
  replaceEmbeddedPortablePdbMethodOffsets
} from "../src/metadata/portable-pdb.js";

const dotnetVersion = spawnSync("dotnet", ["--version"], { encoding: "utf8" });
const dotnetAvailable = dotnetVersion.status === 0;
const targetFramework = dotnetAvailable
  ? `net${dotnetVersion.stdout.trim().split(".")[0]}.0`
  : null;

function stripPortablePdbMethodCustomDebugInformation(pdb) {
  const rows = pdb.tables.rows.get(55) ?? [];
  const remaining = rows
    .filter((row) => row.Parent.target?.table !== 6)
    .map((row, index) => ({ ...row, rid: index + 1 }));
  if (remaining.length > 0) {
    pdb.tables.rows.set(55, remaining);
  } else {
    pdb.tables.rows.delete(55);
    pdb.tables.valid &= ~(1n << 55n);
  }
  pdb.tables.counts[55] = remaining.length;
}

function retainPortablePdbCustomDebugInformation(pdb, predicate) {
  const retained = pdb.customDebugInformation.filter(predicate);
  const retainedRids = new Set(retained.map((record) => record.rid));
  const rows = (pdb.tables.rows.get(55) ?? [])
    .filter((row) => retainedRids.has(row.rid))
    .map((row, index) => ({ ...row, rid: index + 1 }));
  pdb.customDebugInformation = retained.map((record, index) => ({
    ...record,
    rid: index + 1
  }));
  if (rows.length === 0) {
    pdb.tables.rows.delete(55);
    pdb.tables.valid &= ~(1n << 55n);
  } else {
    pdb.tables.rows.set(55, rows);
  }
  pdb.tables.counts[55] = rows.length;
}

test("Portable PDB compilation CDI decoders validate strings and record bounds", () => {
  const optionsGuid = Uint8Array.from([
    0x05, 0xec, 0xfe, 0xb5, 0xd0, 0x8c, 0x83, 0x4a,
    0x96, 0xda, 0x46, 0x62, 0x84, 0xbb, 0x4b, 0xd8
  ]);
  const referencesGuid = Uint8Array.from([
    0x08, 0x47, 0x4d, 0x7e, 0x6e, 0x09, 0x5c, 0x4c,
    0xae, 0xda, 0xcb, 0x10, 0xba, 0x6a, 0x74, 0x0d
  ]);
  const decode = (guid, value, parentTable = 0) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => guid,
        getBlob: () => value
      }
    );
  const optionsValue = new TextEncoder().encode("language\0C#\0optimization\0debug\0");
  assert.deepEqual(decode(optionsGuid, optionsValue).compilationOptions, [
    { name: "language", value: "C#" },
    { name: "optimization", value: "debug" }
  ]);
  assert.throws(
    () => decode(optionsGuid, new TextEncoder().encode("language\0C#\0language\0VB\0")),
    /Duplicate Portable PDB compilation option language/
  );
  assert.throws(
    () => decode(optionsGuid, new TextEncoder().encode("language\0unterminated")),
    /not null-terminated/
  );
  assert.throws(
    () => decode(optionsGuid, new TextEncoder().encode("language\0C#\0"), 48),
    /must belong to the Module/
  );

  const referenceHeader = Uint8Array.of(
    0x03,
    0x78, 0x56, 0x34, 0x12,
    0x21, 0x43, 0x65, 0x87,
    ...Array.from({ length: 16 }, (_, index) => index)
  );
  const referenceValue = Uint8Array.from([
    ...new TextEncoder().encode("reference.dll\0Alias\0"),
    ...referenceHeader
  ]);
  const reference = decode(referencesGuid, referenceValue)
    .compilationMetadataReferences[0];
  assert.deepEqual(reference, {
    fileName: "reference.dll",
    aliases: "Alias",
    flags: 3,
    timeStamp: 0x12345678,
    fileSize: 0x87654321,
    mvid: Uint8Array.from({ length: 16 }, (_, index) => index)
  });
  assert.throws(
    () => decode(referencesGuid, referenceValue.subarray(0, referenceValue.length - 1)),
    /record is truncated/
  );
  assert.throws(
    () => decode(referencesGuid, Uint8Array.from([
      ...new TextEncoder().encode("reference.dll\0\0"),
      0x04, ...referenceHeader.subarray(1)
    ])),
    /reserved bits/
  );

  const typeDefinitionDocumentGuid = Uint8Array.from([
    0xbc, 0x74, 0x2e, 0x93, 0xa9, 0xdb, 0x78, 0x44,
    0x8d, 0x46, 0x0f, 0x32, 0xa7, 0xba, 0xb3, 0xd3
  ]);
  const decodeTypeDefinitionDocuments = (value, documentCount = 2, parentTable = 2) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => typeDefinitionDocumentGuid,
        getBlob: () => value
      },
      documentCount
    );
  assert.deepEqual(
    decodeTypeDefinitionDocuments(Uint8Array.of(1, 2)).typeDefinitionDocuments,
    [1, 2]
  );
  assert.throws(() => decodeTypeDefinitionDocuments(Uint8Array.of(0)), /invalid Document row 0/);
  assert.throws(() => decodeTypeDefinitionDocuments(Uint8Array.of(3)), /invalid Document row 3/);
  assert.throws(
    () => decodeTypeDefinitionDocuments(Uint8Array.of(0x80)),
    /exceeds the available/
  );
  assert.throws(
    () => decodeTypeDefinitionDocuments(Uint8Array.of(1), 2, 0),
    /must belong to a TypeDef/
  );

  const stateMachineScopesGuid = Uint8Array.from([
    0x1e, 0xa6, 0xa9, 0x6d, 0xc7, 0xf8, 0x74, 0x48,
    0xbe, 0x62, 0x68, 0xbc, 0x56, 0x30, 0xdf, 0x71
  ]);
  const decodeStateMachineScopes = (value, parentTable = 6) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => stateMachineScopesGuid,
        getBlob: () => value
      }
    );
  const scopeBytes = new Uint8Array(16);
  const scopeView = new DataView(scopeBytes.buffer);
  scopeView.setUint32(0, 0, true);
  scopeView.setUint32(4, 5, true);
  scopeView.setUint32(8, 42, true);
  scopeView.setUint32(12, 3, true);
  assert.deepEqual(
    decodeStateMachineScopes(scopeBytes).stateMachineHoistedLocalScopes,
    [{ startOffset: 0, length: 5 }, { startOffset: 42, length: 3 }]
  );
  assert.throws(
    () => decodeStateMachineScopes(scopeBytes.subarray(0, 7)),
    /data is truncated/
  );
  const zeroLengthScope = new Uint8Array(8);
  assert.throws(() => decodeStateMachineScopes(zeroLengthScope), /invalid IL scope/);
  const outOfRangeScope = Uint8Array.from(scopeBytes.subarray(0, 8));
  new DataView(outOfRangeScope.buffer).setUint32(0, 0x80000000, true);
  assert.throws(() => decodeStateMachineScopes(outOfRangeScope), /invalid IL scope/);
  assert.throws(
    () => decodeStateMachineScopes(scopeBytes, 50),
    /must belong to a MethodDef/
  );

  const localSlotMapGuid = Uint8Array.from([
    0xa8, 0x52, 0x5f, 0x75, 0xc5, 0x91, 0xbe, 0x45,
    0xb4, 0xb8, 0x20, 0x95, 0x71, 0xe5, 0x52, 0xbd
  ]);
  const decodeLocalSlotMap = (value, parentTable = 6) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => localSlotMapGuid,
        getBlob: () => value
      }
    );
  assert.deepEqual(
    decodeLocalSlotMap(Uint8Array.of(0x81, 1, 1)).editAndContinueLocalSlotMap,
    {
      syntaxOffsetBaseline: -1,
      slots: [{ kind: 0, syntaxOffset: 0, ordinal: 1 }]
    }
  );
  assert.deepEqual(
    decodeLocalSlotMap(Uint8Array.of(0xff, 2, 0x81, 2, 1)).editAndContinueLocalSlotMap,
    {
      syntaxOffsetBaseline: -2,
      slots: [{ kind: 0, syntaxOffset: 0, ordinal: 1 }]
    }
  );
  assert.deepEqual(
    decodeLocalSlotMap(Uint8Array.of(0)).editAndContinueLocalSlotMap.slots,
    [{ kind: null, syntaxOffset: null, ordinal: null }]
  );
  assert.throws(() => decodeLocalSlotMap(Uint8Array.of(0x7f, 0)), /invalid slot kind/);
  assert.throws(() => decodeLocalSlotMap(Uint8Array.of(0x81, 1)), /exceeds the available/);
  assert.throws(() => decodeLocalSlotMap(Uint8Array.of(0), 52), /must belong to a MethodDef/);

  const lambdaMapGuid = Uint8Array.from([
    0x4c, 0x00, 0x43, 0xa6, 0x40, 0x02, 0x6f, 0x49,
    0xa7, 0x83, 0x30, 0xd6, 0x4f, 0x49, 0x79, 0xde
  ]);
  const decodeLambdaMap = (value, parentTable = 6) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => lambdaMapGuid,
        getBlob: () => value
      }
    );
  assert.deepEqual(
    decodeLambdaMap(Uint8Array.of(1, 0, 1, 2, 3, 1))
      .editAndContinueLambdaAndClosureMap,
    {
      methodOrdinal: 1,
      syntaxOffsetBaseline: 0,
      closures: [2],
      lambdas: [{ syntaxOffset: 3, closureOrdinal: 1 }]
    }
  );
  assert.throws(() => decodeLambdaMap(Uint8Array.of(1)), /exceeds the available/);
  assert.throws(
    () => decodeLambdaMap(Uint8Array.of(1, 0, 1)),
    /closure list is truncated/
  );
  assert.throws(
    () => decodeLambdaMap(Uint8Array.of(1, 0, 0, 1, 1)),
    /references a missing closure/
  );
  assert.throws(() => decodeLambdaMap(Uint8Array.of(1, 0, 0), 0), /must belong to a MethodDef/);
});

test("Portable PDB async stepping decoder validates offsets and MethodDef references", () => {
  const asyncSteppingGuid = Uint8Array.from([
    0xc5, 0x2a, 0xfd, 0x54, 0x25, 0xe9, 0x1a, 0x40,
    0x9c, 0x2a, 0xf9, 0x4f, 0x17, 0x10, 0x72, 0xf8
  ]);
  const decode = (value, methodCount = 2, parentTable = 6) =>
    decodePortablePdbCustomDebugInformation(
      { Kind: 1, Value: 1, Parent: { target: { table: parentTable } } },
      {
        getGuid: () => asyncSteppingGuid,
        getBlob: () => value
      },
      0xffffffff,
      methodCount
    );
  const valid = Uint8Array.of(0, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0, 2);
  assert.deepEqual(decode(valid).asyncMethodSteppingInformation, {
    catchHandlerOffset: -1,
    steps: [{ yieldOffset: 4, resumeOffset: 9, methodRid: 2 }]
  });
  assert.throws(() => decode(valid, 2, 0), /must belong to a MethodDef/);
  assert.throws(
    () => decode(Uint8Array.of(1, 0, 0, 0, 4, 0, 0)),
    /step is truncated/
  );
  assert.throws(
    () => decode(Uint8Array.of(1, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0, 3)),
    /invalid offset or MethodDef/
  );
  const invalidCatchOffset = Uint8Array.of(1, 0, 0, 0);
  new DataView(invalidCatchOffset.buffer).setUint32(0, 0x80000001, true);
  assert.throws(() => decode(invalidCatchOffset), /invalid catch offset/);
});

test("MethodDef insertion and removal remap recognized method-scoped CDI", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-method-cdi-"));
  try {
    const project = join(directory, "PdbMethodCdi.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(
      join(directory, "Fixture.cs"),
      "public abstract class PdbInsertedMethodOwner {} " +
      "public class PdbMethodCdiFixture { " +
      "public static int Compute(int argument) { int copy = argument; return copy; } " +
      "public static async System.Threading.Tasks.Task<int> AsyncCompute() { " +
      "await System.Threading.Tasks.Task.Yield(); return 42; } }"
    );
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const original = Uint8Array.from(await readFile(join(output, "PdbMethodCdi.dll")));
    const assembly = parseAssembly(original);
    const method = assembly.methods.find((item) => item.name === "Compute");
    const methodRid = method?.rid;
    const owner = assembly.types.find((type) => type.name === "PdbInsertedMethodOwner");
    const initialPdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const localSlotRecord = initialPdb?.customDebugInformation.find((record) =>
      record.editAndContinueLocalSlotMap && record.Parent.target?.rid === methodRid
    );
    const asyncSteppingRecord = initialPdb?.customDebugInformation.find((record) =>
      record.asyncMethodSteppingInformation
    );
    assert.ok(method);
    assert.ok(owner);
    assert.ok(localSlotRecord);
    assert.ok(asyncSteppingRecord);
    const originalSlotMap = localSlotRecord.editAndContinueLocalSlotMap;
    const originalAsyncStepping = asyncSteppingRecord.asyncMethodSteppingInformation;

    const inserted = assembly.insertMethod({
      owner: { table: "TypeDef", rid: owner.rid },
      name: "Inserted",
      flags: 0x04c6,
      signature: Uint8Array.of(0x20, 0x00, 0x01)
    });
    const insertedAssembly = parseAssembly(assembly.serialize());
    const insertedPdb = insertedAssembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const shiftedSlotRecord = insertedPdb?.customDebugInformation.find((record) =>
      record.editAndContinueLocalSlotMap &&
      record.Parent.target?.rid === methodRid + 1
    );
    assert.ok(shiftedSlotRecord);
    assert.equal(shiftedSlotRecord.Parent.target?.rid, methodRid + 1);
    assert.deepEqual(shiftedSlotRecord?.editAndContinueLocalSlotMap, originalSlotMap);
    const insertedRid = inserted.token & 0x00ffffff;
    const shiftedAsyncRecord = insertedPdb?.customDebugInformation.find((record) =>
      record.kind === asyncSteppingRecord.kind &&
      record.Parent.target?.rid === (
        asyncSteppingRecord.Parent.target.rid >= insertedRid
          ? asyncSteppingRecord.Parent.target.rid + 1
          : asyncSteppingRecord.Parent.target.rid
      )
    );
    assert.deepEqual(
      shiftedAsyncRecord?.asyncMethodSteppingInformation.steps,
      originalAsyncStepping.steps.map((step) => ({
        ...step,
        methodRid: step.methodRid >= insertedRid ? step.methodRid + 1 : step.methodRid
      }))
    );

    const cdiRemovalAssembly = parseAssembly(assembly.serialize());
    const cdiRemovalDebugIndex = cdiRemovalAssembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    const cdiRemovalPdb = cdiRemovalAssembly.pe.debugDirectoryEntries[cdiRemovalDebugIndex]
      .embeddedPortablePdb;
    const methodScopedRecord = cdiRemovalPdb.customDebugInformation.find((record) =>
      record.editAndContinueLocalSlotMap
    );
    const expectedLocalSlotCount = cdiRemovalPdb.customDebugInformation.filter((record) =>
      record.editAndContinueLocalSlotMap
    ).length - 1;
    const insertedParent = {
      raw: encodeCodedIndex(6, insertedRid, "HasCustomDebugInformation"),
      target: { table: 6, tableName: "MethodDef", rid: insertedRid }
    };
    methodScopedRecord.Parent = insertedParent;
    const customDebugRows = cdiRemovalPdb.tables.rows.get(55).map((row) =>
      row.rid === methodScopedRecord.rid ? { ...row, Parent: insertedParent } : row
    ).sort((left, right) =>
      left.Parent.raw - right.Parent.raw || left.rid - right.rid
    ).map((row, index) => ({ ...row, rid: index + 1 }));
    cdiRemovalPdb.customDebugInformation = cdiRemovalPdb.customDebugInformation
      .sort((left, right) =>
        left.Parent.raw - right.Parent.raw || left.rid - right.rid
      )
      .map((record, index) => ({ ...record, rid: index + 1 }));
    cdiRemovalPdb.tables.rows.set(55, customDebugRows);
    cdiRemovalAssembly.replaceEmbeddedPortablePdb(
      cdiRemovalDebugIndex,
      serializeEmbeddedPortablePdb(cdiRemovalPdb)
    );
    cdiRemovalAssembly.removeMethod(insertedRid);
    const cdiRemovedPdb = parseAssembly(cdiRemovalAssembly.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    assert.equal(
      cdiRemovedPdb.customDebugInformation.filter((record) =>
        record.editAndContinueLocalSlotMap
      ).length,
      expectedLocalSlotCount
    );

    assembly.removeMethod(inserted.token & 0x00ffffff);
    const removedAssembly = parseAssembly(assembly.serialize());
    const removedPdb = removedAssembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const restoredSlotRecord = removedPdb?.customDebugInformation.find((record) =>
      record.editAndContinueLocalSlotMap && record.Parent.target?.rid === methodRid
    );
    assert.equal(restoredSlotRecord?.Parent.target?.rid, methodRid);
    assert.deepEqual(restoredSlotRecord?.editAndContinueLocalSlotMap, originalSlotMap);
    const restoredAsyncRecord = removedPdb?.customDebugInformation.find((record) =>
      record.kind === asyncSteppingRecord.kind &&
      record.Parent.target?.rid === asyncSteppingRecord.Parent.target.rid
    );
    assert.deepEqual(
      restoredAsyncRecord?.asyncMethodSteppingInformation,
      originalAsyncStepping
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("external custom-attribute metadata can be resolved for constructors and named members", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-external-attribute-"));
  try {
    const attributeDirectory = join(directory, "ExternalAttributes");
    const consumerDirectory = join(directory, "Consumer");
    await mkdir(attributeDirectory);
    await mkdir(consumerDirectory);
    const attributeProject = join(attributeDirectory, "ExternalAttributes.csproj");
    await writeFile(attributeProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>none</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(attributeDirectory, "ExternalAttributes.cs"), [
      "using System;",
      "namespace ExternalAttributes;",
      "public enum Mode : short { Read = 1, Write = 2 }",
      "[AttributeUsage(AttributeTargets.Class)]",
      "public abstract class BaseAttribute : Attribute",
      "{",
      "    public string Label { get; set; } = \"\";",
      "}",
      "public sealed class DataAttribute : BaseAttribute",
      "{",
      "    public Mode Mode { get; set; }",
      "    public bool Enabled;",
      "    public DataAttribute(int code, Mode mode) { }",
      "}"
    ].join("\n"));
    const consumerProject = join(consumerDirectory, "Consumer.csproj");
    await writeFile(consumerProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>none</DebugType>",
      "  </PropertyGroup>",
      "  <ItemGroup>",
      "    <ProjectReference Include=\"..\\ExternalAttributes\\ExternalAttributes.csproj\" />",
      "  </ItemGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(consumerDirectory, "Consumer.cs"), [
      "[ExternalAttributes.Data(7, ExternalAttributes.Mode.Write, Label = \"resolved\", Mode = ExternalAttributes.Mode.Write, Enabled = true)]",
      "public class Target { }"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", consumerProject, "--configuration", "Release", "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const externalPath = join(
      attributeDirectory,
      "bin",
      "Release",
      targetFramework,
      "ExternalAttributes.dll"
    );
    const consumerPath = join(
      consumerDirectory,
      "bin",
      "Release",
      targetFramework,
      "Consumer.dll"
    );
    const externalAssembly = parseAssembly(Uint8Array.from(await readFile(externalPath)));
    const consumerAssembly = parseAssembly(Uint8Array.from(await readFile(consumerPath)));
    const externalType = (name) => {
      const type = externalAssembly.types.find((candidate) =>
        `${candidate.namespace ? `${candidate.namespace}.` : ""}${candidate.name}` === name
      );
      return type ? { assembly: externalAssembly, rid: type.rid } : undefined;
    };
    const resolveType = (name) => externalType(name.split(",", 1)[0].trim());
    const target = consumerAssembly.types.find((type) => type.name === "Target");
    const attribute = consumerAssembly.customAttributes.find((record) =>
      record.parent?.table === 2 && record.parent.rid === target?.rid
    );
    assert.ok(target);
    assert.ok(attribute);
    assert.throws(
      () => consumerAssembly.parseCustomAttribute(attribute.rid),
      /enum Mode is not defined/
    );
    const parsed = consumerAssembly.parseCustomAttribute(attribute.rid, { resolveType });
    assert.deepEqual(parsed.fixedArguments, [7, 2]);
    assert.deepEqual(parsed.namedArguments.map(({ name, value }) => [name, value]), [
      ["Label", "resolved"],
      ["Mode", 2],
      ["Enabled", true]
    ]);
    assert.throws(
      () => consumerAssembly.parseCustomAttribute(attribute.rid, {
        resolveType: () => ({})
      }),
      /resolver must return \{ assembly, rid \}/
    );
    const inserted = consumerAssembly.insertCustomAttribute({
      parent: { table: "TypeDef", rid: target.rid },
      constructor: attribute.constructor,
      value: parsed,
      resolveType
    });
    assert.deepEqual(
      consumerAssembly.parseCustomAttribute(inserted.rid, { resolveType }),
      parsed
    );

    const invalidNamedValue = {
      ...parsed,
      namedArguments: parsed.namedArguments.map((argument) => ({ ...argument }))
    };
    invalidNamedValue.namedArguments[0].name = "Missing";
    const beforeInvalidEdit = consumerAssembly.serialize();
    assert.throws(
      () => consumerAssembly.replaceCustomAttribute(
        attribute.rid,
        invalidNamedValue,
        { resolveType }
      ),
      /named property Missing does not exist/
    );
    assert.deepEqual(consumerAssembly.serialize(), beforeInvalidEdit);

    const invalidConstructorAssembly = parseAssembly(
      Uint8Array.from(await readFile(consumerPath))
    );
    const invalidConstructor = invalidConstructorAssembly.memberRefs.find((reference) =>
      reference.rid === attribute.constructor.rid
    );
    assert.ok(invalidConstructor);
    invalidConstructor.signature = Uint8Array.of(0x20, 0x01, 0x01, 0x0e);
    assert.throws(
      () => invalidConstructorAssembly.parseCustomAttribute(attribute.rid, { resolveType }),
      /does not match a declared constructor/
    );

    const permissionSet = {
      format: "binary",
      attributes: [{
        typeName: "ExternalAttributes.DataAttribute, ExternalAttributes",
        namedArguments: [{
          kind: "property",
          type: { kind: "enum", name: "ExternalAttributes.Mode", elementType: 0x06 },
          name: "Mode",
          value: 1
        }, {
          kind: "field",
          type: { kind: "primitive", elementType: 0x02 },
          name: "Enabled",
          value: true
        }]
      }]
    };
    const securityRid = consumerAssembly.addDeclSecurity({
      parent: { table: "Assembly", rid: 1 },
      action: 2,
      permissionSet,
      resolveType
    });
    assert.deepEqual(
      consumerAssembly.parseDeclSecurity(securityRid, { resolveType }).permissionSet,
      permissionSet
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("TypeDefinitionDocument CDI follows TypeDef insertion and removal", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-typedef-cdi-"));
  try {
    const project = join(directory, "PdbTypeDefCdi.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.cs"), [
      "public class BeforeType {}",
      "public interface EmptyType {}",
      "public class AfterType {}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assembly = parseAssembly(
      Uint8Array.from(await readFile(join(output, "PdbTypeDefCdi.dll")))
    );
    const embeddedPdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const debugEntryIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    const emptyType = assembly.types.find((type) => type.name === "EmptyType");
    assert.ok(embeddedPdb);
    assert.ok(debugEntryIndex >= 0);
    assert.ok(emptyType);
    const emptyTypeRid = emptyType.rid;
    const typeDocumentRecord = embeddedPdb.customDebugInformation.find((record) =>
      Array.isArray(record.typeDefinitionDocuments) &&
      record.Parent.target?.table === 2 &&
      record.Parent.target.rid === emptyType.rid
    );
    assert.ok(typeDocumentRecord);
    const originalDocumentRids = typeDocumentRecord.typeDefinitionDocuments;
    const originalTypeDocumentCount = embeddedPdb.customDebugInformation.filter((record) =>
      Array.isArray(record.typeDefinitionDocuments)
    ).length;

    assembly.addEmbeddedPortablePdbDocument(debugEntryIndex, "generated/type-doc.cs");
    const addedDocumentPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    const addedDocumentRid = addedDocumentPdb.documents.length;
    assert.ok(addedDocumentRid > 0);
    const beforeInvalidDocumentReference = assembly.serialize();
    assert.throws(() => assembly.replaceEmbeddedPortablePdbTypeDefinitionDocuments(
      debugEntryIndex,
      emptyTypeRid,
      [addedDocumentRid + 1]
    ), RangeError);
    assert.deepEqual(assembly.serialize(), beforeInvalidDocumentReference);
    assembly.replaceEmbeddedPortablePdbTypeDefinitionDocuments(
      debugEntryIndex,
      emptyTypeRid,
      [...originalDocumentRids, addedDocumentRid]
    );
    const replacedDocumentPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.deepEqual(
      replacedDocumentPdb.customDebugInformation.find((record) =>
        record.kind === typeDocumentRecord.kind &&
        record.Parent.target?.rid === emptyTypeRid
      )?.typeDefinitionDocuments,
      [...originalDocumentRids, addedDocumentRid]
    );

    const { token: insertedToken } = assembly.insertTypeDef({
      beforeRid: emptyType.rid,
      name: "InsertedType"
    });
    const insertedTypeRid = insertedToken & 0x00ffffff;
    assembly.addEmbeddedPortablePdbTypeDefinitionDocuments(
      debugEntryIndex,
      insertedTypeRid,
      [addedDocumentRid]
    );
    const insertedPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(
      insertedPdb.customDebugInformation.find((record) =>
        Array.isArray(record.typeDefinitionDocuments) &&
        record.Parent.target?.rid === emptyTypeRid + 1
      )?.Parent.target.rid,
      emptyTypeRid + 1
    );
    assert.deepEqual(
      insertedPdb.customDebugInformation.find((record) =>
        record.kind === typeDocumentRecord.kind &&
        record.Parent.target?.rid === emptyTypeRid + 1
      )?.typeDefinitionDocuments,
      [...originalDocumentRids, addedDocumentRid]
    );
    assert.deepEqual(
      insertedPdb.customDebugInformation.find((record) =>
        record.kind === typeDocumentRecord.kind &&
        record.Parent.target?.rid === insertedTypeRid
      )?.typeDefinitionDocuments,
      [addedDocumentRid]
    );

    assembly.removeEmbeddedPortablePdbDocument(debugEntryIndex, addedDocumentRid);
    const restoredPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    const restoredTypeDocument = restoredPdb.customDebugInformation.find((record) =>
      Array.isArray(record.typeDefinitionDocuments) &&
      record.Parent.target?.rid === emptyTypeRid + 1
    );
    assert.deepEqual(restoredTypeDocument?.typeDefinitionDocuments, originalDocumentRids);
    assert.equal(restoredPdb.customDebugInformation.some((record) =>
      record.kind === typeDocumentRecord.kind &&
      record.Parent.target?.rid === insertedTypeRid
    ), false);

    assembly.removeTypeDef(insertedTypeRid);
    assembly.removeTypeDef(emptyTypeRid);
    const removedPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(
      removedPdb.customDebugInformation.filter((record) =>
        Array.isArray(record.typeDefinitionDocuments)
      ).length,
      originalTypeDocumentCount - 1
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("adding an embedded Portable PDB Document updates the PDB and PE identity", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-document-add-"));
  try {
    const project = join(directory, "PdbDocumentAdd.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(
      join(directory, "Fixture.cs"),
      "public class DocumentFixture { public int Get() { return 1; } }"
    );
    await writeFile(
      join(directory, "Other.cs"),
      "public class OtherDocumentFixture { public int Get() { return 2; } }"
    );
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assembly = parseAssembly(
      Uint8Array.from(await readFile(join(output, "PdbDocumentAdd.dll")))
    );
    const debugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    assert.notEqual(debugIndex, -1);
    const originalPdb = assembly.pe.debugDirectoryEntries[debugIndex].embeddedPortablePdb;
    const originalDocumentCount = originalPdb.documents.length;
    const originalId = Uint8Array.from(originalPdb.id);
    const removableDebugInfo = originalPdb.customDebugInformation[0];
    assert.ok(removableDebugInfo);
    const removedDebugInfoBytes = removeEmbeddedPortablePdbCustomDebugInformation(
      originalPdb,
      removableDebugInfo.rid
    );
    const removedDebugInfoPdb = parseEmbeddedPortablePdbData(
      removedDebugInfoBytes,
      0,
      removedDebugInfoBytes.length
    );
    assert.equal(
      removedDebugInfoPdb.customDebugInformation.length,
      originalPdb.customDebugInformation.length - 1
    );
    const opaqueStreams = new Map(
      [...originalPdb.metadataRoot.streams].map(([name, stream]) =>
        [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
      )
    );
    const guidStream = opaqueStreams.get("#GUID");
    const opaqueKindGuid = Uint8Array.from({ length: 16 }, (_, index) => 0xa0 + index);
    const opaqueKindIndex = guidStream.bytes.length / 16 + 1;
    const expandedGuidHeap = new Uint8Array(guidStream.bytes.length + 16);
    expandedGuidHeap.set(guidStream.bytes);
    expandedGuidHeap.set(opaqueKindGuid, guidStream.bytes.length);
    guidStream.bytes = expandedGuidHeap;
    const opaqueRows = new Map(originalPdb.tables.rows);
    opaqueRows.set(55, originalPdb.tables.rows.get(55).map((row) =>
      row.rid === removableDebugInfo.rid ? { ...row, Kind: opaqueKindIndex } : { ...row }
    ));
    const opaquePdbBytes = serializeEmbeddedPortablePdb({
      ...originalPdb,
      metadataRoot: { ...originalPdb.metadataRoot, streams: opaqueStreams },
      tables: { ...originalPdb.tables, rows: opaqueRows }
    });
    const opaquePdb = parseEmbeddedPortablePdbData(
      opaquePdbBytes,
      0,
      opaquePdbBytes.length
    );
    assert.equal(
      opaquePdb.customDebugInformation.find((record) =>
        record.rid === removableDebugInfo.rid
      ).kind,
      "a3a2a1a0-a5a4-a7a6-a8a9-aaabacadaeaf"
    );
    assert.throws(
      () => insertEmbeddedPortablePdbDocument(opaquePdb, {
        beforeRid: 1,
        name: "generated/opaque-safe.cs"
      }),
      /cannot preserve opaque custom debug information/
    );
    const opaquePdbWithoutRecordBytes = removeEmbeddedPortablePdbCustomDebugInformation(
      opaquePdb,
      removableDebugInfo.rid
    );
    const opaquePdbWithoutRecord = parseEmbeddedPortablePdbData(
      opaquePdbWithoutRecordBytes,
      0,
      opaquePdbWithoutRecordBytes.length
    );
    assert.equal(
      opaquePdbWithoutRecord.customDebugInformation.length,
      originalPdb.customDebugInformation.length - 1
    );
    const debugInfoAssembly = parseAssembly(assembly.serialize());
    const debugInfoDebugIndex = debugInfoAssembly.pe.debugDirectoryEntries.findIndex(
      (entry) => entry.embeddedPortablePdb
    );
    debugInfoAssembly.removeEmbeddedPortablePdbCustomDebugInformation(
      debugInfoDebugIndex,
      removableDebugInfo.rid
    );
    const rewrittenDebugInfoPdb = parseAssembly(debugInfoAssembly.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    assert.equal(
      rewrittenDebugInfoPdb.customDebugInformation.length,
      originalPdb.customDebugInformation.length - 1
    );
    const referencedDocumentRid = originalPdb.methodDebugInformation.find((method) =>
      method.sequencePoints.length > 0
    )?.sequencePoints[0].documentRid;
    assert.ok(referencedDocumentRid);
    const hashAlgorithmGuid = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
    const languageGuid = Uint8Array.from({ length: 16 }, (_, index) => 16 - index);
    const hash = Uint8Array.of(1, 2, 3, 4);
    assembly.addEmbeddedPortablePdbDocument(debugIndex, "generated/new-file.cs", {
      hashAlgorithmGuid,
      hash,
      languageGuid
    });
    assert.throws(
      () => assembly.addEmbeddedPortablePdbDocument(debugIndex, "generated/new-file.cs"),
      /already exists/
    );
    assert.throws(
      () => assembly.addEmbeddedPortablePdbDocument(debugIndex, "generated/invalid.cs", {
        hash: Uint8Array.of(1)
      }),
      /hashes and GUIDs have invalid values/
    );

    const rewritten = parseAssembly(assembly.serialize());
    const rewrittenPdb = rewritten.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(rewrittenPdb.documents.length, originalDocumentCount + 1);
    assert.equal(rewrittenPdb.documents.at(-1).name, "generated/new-file.cs");
    assert.deepEqual(
      Uint8Array.from(rewrittenPdb.heaps.getGuid(rewrittenPdb.documents.at(-1).HashAlgorithm)),
      hashAlgorithmGuid
    );
    assert.deepEqual(
      Uint8Array.from(rewrittenPdb.heaps.getGuid(rewrittenPdb.documents.at(-1).Language)),
      languageGuid
    );
    assert.deepEqual(
      Uint8Array.from(rewrittenPdb.heaps.getBlob(rewrittenPdb.documents.at(-1).Hash)),
      hash
    );
    assert.notDeepEqual(rewrittenPdb.id, originalId);
    const updatedHash = Uint8Array.of(9, 8, 7);
    assembly.replaceEmbeddedPortablePdbDocumentMetadata(
      debugIndex,
      originalDocumentCount + 1,
      { hash: updatedHash }
    );
    const metadataUpdatedPdb = parseAssembly(assembly.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    const updatedDocument = metadataUpdatedPdb.documents.at(-1);
    assert.deepEqual(
      Uint8Array.from(metadataUpdatedPdb.heaps.getGuid(updatedDocument.HashAlgorithm)),
      hashAlgorithmGuid
    );
    assert.deepEqual(
      Uint8Array.from(metadataUpdatedPdb.heaps.getGuid(updatedDocument.Language)),
      languageGuid
    );
    assert.deepEqual(
      Uint8Array.from(metadataUpdatedPdb.heaps.getBlob(updatedDocument.Hash)),
      updatedHash
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbDocumentMetadata(
        debugIndex,
        originalDocumentCount + 1,
        { hashAlgorithmGuid: null }
      ),
      /hashes and GUIDs have invalid values/
    );
    assembly.replaceEmbeddedPortablePdbDocumentMetadata(
      debugIndex,
      originalDocumentCount + 1,
      { hashAlgorithmGuid: null, hash: null, languageGuid: null }
    );
    const clearedMetadataPdb = parseAssembly(assembly.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    assert.equal(clearedMetadataPdb.documents.at(-1).HashAlgorithm, 0);
    assert.equal(clearedMetadataPdb.documents.at(-1).Hash, 0);
    assert.equal(clearedMetadataPdb.documents.at(-1).Language, 0);
    assert.throws(
      () => assembly.removeEmbeddedPortablePdbDocument(debugIndex, referencedDocumentRid),
      /referenced by method debug information/
    );
    assembly.removeEmbeddedPortablePdbDocument(debugIndex, originalDocumentCount + 1);
    const restoredPdb = parseAssembly(assembly.serialize()).pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(restoredPdb.documents.length, originalDocumentCount);
    assert.equal(
      restoredPdb.documents.some((document) => document.name === "generated/new-file.cs"),
      false
    );
    assert.ok(originalDocumentCount >= 2);
    const beforeInvalidInsertion = assembly.serialize();
    assert.throws(
      () => assembly.insertEmbeddedPortablePdbDocument(debugIndex, {
        beforeRid: 0,
        name: "generated/invalid-first.cs"
      }),
      RangeError
    );
    assert.deepEqual(assembly.serialize(), beforeInvalidInsertion);

    assembly.insertEmbeddedPortablePdbDocument(debugIndex, {
      beforeRid: 2,
      name: "generated/inserted-file.cs"
    });
    const insertedPdb = parseAssembly(assembly.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    assert.equal(insertedPdb.documents.length, originalDocumentCount + 1);
    assert.equal(insertedPdb.documents[1].name, "generated/inserted-file.cs");
    const remapDocumentRid = (rid) => rid >= 2 ? rid + 1 : rid;
    for (let index = 0; index < restoredPdb.documents.length; index++) {
      assert.equal(
        insertedPdb.documents[remapDocumentRid(index + 1) - 1].name,
        restoredPdb.documents[index].name
      );
    }
    for (let index = 0; index < restoredPdb.methodDebugInformation.length; index++) {
      const before = restoredPdb.methodDebugInformation[index];
      const after = insertedPdb.methodDebugInformation[index];
      assert.equal(after.Document.rid, remapDocumentRid(before.Document.rid));
      assert.deepEqual(
        after.sequencePoints.map((point) => point.documentRid),
        before.sequencePoints.map((point) => remapDocumentRid(point.documentRid))
      );
    }
    const typeDefinitionDocuments = restoredPdb.customDebugInformation.filter((record) =>
      Array.isArray(record.typeDefinitionDocuments)
    );
    for (const record of typeDefinitionDocuments) {
      const shifted = insertedPdb.customDebugInformation.find((candidate) =>
        candidate.kind === record.kind &&
        candidate.Parent.target?.table === 2 &&
        candidate.Parent.target.rid === record.Parent.target.rid
      );
      assert.deepEqual(
        shifted?.typeDefinitionDocuments,
        record.typeDefinitionDocuments.map(remapDocumentRid)
      );
    }
    for (const record of restoredPdb.customDebugInformation.filter((candidate) =>
      candidate.Parent.target?.table === 48
    )) {
      assert.ok(insertedPdb.customDebugInformation.some((candidate) =>
        candidate.kind === record.kind &&
        candidate.Parent.target?.table === 48 &&
        candidate.Parent.target.rid === remapDocumentRid(record.Parent.target.rid)
      ));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("IL edits rebase state-machine hoisted-local scopes", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-hoisted-scopes-"));
  try {
    const project = join(directory, "PdbHoistedScopes.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(
      join(directory, "Fixture.cs"),
      "using System.Threading.Tasks; " +
      "public class PdbHoistedScopesFixture { " +
      "public async Task<int> ComputeAsync() { int value = 5; " +
      "await Task.Yield(); return value; } }"
    );
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assembly = parseAssembly(
      Uint8Array.from(await readFile(join(output, "PdbHoistedScopes.dll")))
    );
    const pdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const hoistedScopesRecord = pdb?.customDebugInformation.find((record) =>
      Array.isArray(record.stateMachineHoistedLocalScopes) &&
      record.stateMachineHoistedLocalScopes.length > 0
    );
    assert.ok(hoistedScopesRecord);
    const methodRid = hoistedScopesRecord.Parent.target?.rid;
    const asyncSteppingRecord = pdb.customDebugInformation.find((record) =>
      record.Parent.target?.table === 6 &&
      record.Parent.target.rid === methodRid &&
      record.asyncMethodSteppingInformation
    );
    assert.ok(asyncSteppingRecord);
    const method = assembly.methods.find((item) => item.rid === methodRid);
    assert.ok(method);
    const originalScopes = hoistedScopesRecord.stateMachineHoistedLocalScopes;
    const originalAsyncStepping = asyncSteppingRecord.asyncMethodSteppingInformation;

    assembly.insertInstruction(method.rid, 0, "nop");
    const rewritten = parseAssembly(assembly.serialize());
    const rewrittenPdb = rewritten.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    const rewrittenRecord = rewrittenPdb?.customDebugInformation.find((record) =>
      record.kind === hoistedScopesRecord.kind &&
      record.Parent.target?.rid === methodRid
    );
    assert.deepEqual(
      rewrittenRecord?.stateMachineHoistedLocalScopes,
      originalScopes.map((scope) => ({
        startOffset: scope.startOffset + 1,
        length: scope.length
      }))
    );
    const rewrittenAsyncStepping = rewrittenPdb?.customDebugInformation.find((record) =>
      record.kind === asyncSteppingRecord.kind &&
      record.Parent.target?.rid === methodRid
    )?.asyncMethodSteppingInformation;
    assert.deepEqual(rewrittenAsyncStepping, {
      catchHandlerOffset: originalAsyncStepping.catchHandlerOffset < 0
        ? originalAsyncStepping.catchHandlerOffset
        : originalAsyncStepping.catchHandlerOffset + 1,
      steps: originalAsyncStepping.steps.map((step) => ({
        ...step,
        yieldOffset: step.yieldOffset + 1,
        resumeOffset: step.resumeOffset + 1
      }))
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("embedded Portable PDB LocalScope replacement validates method boundaries", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-local-scope-edit-"));
  try {
    const project = join(directory, "PdbLocalScopeEdit.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.cs"), [
      "public static class PdbLocalScopeEditFixture {",
      "  public static int Calculate(int value) {",
      "    int total = value + 1;",
      "    const int constant = 3;",
      "    total += constant;",
      "    if (value > 0) {",
      "      int inner = value + 2;",
      "      total += inner;",
      "    }",
      "    return total;",
      "  }",
      "}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const original = Uint8Array.from(await readFile(join(output, "PdbLocalScopeEdit.dll")));
    const assembly = parseAssembly(original);
    const debugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    assert.notEqual(debugIndex, -1);
    const pdb = assembly.pe.debugDirectoryEntries[debugIndex].embeddedPortablePdb;
    const scopeRows = pdb.tables.rows.get(50) ?? [];
    const scopeEdit = scopeRows.map((scope) => {
      const body = assembly.getMethodBody(scope.Method.rid);
      if (!body) return null;
      const start = scope.StartOffset;
      const end = start + scope.Length;
      const hasChild = scopeRows.some((candidate) =>
        candidate.Method.rid === scope.Method.rid &&
        candidate.rid !== scope.rid &&
        candidate.StartOffset >= start &&
        candidate.StartOffset + candidate.Length <= end
      );
      if (hasChild) return null;
      const boundaries = [
        ...body.instructions.map((instruction) => instruction.offset),
        body.codeSize
      ];
      const shorterEnd = Math.max(...boundaries.filter((offset) =>
        offset > start && offset < end
      ));
      return Number.isFinite(shorterEnd)
        ? { scope, body, shorterLength: shorterEnd - start }
        : null;
    }).find(Boolean);
    assert.ok(scopeEdit, "compiler PDB should contain a leaf scope with an interior instruction boundary");
    const importScopeEdit = scopeRows.find((scope) => scope.ImportScope.rid > 0);
    assert.ok(importScopeEdit, "compiler PDB should associate a LocalScope with an ImportScope");
    const localVariable = (pdb.tables.rows.get(51) ?? []).find((row) =>
      pdb.heaps.getString(row.Name).length > 0
    );
    assert.ok(localVariable, "compiler PDB should contain a named local variable");
    const replacementName = `${pdb.heaps.getString(localVariable.Name)}_edited`;
    const localConstant = (pdb.tables.rows.get(52) ?? []).find((row) =>
      pdb.heaps.getString(row.Name).length > 0
    );
    assert.ok(localConstant, "compiler PDB should contain a named local constant");
    const replacementConstantName = `${pdb.heaps.getString(localConstant.Name)}_edited`;
    const compilationOptions = pdb.customDebugInformation.find((record) =>
      Array.isArray(record.compilationOptions)
    );
    assert.ok(compilationOptions, "compiler PDB should contain CompilationOptions CDI");
    const replacementOptions = new TextEncoder().encode(
      "language\0C#\0optimization\0debug\0"
    );

    const standaloneBytes = replaceEmbeddedPortablePdbLocalScope(
      pdb,
      scopeEdit.scope.rid,
      { length: scopeEdit.shorterLength }
    );
    const standalonePdb = parseEmbeddedPortablePdbData(
      standaloneBytes,
      0,
      standaloneBytes.length
    );
    assert.equal(
      standalonePdb.tables.rows.get(50)[scopeEdit.scope.rid - 1].Length,
      scopeEdit.shorterLength
    );
    const standaloneImportBytes = replaceEmbeddedPortablePdbLocalScope(
      pdb,
      importScopeEdit.rid,
      { importScopeRid: 0 }
    );
    const standaloneImportPdb = parseEmbeddedPortablePdbData(
      standaloneImportBytes,
      0,
      standaloneImportBytes.length
    );
    assert.equal(
      standaloneImportPdb.tables.rows.get(50)[importScopeEdit.rid - 1].ImportScope.rid,
      0
    );
    const standaloneVariableBytes = replaceEmbeddedPortablePdbLocalVariable(
      pdb,
      localVariable.rid,
      { name: replacementName }
    );
    const standaloneVariablePdb = parseEmbeddedPortablePdbData(
      standaloneVariableBytes,
      0,
      standaloneVariableBytes.length
    );
    assert.equal(
      standaloneVariablePdb.heaps.getString(
        standaloneVariablePdb.tables.rows.get(51)[localVariable.rid - 1].Name
      ),
      replacementName
    );
    const standaloneConstantBytes = replaceEmbeddedPortablePdbLocalConstant(
      pdb,
      localConstant.rid,
      { name: replacementConstantName }
    );
    const standaloneConstantPdb = parseEmbeddedPortablePdbData(
      standaloneConstantBytes,
      0,
      standaloneConstantBytes.length
    );
    assert.equal(
      standaloneConstantPdb.heaps.getString(
        standaloneConstantPdb.tables.rows.get(52)[localConstant.rid - 1].Name
      ),
      replacementConstantName
    );
    const standaloneCdiBytes = replaceEmbeddedPortablePdbCustomDebugInformation(
      pdb,
      compilationOptions.rid,
      replacementOptions
    );
    const standaloneCdiPdb = parseEmbeddedPortablePdbData(
      standaloneCdiBytes,
      0,
      standaloneCdiBytes.length
    );
    assert.deepEqual(
      standaloneCdiPdb.customDebugInformation.find((record) =>
        record.rid === compilationOptions.rid
      ).compilationOptions,
      [
        { name: "language", value: "C#" },
        { name: "optimization", value: "debug" }
      ]
    );

    const beforeInvalidEdit = assembly.serialize();
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbLocalScope(
        debugIndex,
        scopeEdit.scope.rid,
        { startOffset: scopeEdit.body.codeSize + 1 }
      ),
      /instruction boundaries/
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbLocalVariable(
        debugIndex,
        localVariable.rid,
        { attributes: 2 }
      ),
      /pinned flag/
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbLocalConstant(
        debugIndex,
        localConstant.rid,
        { name: "invalid\0name" }
      ),
      /null-free/
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbLocalScope(
        debugIndex,
        importScopeEdit.rid,
        { importScopeRid: pdb.tables.counts[53] + 1 }
      ),
      /importScopeRid is out of range/
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdbCustomDebugInformation(
        debugIndex,
        compilationOptions.rid,
        Uint8Array.of(0xff, 0)
      ),
      /valid UTF-8/
    );
    assert.deepEqual(assembly.serialize(), beforeInvalidEdit);
    assembly.replaceEmbeddedPortablePdbLocalScope(
      debugIndex,
      scopeEdit.scope.rid,
      { length: scopeEdit.shorterLength }
    );
    assembly.replaceEmbeddedPortablePdbLocalScope(
      debugIndex,
      importScopeEdit.rid,
      { importScopeRid: 0 }
    );
    assembly.replaceEmbeddedPortablePdbLocalVariable(
      debugIndex,
      localVariable.rid,
      { name: replacementName }
    );
    assembly.replaceEmbeddedPortablePdbLocalConstant(
      debugIndex,
      localConstant.rid,
      { name: replacementConstantName }
    );
    assembly.replaceEmbeddedPortablePdbCustomDebugInformation(
      debugIndex,
      compilationOptions.rid,
      replacementOptions
    );
    const rewritten = parseAssembly(assembly.serialize());
    const rewrittenPdb = rewritten.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(
      rewrittenPdb.tables.rows.get(50)[scopeEdit.scope.rid - 1].Length,
      scopeEdit.shorterLength
    );
    assert.equal(
      rewrittenPdb.tables.rows.get(50)[importScopeEdit.rid - 1].ImportScope.rid,
      0
    );
    assert.equal(
      rewrittenPdb.heaps.getString(
        rewrittenPdb.tables.rows.get(51)[localVariable.rid - 1].Name
      ),
      replacementName
    );
    assert.equal(
      rewrittenPdb.heaps.getString(
        rewrittenPdb.tables.rows.get(52)[localConstant.rid - 1].Name
      ),
      replacementConstantName
    );
    assert.deepEqual(
      rewrittenPdb.customDebugInformation.find((record) =>
        record.rid === compilationOptions.rid
      ).compilationOptions,
      [
        { name: "language", value: "C#" },
        { name: "optimization", value: "debug" }
      ]
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("MethodDef removal removes embedded Portable PDB local scopes", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-method-removal-"));
  try {
    const project = join(directory, "PdbMethodRemoval.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.cs"), [
      "public static class PdbMethodRemovalFixture {",
      "  public static void Before() {}",
      "  public static int Gone<T>(T argument) {",
      "    int local = 41;",
      "    const int constant = 1;",
      "    string label = \"value\";",
      "    return local + constant + label.Length;",
      "  }",
      "  public static int After() {",
      "    int after = 7;",
      "    const int afterConstant = 2;",
      "    return after + afterConstant;",
      "  }",
      "}",
      "public class BeforeType {}",
      "public class AfterType {}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const original = Uint8Array.from(await readFile(join(output, "PdbMethodRemoval.dll")));
    const assembly = parseAssembly(original);
    const method = assembly.methods.find((item) => item.name === "Gone");
    const debugEntry = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    );
    assert.ok(method);
    assert.ok(method.rid > 0 && method.rid <= assembly.methods.length);
    assert.ok(assembly.tables.counts[8] > 0);
    assert.ok(assembly.tables.counts[42] > 0);
    assert.ok(debugEntry);
    const compilerPdb = debugEntry.embeddedPortablePdb;
    const compilationOptions = compilerPdb.customDebugInformation.find((record) =>
      Array.isArray(record.compilationOptions)
    );
    const metadataReferences = compilerPdb.customDebugInformation.find((record) =>
      Array.isArray(record.compilationMetadataReferences)
    );
    const typeDefinitionDocuments = compilerPdb.customDebugInformation.find((record) =>
      Array.isArray(record.typeDefinitionDocuments)
    );
    assert.ok(
      compilationOptions?.compilationOptions.some((option) =>
        option.name === "language" && option.value === "C#"
      ),
      JSON.stringify(compilerPdb.customDebugInformation.map((record) => ({
        kind: record.kind,
        parent: record.Parent.target,
        options: record.compilationOptions
      })))
    );
    assert.ok(metadataReferences?.compilationMetadataReferences.length > 0);
    assert.ok(metadataReferences.compilationMetadataReferences.every((reference) =>
      reference.fileName.length > 0 && reference.mvid.length === 16
    ));
    assert.ok(typeDefinitionDocuments?.typeDefinitionDocuments.length > 0);
    assert.equal(typeDefinitionDocuments?.Parent.target?.table, 2);
    assert.ok(typeDefinitionDocuments?.typeDefinitionDocuments.every((rid) =>
      rid > 0 && rid <= compilerPdb.documents.length
    ));
    const typeRefRemap = parseAssembly(original);
    const typeRefPdbIndex = typeRefRemap.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    const typeRefPdb = typeRefRemap.pe.debugDirectoryEntries[typeRefPdbIndex]
      .embeddedPortablePdb;
    retainPortablePdbCustomDebugInformation(typeRefPdb, (record) =>
      Array.isArray(record.compilationOptions) ||
      Array.isArray(record.compilationMetadataReferences) ||
      Array.isArray(record.typeDefinitionDocuments)
    );
    const typeRefSourceLinkPdbBytes = addEmbeddedPortablePdbSourceLink(typeRefPdb, {
      documents: { "**/*.cs": "https://example.invalid/sources/*" }
    });
    const typeRefSourceLinkPdb = parseEmbeddedPortablePdbData(
      typeRefSourceLinkPdbBytes,
      0,
      typeRefSourceLinkPdbBytes.length
    );
    const typeRefPdbBytes = addEmbeddedPortablePdbSource(
      typeRefSourceLinkPdb,
      1,
      new TextEncoder().encode("safe remapping fixture")
    );
    typeRefRemap.replaceEmbeddedPortablePdb(
      typeRefPdbIndex,
      typeRefPdbBytes
    );
    const { token: insertedTypeRefToken, tokenMap: typeRefTokenMap } =
      typeRefRemap.insertTypeRefSorted({
        name: "Inserted.Before.Scoped"
      });
    assert.ok(typeRefTokenMap.size > 0);
    const typeRefRemapReparsed = parseAssembly(typeRefRemap.serialize());
    const typeRefRemappedPdb = typeRefRemapReparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.equal(typeRefRemappedPdb?.rowCounts.get(1), typeRefRemapReparsed.tables.counts[1]);
    assert.ok(typeRefRemappedPdb?.customDebugInformation.some((record) =>
      record.sourceLink?.documents["**/*.cs"] === "https://example.invalid/sources/*"
    ));
    assert.ok(typeRefRemappedPdb?.customDebugInformation.some((record) =>
      record.embeddedSource?.length === 22
    ));
    assert.ok(typeRefRemappedPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.compilationOptions)
    ));
    assert.ok(typeRefRemappedPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.compilationMetadataReferences)
    ));
    assert.ok(typeRefRemappedPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.typeDefinitionDocuments)
    ));
    typeRefRemap.removeTypeRef(insertedTypeRefToken & 0x00ffffff);
    const typeRefRemovalReparsed = parseAssembly(typeRefRemap.serialize());
    const typeRefRemovalPdb = typeRefRemovalReparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.equal(typeRefRemovalPdb?.rowCounts.get(1), typeRefRemovalReparsed.tables.counts[1]);
    assert.ok(typeRefRemovalPdb?.customDebugInformation.some((record) =>
      record.sourceLink?.documents["**/*.cs"] === "https://example.invalid/sources/*"
    ));
    assert.ok(typeRefRemovalPdb?.customDebugInformation.some((record) =>
      record.embeddedSource?.length === 22
    ));
    assert.ok(typeRefRemovalPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.compilationOptions)
    ));
    assert.ok(typeRefRemovalPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.compilationMetadataReferences)
    ));
    assert.ok(typeRefRemovalPdb?.customDebugInformation.some((record) =>
      Array.isArray(record.typeDefinitionDocuments)
    ));
    const typeDefGuard = parseAssembly(original);
    const typeDefPdbIndex = typeDefGuard.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    const typeDefPdb = typeDefGuard.pe.debugDirectoryEntries[typeDefPdbIndex]
      .embeddedPortablePdb;
    retainPortablePdbCustomDebugInformation(typeDefPdb, (record) =>
      Array.isArray(record.typeDefinitionDocuments)
    );
    const typeDocumentParents = typeDefPdb.customDebugInformation
      .filter((record) => Array.isArray(record.typeDefinitionDocuments))
      .map((record) => record.Parent.target.rid);
    typeDefGuard.replaceEmbeddedPortablePdb(
      typeDefPdbIndex,
      serializeEmbeddedPortablePdb(typeDefPdb)
    );
    typeDefGuard.insertTypeDef({ beforeRid: 2, name: "Inserted.Type" });
    const typeDefRemappedPdb = parseAssembly(typeDefGuard.serialize())
      .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb;
    assert.deepEqual(
      typeDefRemappedPdb.customDebugInformation
        .filter((record) => Array.isArray(record.typeDefinitionDocuments))
        .map((record) => record.Parent.target.rid),
      typeDocumentParents.map((rid) => rid >= 2 ? rid + 1 : rid)
    );
    assert.equal(typeDefRemappedPdb.rowCounts.get(2), typeDefGuard.tables.counts[2]);

    const appendedReference = parseAssembly(original);
    const appendedReferencePdb = appendedReference.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.ok(appendedReferencePdb?.rowCounts.has(35));
    assert.ok(appendedReferencePdb.rowCounts.has(2));
    appendedReference.addAssemblyRef({ name: "PdbRowCount.Dependency" });
    appendedReference.addTypeDef({ name: "PdbRowCount.Type" });
    const appendedReferenceReparsed = parseAssembly(appendedReference.serialize());
    const appendedReferencePdbReparsed = appendedReferenceReparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    for (const table of [2, 35]) {
      assert.equal(
        appendedReferencePdbReparsed?.rowCounts.get(table),
        appendedReferenceReparsed.tables.counts[table]
      );
    }
    assert.ok(debugEntry.embeddedPortablePdb.tables.get(50).some((scope) =>
      scope.Method.rid === method.rid
    ));

    const nonTrailing = parseAssembly(original);
    const nonTrailingTokenMap = nonTrailing.removeMethod(1);
    assert.equal(nonTrailingTokenMap.get(0x06000002), 0x06000001);
    const nonTrailingReparsed = parseAssembly(nonTrailing.serialize());
    assert.equal(nonTrailingReparsed.methods.some((item) => item.name === "Before"), false);
    assert.equal(nonTrailingReparsed.methods.find((item) => item.name === "Gone")?.rid, 1);
    const nonTrailingPdb = nonTrailingReparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.ok(nonTrailingPdb);
    assert.equal(nonTrailingPdb.rowCounts.get(6), nonTrailingReparsed.methods.length);
    assert.equal(nonTrailingPdb.methodDebugInformation.length, nonTrailingReparsed.methods.length);

    const scoped = parseAssembly(original);
    const scopedMethod = scoped.methods.find((item) => item.name === "Gone");
    const scopedPdb = scoped.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    const scopedMethodRows = (scopedPdb.tables.rows.get(50) ?? [])
      .filter((scope) => scope.Method.rid === scopedMethod.rid);
    const variableCountBeforeScopedRemoval = scopedPdb.tables.counts[51];
    const constantCountBeforeScopedRemoval = scopedPdb.tables.counts[52];
    assert.ok(scopedMethodRows.length > 0);
    assert.ok(variableCountBeforeScopedRemoval > 0);
    assert.ok(constantCountBeforeScopedRemoval > 0);
    scoped.removeMethod(scopedMethod.rid);
    const scopedReparsed = parseAssembly(scoped.serialize());
    const scopedPdbAfterRemoval = scopedReparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    assert.equal(scopedReparsed.methods.some((item) => item.name === "Gone"), false);
    const afterMethod = scopedReparsed.methods.find((item) => item.name === "After");
    assert.ok(afterMethod);
    assert.ok((scopedPdbAfterRemoval.tables.rows.get(50) ?? []).some((scope) =>
      scope.Method.rid === afterMethod.rid
    ));
    assert.ok((scopedPdbAfterRemoval.tables.rows.get(51) ?? []).some((variable) =>
      scopedPdbAfterRemoval.heaps.getString(variable.Name) === "after"
    ));
    assert.ok(scopedPdbAfterRemoval.tables.counts[51] < variableCountBeforeScopedRemoval);
    assert.ok(scopedPdbAfterRemoval.tables.counts[52] < constantCountBeforeScopedRemoval);

    const methodDebug = parseAssembly(original);
    const methodDebugPdb = methodDebug.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    ).embeddedPortablePdb;
    const liveMethod = methodDebug.methods.find((item) => item.name === "Before");
    const document = methodDebugPdb.tables.get(48)[0];
    assert.ok(liveMethod);
    assert.ok(document?.Language);
    const customDebugRows = (methodDebugPdb.tables.rows.get(55) ?? [])
      .map((row) => ({ ...row }));
    customDebugRows.push({
      rid: customDebugRows.length + 1,
      Parent: {
        raw: encodeCodedIndex(6, liveMethod.rid, "HasCustomDebugInformation"),
        target: { table: 6, rid: liveMethod.rid }
      },
      Kind: document.Language,
      Value: 0
    });
    customDebugRows.sort((left, right) => left.Parent.raw - right.Parent.raw);
    customDebugRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    methodDebugPdb.tables.rows.set(55, customDebugRows);
    methodDebugPdb.tables.counts[55] = customDebugRows.length;
    methodDebugPdb.tables.valid |= 1n << 55n;
    const methodToRemove = methodDebug.methods.find((item) => item.name === "Gone");
    assert.ok(methodToRemove);
    const beforeCustomDebugRemoval = methodDebug.serialize();
    assert.throws(
      () => methodDebug.removeMethod(methodToRemove.rid),
      /cannot update method-scoped CustomDebugInformation/
    );
    assert.deepEqual(methodDebug.serialize(), beforeCustomDebugRemoval);

    const tokenMap = assembly.removeMethod(method.rid);
    assert.ok(tokenMap.size > 0);
    const rewritten = assembly.serialize();
    const reparsed = parseAssembly(rewritten);
    assert.equal(reparsed.methods.some((item) => item.name === "Gone"), false);
    const updatedPdb = reparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.ok(updatedPdb);
    assert.equal(updatedPdb.rowCounts.get(6), reparsed.methods.length);
    assert.equal(updatedPdb.tables.counts[49], reparsed.methods.length);
    assert.equal(updatedPdb.methodDebugInformation.length, reparsed.methods.length);
    for (const [table, count] of updatedPdb.rowCounts) {
      assert.equal(count, reparsed.tables.counts[table]);
    }

    const rewrittenPath = join(output, "PdbMethodRemovalRewritten.dll");
    const runnerDirectory = join(directory, "runner");
    await mkdir(runnerDirectory);
    await writeFile(rewrittenPath, rewritten);
    await writeFile(join(runnerDirectory, "Runner.csproj"), [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <OutputType>Exe</OutputType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(runnerDirectory, "Program.cs"), [
      "using System;",
      "using System.IO;",
      "using System.Reflection;",
      "var loaded = Assembly.LoadFrom(Path.GetFullPath(args[0]));",
      "var fixture = loaded.GetType(\"PdbMethodRemovalFixture\");",
      "return fixture is null || fixture.GetMethod(\"Gone\") is not null ? 1 : 0;"
    ].join("\n"));
    const load = spawnSync(
      "dotnet",
      ["run", "--project", join(runnerDirectory, "Runner.csproj"), "--configuration", "Release",
        "--no-launch-profile", "--", rewrittenPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(load.status, 0, load.stderr || load.stdout || load.error?.message);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Portable PDB method removal prunes state-machine and async stepping records", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pdb-async-removal-"));
  try {
    const project = join(directory, "AsyncFixture.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.cs"), [
      "public static class AsyncFixture {",
      "  public static async System.Threading.Tasks.Task<int> AsyncGone() {",
      "    await System.Threading.Tasks.Task.Yield();",
      "    return 17;",
      "  }",
      "  public static async System.Threading.Tasks.Task<int> AsyncKept() {",
      "    await System.Threading.Tasks.Task.Yield();",
      "    return 23;",
      "  }",
      "}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assembly = parseAssembly(Uint8Array.from(
      await readFile(join(output, "AsyncFixture.dll"))
    ));
    const method = assembly.methods.find((item) => item.name === "AsyncGone");
    const pdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.ok(method);
    assert.ok(pdb);
    const stateMachineRows = pdb.tables.rows.get(54) ?? [];
    assert.ok(stateMachineRows.some((row) =>
      row.KickoffMethod.rid === method.rid
    ));
    assert.ok(stateMachineRows.length > 1);
    const expectedStateMachineRows = stateMachineRows
      .filter((row) =>
        row.MoveNextMethod.rid !== method.rid &&
        row.KickoffMethod.rid !== method.rid
      )
      .map((row) => ({
        moveNext: row.MoveNextMethod.rid > method.rid
          ? row.MoveNextMethod.rid - 1
          : row.MoveNextMethod.rid,
        kickoff: row.KickoffMethod.rid > method.rid
          ? row.KickoffMethod.rid - 1
          : row.KickoffMethod.rid
      }));
    const asyncStepping = pdb.customDebugInformation.find((record) =>
      record.asyncMethodSteppingInformation
    );
    assert.ok(asyncStepping?.asyncMethodSteppingInformation.steps.length > 0);
    asyncStepping.asyncMethodSteppingInformation.steps[0].methodRid = method.rid;
    const expectedAsyncRecordCount = pdb.customDebugInformation.filter((record) =>
      record.asyncMethodSteppingInformation &&
      !record.asyncMethodSteppingInformation.steps.some((step) =>
        step.methodRid === method.rid
      )
    ).length;

    const oldCounts = [...assembly.tables.counts];
    const newCounts = [...oldCounts];
    newCounts[6]--;
    const rewrittenPdb = removeEmbeddedPortablePdbMethod(
      pdb,
      method.rid,
      oldCounts,
      newCounts
    );
    const reparsedPdb = parseEmbeddedPortablePdbData(
      rewrittenPdb,
      0,
      rewrittenPdb.length
    );
    assert.equal(reparsedPdb.tables.counts[49], newCounts[6]);
    assert.equal(reparsedPdb.tables.counts[54], expectedStateMachineRows.length);
    assert.deepEqual(
      (reparsedPdb.tables.rows.get(54) ?? []).map((row) => ({
        moveNext: row.MoveNextMethod.rid,
        kickoff: row.KickoffMethod.rid
      })),
      expectedStateMachineRows
    );
    assert.equal(reparsedPdb.customDebugInformation.filter((record) =>
      record.asyncMethodSteppingInformation
    ).length, expectedAsyncRecordCount);
    for (const [table, count] of reparsedPdb.rowCounts) {
      assert.equal(count, newCounts[table]);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("VB DefaultNamespace custom debug data survives safe metadata RID remapping", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-vb-pdb-namespace-"));
  try {
    const project = join(directory, "NamespaceFixture.vbproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <RootNamespace>PortableRoot</RootNamespace>",
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.vb"), [
      "Public Module Fixture",
      "    Public Function Answer() As Integer",
      "        Return 42",
      "    End Function",
      "End Module"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Release", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assemblyPath = join(output, "NamespaceFixture.dll");
    const assembly = parseAssembly(Uint8Array.from(await readFile(assemblyPath)));
    const debugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    assert.notEqual(debugIndex, -1);
    const pdb = assembly.pe.debugDirectoryEntries[debugIndex].embeddedPortablePdb;
    const defaultNamespace = pdb.customDebugInformation.find((record) =>
      record.defaultNamespace !== undefined
    );
    assert.equal(defaultNamespace?.Parent.target?.table, 0);
    assert.equal(defaultNamespace?.defaultNamespace, "PortableRoot");

    retainPortablePdbCustomDebugInformation(
      pdb,
      (record) => record.defaultNamespace !== undefined
    );
    assembly.replaceEmbeddedPortablePdb(debugIndex, serializeEmbeddedPortablePdb(pdb));
    const { tokenMap } = assembly.insertTypeRefSorted({
      name: "Added.Before.PortableRoot"
    });
    assert.ok(tokenMap.size > 0);
    const reparsed = parseAssembly(assembly.serialize());
    const reparsedPdb = reparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.equal(reparsedPdb?.customDebugInformation.length, 1);
    assert.equal(reparsedPdb?.customDebugInformation[0].defaultNamespace, "PortableRoot");
    assert.equal(reparsedPdb?.rowCounts.get(1), reparsed.tables.counts[1]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("C# dynamic-local custom debug data survives safe metadata RID remapping", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-csharp-pdb-dynamic-"));
  try {
    const project = join(directory, "DynamicFixture.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>embedded</DebugType>",
      "    <Optimize>false</Optimize>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Fixture.cs"), [
      "public static class DynamicFixture",
      "{",
      "    public static object Answer()",
      "    {",
      "        dynamic value = 42;",
      "        return value;",
      "    }",
      "}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assemblyPath = join(output, "DynamicFixture.dll");
    const assembly = parseAssembly(Uint8Array.from(await readFile(assemblyPath)));
    const debugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    assert.notEqual(debugIndex, -1);
    const pdb = assembly.pe.debugDirectoryEntries[debugIndex].embeddedPortablePdb;
    const dynamicLocals = pdb.customDebugInformation.find((record) =>
      record.dynamicLocalVariables instanceof Uint8Array
    );
    assert.ok(dynamicLocals);
    assert.ok([51, 52].includes(dynamicLocals.Parent.target?.table));
    const expectedValue = dynamicLocals.dynamicLocalVariables.slice();
    retainPortablePdbCustomDebugInformation(
      pdb,
      (record) => record.dynamicLocalVariables instanceof Uint8Array
    );
    assembly.replaceEmbeddedPortablePdb(debugIndex, serializeEmbeddedPortablePdb(pdb));
    const { tokenMap } = assembly.insertTypeRefSorted({
      name: "Added.Before.DynamicFixture"
    });
    assert.ok(tokenMap.size > 0);
    const reparsed = parseAssembly(assembly.serialize());
    const reparsedPdb = reparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.deepEqual(reparsedPdb?.customDebugInformation[0].dynamicLocalVariables, expectedValue);
    assert.equal(reparsedPdb?.rowCounts.get(1), reparsed.tables.counts[1]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("MethodDef removal updates or protects the CLI entry-point token", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-cli-entrypoint-"));
  try {
    const project = join(directory, "EntryPoint.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <OutputType>Exe</OutputType>",
      "    <DebugType>embedded</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Program.cs"), [
      "public interface IUnused { void Removed(); }",
      "public static class Program { public static void Main() { int value = 42; _ = value; } }"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Release", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assemblyPath = join(output, "EntryPoint.dll");
    const original = Uint8Array.from(await readFile(assemblyPath));
    const assembly = parseAssembly(original);
    const removed = assembly.methods.find((method) => method.name === "Removed");
    const main = assembly.methods.find((method) => method.name === "Main");
    assert.ok(removed);
    assert.ok(main);
    assert.ok(removed.rid < main.rid);
    assert.equal(assembly.cli.entryPointToken, 0x06000000 + main.rid);
    const pdbEntry = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    );
    assert.ok(pdbEntry);
    assert.equal(pdbEntry.embeddedPortablePdb.tables.get(50).some((scope) =>
      scope.Method.rid === removed.rid
    ), false);
    assert.ok(pdbEntry.embeddedPortablePdb.tables.get(50).some((scope) =>
      scope.Method.rid === main.rid
    ));

    const rejected = parseAssembly(original);
    const entryPointRid = rejected.cli.entryPointToken & 0x00ffffff;
    const beforeRejectedRemoval = rejected.serialize();
    assert.throws(() => rejected.removeMethod(entryPointRid), /CLI entry point/);
    assert.deepEqual(rejected.serialize(), beforeRejectedRemoval);

    assembly.removeMethod(removed.rid);
    const rewritten = assembly.serialize();
    const reparsed = parseAssembly(rewritten);
    const rewrittenMain = reparsed.methods.find((method) => method.name === "Main");
    assert.ok(rewrittenMain);
    assert.equal(reparsed.cli.entryPointToken, 0x06000000 + rewrittenMain.rid);
    const rewrittenPdb = reparsed.pe.debugDirectoryEntries.find((entry) =>
      entry.embeddedPortablePdb
    )?.embeddedPortablePdb;
    assert.ok(rewrittenPdb);
    assert.equal(rewrittenPdb.rowCounts.get(6), reparsed.methods.length);
    const remappedScope = rewrittenPdb.tables.get(50).find((scope) =>
      scope.Method.rid === rewrittenMain.rid
    );
    assert.ok(remappedScope);
    assert.equal(remappedScope.Method.raw, rewrittenMain.rid);
    await writeFile(assemblyPath, rewritten);
    const execution = spawnSync("dotnet", [assemblyPath], {
      encoding: "utf8",
      timeout: 120_000
    });
    assert.equal(execution.status, 0, execution.stderr || execution.stdout || execution.error?.message);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("classic PDB parser reads a compiler-produced MSF identity", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-classic-pdb-"));
  try {
    const project = join(directory, "ClassicPdb.csproj");
    const output = join(directory, "out");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>full</DebugType>",
      "    <DebugSymbols>true</DebugSymbols>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Class1.cs"), [
      "public static class ClassicPdb {",
      "  public static int Answer()",
      "  {",
      "    var value = 40;",
      "    return value + 2;",
      "  }",
      "}"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Debug", "--output", output, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const pdbBytes = await readFile(join(output, "ClassicPdb.pdb"));
    const signature = new TextDecoder().decode(pdbBytes.subarray(0, 32));
    if (!signature.startsWith("Microsoft C/C++ MSF 7.00")) {
      t.skip("The installed SDK emitted a non-classic PDB format");
      return;
    }
    const pdb = parseClassicPdb(pdbBytes);
    const pe = parsePE(await readFile(join(output, "ClassicPdb.dll")));
    const codeView = pe.debugDirectoryEntries.find((entry) => entry.codeView)?.codeView;
    assert.ok(codeView);
    assert.equal(codeView.guid, pdb.info.guid);
    assert.equal(codeView.age, pdb.info.age);
    assert.ok(pdb.streams.length >= 3);
    assert.ok(pdb.info.namedStreams instanceof Map);
    assert.ok(pdb.info.namedStreams.has("/names"));
    assert.ok(pdb.dbi);
    assert.equal(pdb.dbi.age, pdb.info.age);
    assert.ok(pdb.dbi.version >= 19990903);
    assert.ok(pdb.dbi.modules.some((module) => module.moduleName.length > 0));
    assert.ok(pdb.dbi.modules.some((module) => module.symbols?.records.length > 0));
    assert.ok(pdb.dbi.modules.some((module) =>
      module.symbols?.records.some((record) =>
        record.decoded?.kind === "managedProcedure" &&
        record.decoded.name === "Answer" &&
        record.decoded.methodToken === 0x06000001
      )
    ));
    assert.ok(pdb.dbi.modules.some((module) =>
      module.symbols?.records.some((record) =>
        record.decoded?.kind === "compileInfo" && record.decoded.version.length > 0
      )
    ));
    const checksumModuleIndex = pdb.dbi.modules.findIndex((module) =>
      (module.c13?.fileChecksums.size ?? 0) > 0
    );
    assert.ok(checksumModuleIndex >= 0);
    const checksumModule = pdb.dbi.modules[checksumModuleIndex];
    const [checksumOffset, checksumRecord] = checksumModule.c13.fileChecksums.entries().next().value;
    const appendedChecksumBytes = insertClassicPdbFileChecksum(pdbBytes, {
      moduleIndex: checksumModuleIndex,
      fileNameOffset: checksumRecord.fileNameOffset,
      checksum: new Uint8Array(16).fill(0x43)
    });
    const appendedChecksumPdb = parseClassicPdb(appendedChecksumBytes);
    const appendedChecksumModule = appendedChecksumPdb.dbi.modules[checksumModuleIndex];
    const appendedChecksumOffset = [...appendedChecksumModule.c13.fileChecksums.keys()].at(-1);
    assert.ok(appendedChecksumModule.c13.fileChecksums.has(appendedChecksumOffset));
    const removedChecksumPdb = parseClassicPdb(removeClassicPdbFileChecksum(
      appendedChecksumBytes,
      {
        moduleIndex: checksumModuleIndex,
        fileChecksumOffset: appendedChecksumOffset
      }
    ));
    assert.deepEqual(
      [...removedChecksumPdb.dbi.modules[checksumModuleIndex].c13.fileChecksums.keys()],
      [...checksumModule.c13.fileChecksums.keys()]
    );
    const replacementSize = checksumRecord.checksum.length === 32 ? 20 : 32;
    const replacementChecksum = new Uint8Array(replacementSize).fill(0x5a);
    const resizedPdbBytes = replaceClassicPdbFileChecksum(pdbBytes, {
      moduleIndex: checksumModuleIndex,
      fileChecksumOffset: checksumOffset,
      checksum: replacementChecksum
    });
    const resizedPdb = parseClassicPdb(resizedPdbBytes);
    const resizedModule = resizedPdb.dbi.modules[checksumModuleIndex];
    const resizedChecksum = resizedModule.c13.fileChecksums.get(checksumOffset);
    assert.deepEqual(resizedChecksum.checksum, replacementChecksum);
    for (const subsection of resizedModule.c13.lines) {
      for (const block of subsection.blocks) {
        assert.ok(resizedModule.c13.fileChecksums.has(block.fileChecksumOffset));
      }
    }
    assert.ok(pdb.dbi.modules.some((module) =>
      module.c13?.lines.some((line) =>
        line.blocks.some((block) =>
          block.lines.length > 0 && block.fileName?.endsWith("Class1.cs")
        )
      )
    ));
    const editableLine = pdb.dbi.modules.flatMap((module, moduleIndex) =>
      module.c13?.lines.flatMap((line, lineSubsectionIndex) =>
        line.blocks.flatMap((block, blockIndex) =>
          block.lines.map((record, lineIndex) => ({
            moduleIndex,
            lineSubsectionIndex,
            blockIndex,
            lineIndex,
            record
          }))
        )
      ) ?? []
    ).find((entry, index, entries) =>
      index > 0 && entry.record.offset !== entries[0].record.offset
    );
    assert.ok(editableLine);
    const changedLineOffset = editableLine.record.offset === 0
      ? 1
      : editableLine.record.offset - 1;
    const editedPdbBytes = replaceClassicPdbLineInfo(pdbBytes, {
      moduleIndex: editableLine.moduleIndex,
      lineSubsectionIndex: editableLine.lineSubsectionIndex,
      blockIndex: editableLine.blockIndex,
      lineIndex: editableLine.lineIndex,
      line: { offset: changedLineOffset }
    });
    const editedPdb = parseClassicPdb(editedPdbBytes);
    assert.equal(
      editedPdb.dbi.modules[editableLine.moduleIndex]
        .c13.lines[editableLine.lineSubsectionIndex]
        .blocks[editableLine.blockIndex]
        .lines[editableLine.lineIndex].offset,
      changedLineOffset
    );
    assert.equal(editedPdbBytes.length, pdbBytes.length);
    const editableBlock = pdb.dbi.modules.flatMap((module, moduleIndex) =>
      module.c13?.lines.flatMap((line, lineSubsectionIndex) =>
        line.blocks.map((block, blockIndex) => ({
          moduleIndex,
          lineSubsectionIndex,
          blockIndex,
          block
        }))
      ) ?? []
    ).find((entry) => entry.block.lines.length > 0);
    assert.ok(editableBlock);
    const expandedLines = [
      ...editableBlock.block.lines,
      { ...editableBlock.block.lines.at(-1) }
    ];
    const resizedLineBlockPdb = parseClassicPdb(replaceClassicPdbLineBlock(pdbBytes, {
      moduleIndex: editableBlock.moduleIndex,
      lineSubsectionIndex: editableBlock.lineSubsectionIndex,
      blockIndex: editableBlock.blockIndex,
      lines: expandedLines
    }));
    assert.deepEqual(
      resizedLineBlockPdb.dbi.modules[editableBlock.moduleIndex]
        .c13.lines[editableBlock.lineSubsectionIndex]
        .blocks[editableBlock.blockIndex].lines,
      expandedLines
    );
    const blocksBeforeInsert = pdb.dbi.modules[editableBlock.moduleIndex]
      .c13.lines[editableBlock.lineSubsectionIndex].blocks;
    const insertedLineBlockBytes = insertClassicPdbLineBlock(pdbBytes, {
      moduleIndex: editableBlock.moduleIndex,
      lineSubsectionIndex: editableBlock.lineSubsectionIndex,
      beforeBlockIndex: editableBlock.blockIndex,
      fileChecksumOffset: editableBlock.block.fileChecksumOffset,
      lines: editableBlock.block.lines
    });
    const insertedLineBlock = parseClassicPdb(insertedLineBlockBytes);
    assert.equal(
      insertedLineBlock.dbi.modules[editableBlock.moduleIndex]
        .c13.lines[editableBlock.lineSubsectionIndex].blocks.length,
      blocksBeforeInsert.length + 1
    );
    const removedLineBlock = parseClassicPdb(removeClassicPdbLineBlock(
      insertedLineBlockBytes,
      {
        moduleIndex: editableBlock.moduleIndex,
        lineSubsectionIndex: editableBlock.lineSubsectionIndex,
        blockIndex: editableBlock.blockIndex
      }
    ));
    assert.deepEqual(
      removedLineBlock.dbi.modules[editableBlock.moduleIndex]
        .c13.lines[editableBlock.lineSubsectionIndex].blocks,
      blocksBeforeInsert
    );
    const managedModuleIndex = pdb.dbi.modules.findIndex((module) =>
      module.symbols?.records.some((record) =>
        record.decoded?.kind === "managedProcedure" && record.decoded.name === "Answer"
      )
    );
    const managedRecordIndex = pdb.dbi.modules[managedModuleIndex].symbols.records.findIndex(
      (record) => record.decoded?.kind === "managedProcedure" && record.decoded.name === "Answer"
    );
    assert.throws(() => replaceClassicPdbSymbolName(pdbBytes, {
      moduleIndex: managedModuleIndex,
      recordIndex: managedRecordIndex,
      name: "A"
    }), /cannot resize modules with scoped or unknown symbols/);
    const renamedPdbBytes = replaceClassicPdbSymbolName(pdbBytes, {
      moduleIndex: managedModuleIndex,
      recordIndex: managedRecordIndex,
      name: "Answor"
    });
    const renamedPdb = parseClassicPdb(renamedPdbBytes);
    assert.equal(
      renamedPdb.dbi.modules[managedModuleIndex].symbols.records[managedRecordIndex].decoded.name,
      "Answor"
    );
    const sourceFile = pdb.dbi.modules.flatMap((module) =>
      module.c13?.lines.flatMap((line) => line.blocks) ?? []
    ).find((block) => block.fileName?.endsWith("Class1.cs"));
    assert.ok(sourceFile);
    const replacementPath = sourceFile.fileName.replace("Class1.cs", "OtherLongerSource.cs");
    const renamedPathPdb = parseClassicPdb(replaceClassicPdbStringTableName(pdbBytes, {
      nameOffset: sourceFile.fileNameOffset,
      name: replacementPath
    }));
    assert.ok(renamedPathPdb.dbi.modules.some((module) =>
      module.c13?.lines.some((line) =>
        line.blocks.some((block) => block.fileName === replacementPath)
      )
    ));
    assert.ok(pdb.dbi.modules.some((module) =>
      module.sourceFiles.some((file) => file.endsWith("Class1.cs"))
    ));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rewritten and signed IL assemblies with 15 directories load in .NET", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-runtime-"));
  try {
    const bytes = Uint8Array.from(
      await readFile(new URL("./fixtures/Fixture.dll", import.meta.url))
    );
    const pe = parsePE(bytes);
    const debugDirectoryOffset = pe.optionalHeaderOffset +
      (pe.optionalHeaderMagic === 0x10b ? 96 : 112) + 6 * 8;
    const view = new DataView(bytes.buffer);
    view.setUint32(debugDirectoryOffset, 0, true);
    view.setUint32(debugDirectoryOffset + 4, 0, true);
    view.setUint32(
      pe.optionalHeaderOffset + (pe.optionalHeaderMagic === 0x10b ? 92 : 108),
      15,
      true
    );
    const assembly = parseAssembly(bytes);
    assembly.tables.sorted &= ~(1n << 12n);
    const insertedMethodToken = assembly.insertMethod({
      owner: { table: "TypeDef", rid: assembly.types[1].rid },
      name: "RuntimeInserted",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x08),
      body: Uint8Array.of(0x0e, 0x1f, 43, 0x2a)
    }).token;
    assert.equal(insertedMethodToken >>> 24, 6);
    const objectType = assembly.typeRefs.find((type) =>
      type.namespace === "System" && type.name === "Object"
    );
    assert.ok(objectType);
    const ownerRid = assembly.addTypeDef({
      name: "RuntimeSmokeHolder",
      extends: { table: "TypeRef", rid: objectType.rid }
    }) & 0x00ffffff;
    assembly.tables.sorted &= ~(1n << 11n);
    const fieldRid = assembly.addField({
      owner: { table: "TypeDef", rid: ownerRid },
      name: "RuntimeAnswer",
      flags: 0x0056,
      signature: Uint8Array.of(0x06, 0x08)
    }) & 0x00ffffff;
    assembly.addConstant({
      parent: { table: "Field", rid: fieldRid },
      type: 0x08,
      value: Uint8Array.of(42, 0, 0, 0)
    });
    assembly.addMethod({
      owner: { table: "TypeDef", rid: ownerRid },
      name: "RuntimeSmoke",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x08),
      body: Uint8Array.of(0x0e, 0x1f, 42, 0x2a)
    });
    const tableStream = assembly.metadataRoot.streams.get("#~");
    assert.ok(tableStream);
    assembly.metadataRoot.streams.delete("#~");
    assembly.metadataRoot.streams.set("#-", tableStream);
    if (assembly._heapStreams) {
      assembly._heapStreams.delete("#~");
      assembly._heapStreams.set("#-", tableStream.bytes.slice());
    }
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
    for (const row of assembly.tables.get(2)) {
      row.MethodList = {
        raw: row.MethodList.rid,
        table: 5,
        tableName: "MethodPtr",
        rid: row.MethodList.rid
      };
    }
    assembly._metadataDirty = true;
    assembly.insertMethod({
      owner: { table: "TypeDef", rid: ownerRid },
      name: "PointerInserted",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x08),
      body: Uint8Array.of(0x0e, 0x1f, 44, 0x2a)
    });
    assembly.replaceStrongNamePublicKey(
      generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey
    );
    const assemblyPath = join(directory, "Fixture.dll");
    const rewrittenBytes = assembly.serialize();
    const rewritten = parseAssembly(rewrittenBytes);
    assert.equal(rewritten.pe.directories.length, 15);
    assert.equal(rewritten.verifyStrongNameSignature(), true);
    await writeFile(assemblyPath, rewrittenBytes);
    const projectPath = join(directory, "RuntimeSmoke.csproj");
    await writeFile(projectPath, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      "    <OutputType>Exe</OutputType>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <ImplicitUsings>enable</ImplicitUsings>",
      "    <Nullable>enable</Nullable>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Program.cs"), [
      "using System;",
      "using System.IO;",
      "using System.Reflection;",
      "var assembly = Assembly.LoadFile(Path.GetFullPath(args[0]));",
      "var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;",
      "var inserted = assembly.GetTypes().SelectMany(candidate => candidate.GetMethods(flags))",
      "    .Single(method => method.Name == \"RuntimeInserted\");",
      "var pointerInserted = assembly.GetTypes().SelectMany(candidate => candidate.GetMethods(flags))",
      "    .Single(method => method.Name == \"PointerInserted\");",
      "var type = assembly.GetTypes().Single(candidate =>",
      "    candidate.GetMethods(flags).Any(method => method.Name == \"RuntimeSmoke\"));",
      "var smoke = type.GetMethod(\"RuntimeSmoke\", flags)",
      "    ?? throw new InvalidOperationException(\"RuntimeSmoke was not found\");",
      "var field = type.GetField(\"RuntimeAnswer\", flags)",
      "    ?? throw new InvalidOperationException(\"RuntimeAnswer was not found\");",
      "Console.WriteLine($\"{smoke.Invoke(null, null)}:{field.GetRawConstantValue()}:{inserted.Invoke(null, null)}:{pointerInserted.Invoke(null, null)}\");"
    ].join("\n"));

    const result = spawnSync(
      "dotnet",
      ["run", "--project", projectPath, "--configuration", "Release", "--", assemblyPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
    assert.equal(result.stdout.trim().split(/\r?\n/).at(-1), "42:42:43:44");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rewritten custom-attribute named arguments load in .NET", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-named-attribute-"));
  try {
    const libraryDirectory = join(directory, "library");
    const project = join(directory, "NamedAttributes.csproj");
    await writeFile(project, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>none</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "NamedAttributes.cs"), [
      "[System.AttributeUsage(System.AttributeTargets.Class)]",
      "public sealed class NamedDataAttribute : System.Attribute",
      "{",
      "    public int Count { get; set; }",
      "    public string Label;",
      "    public long Wide { get; set; }",
      "    public ulong UnsignedWide;",
      "    public NamedDataAttribute() { }",
      "}",
      "[NamedData(Count = 5, Label = \"original\", Wide = 9223372036854775807L, UnsignedWide = 18446744073709551615UL)]",
      "public class NamedDataTarget { }",
      "[System.AttributeUsage(System.AttributeTargets.Class)]",
      "public abstract class GenericNamedBase<T> : System.Attribute",
      "{",
      "    public T Value { get; set; }",
      "}",
      "public sealed class ClosedNamedAttribute : GenericNamedBase<int>",
      "{",
      "    public ClosedNamedAttribute() { }",
      "}",
      "[ClosedNamed(Value = 12)]",
      "public class ClosedNamedTarget { }"
    ].join("\n"));
    const build = spawnSync(
      "dotnet",
      ["build", project, "--configuration", "Release", "--output", libraryDirectory, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(build.status, 0, build.stderr || build.stdout || build.error?.message);

    const assemblyPath = join(libraryDirectory, "NamedAttributes.dll");
    const assemblyBytes = Uint8Array.from(await readFile(assemblyPath));
    const assembly = parseAssembly(assemblyBytes);
    const namedTarget = assembly.types.find((type) => type.name === "NamedDataTarget");
    const attribute = assembly.customAttributes.find((record) =>
      record.parent?.table === 2 &&
      record.parent.rid === namedTarget?.rid
    );
    assert.ok(namedTarget);
    assert.ok(attribute);
    const value = assembly.parseCustomAttribute(attribute.rid);
    assert.deepEqual(
      value.namedArguments.map(({ name, value: argumentValue }) => [name, argumentValue]),
      [
        ["Count", 5],
        ["Label", "original"],
        ["Wide", 9223372036854775807n],
        ["UnsignedWide", 18446744073709551615n]
      ]
    );
    const closedNamedTarget = assembly.types.find((type) =>
      type.name === "ClosedNamedTarget"
    );
    const inheritedAttribute = assembly.customAttributes.find((record) =>
      record.parent?.table === 2 &&
      record.parent.rid === closedNamedTarget?.rid
    );
    assert.ok(closedNamedTarget);
    assert.ok(inheritedAttribute);
    const inheritedValue = assembly.parseCustomAttribute(inheritedAttribute.rid);
    assert.deepEqual(inheritedValue.namedArguments.map(({ name, value: argumentValue }) =>
      [name, argumentValue]
    ), [["Value", 12]]);
    const inheritedTypeMismatch = {
      ...inheritedValue,
      namedArguments: inheritedValue.namedArguments.map((argument) => ({
        ...argument,
        type: { kind: "string" },
        value: "twelve"
      }))
    };
    assert.throws(
      () => assembly.replaceCustomAttribute(inheritedAttribute.rid, inheritedTypeMismatch),
      /named property Value has a type that does not match/
    );
    const securityAssembly = parseAssembly(assemblyBytes);
    const permissionSet = {
      format: "binary",
      attributes: [{
        typeName: "NamedDataAttribute, NamedAttributes",
        namedArguments: [{
          kind: "property",
          name: "Count",
          type: { kind: "primitive", elementType: 0x08 },
          value: 9
        }]
      }]
    };
    const securityRid = securityAssembly.addDeclSecurity({
      parent: { table: "Assembly", rid: 1 },
      action: 2,
      permissionSet
    });
    assert.deepEqual(
      securityAssembly.parseDeclSecurity(securityRid).permissionSet,
      permissionSet
    );
    const invalidPermissionSet = {
      ...permissionSet,
      attributes: permissionSet.attributes.map((attribute) => ({
        ...attribute,
        namedArguments: attribute.namedArguments.map((argument) => ({
          ...argument,
          name: "Missing"
        }))
      }))
    };
    const beforeInvalidSecurity = securityAssembly.serialize();
    assert.throws(
      () => securityAssembly.replaceDeclSecurity(securityRid, {
        permissionSet: invalidPermissionSet
      }),
      /named property Missing does not exist/
    );
    assert.throws(
      () => securityAssembly.addDeclSecurity({
        parent: { table: "Assembly", rid: 1 },
        action: 3,
        permissionSet: invalidPermissionSet
      }),
      /named property Missing does not exist/
    );
    assert.deepEqual(securityAssembly.serialize(), beforeInvalidSecurity);
    const beforeInvalidAttributes = assembly.serialize();
    const missingNamedMember = {
      ...value,
      namedArguments: value.namedArguments.map((argument) => ({ ...argument }))
    };
    missingNamedMember.namedArguments[0].name = "Missing";
    assert.throws(
      () => assembly.replaceCustomAttribute(attribute.rid, missingNamedMember),
      /named property Missing does not exist/
    );
    const mismatchedNamedMember = {
      ...value,
      namedArguments: value.namedArguments.map((argument) => ({ ...argument }))
    };
    mismatchedNamedMember.namedArguments[0].type = { kind: "string" };
    mismatchedNamedMember.namedArguments[0].value = "seven";
    assert.throws(
      () => assembly.replaceCustomAttribute(attribute.rid, mismatchedNamedMember),
      /named property Count has a type that does not match/
    );
    assert.deepEqual(assembly.serialize(), beforeInvalidAttributes);
    value.namedArguments.find((argument) => argument.name === "Count").value = 7;
    value.namedArguments.find((argument) => argument.name === "Label").value = "updated";
    value.namedArguments.find((argument) => argument.name === "Wide").value = -9007199254740993n;
    value.namedArguments.find((argument) => argument.name === "UnsignedWide").value = 9007199254740993n;
    assembly.replaceCustomAttribute(attribute.rid, value);
    const rewrittenBytes = assembly.serialize();
    const reparsed = parseAssembly(rewrittenBytes);
    assert.deepEqual(
      reparsed.parseCustomAttribute(attribute.rid).namedArguments.map(({ name, value: argumentValue }) =>
        [name, argumentValue]
      ),
      [
        ["Count", 7],
        ["Label", "updated"],
        ["Wide", -9007199254740993n],
        ["UnsignedWide", 9007199254740993n]
      ]
    );
    await writeFile(assemblyPath, rewrittenBytes);

    const harnessProject = join(directory, "NamedAttributeHarness.csproj");
    await writeFile(harnessProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      "    <OutputType>Exe</OutputType>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Program.cs"), [
      "using System;",
      "using System.IO;",
      "using System.Linq;",
      "using System.Reflection;",
      "var assembly = Assembly.LoadFile(Path.GetFullPath(args[0]));",
      "var attribute = assembly.GetType(\"NamedDataTarget\")!",
      "    .GetCustomAttributes(false).Single(value => value.GetType().Name == \"NamedDataAttribute\");",
      "Console.WriteLine(attribute.GetType().GetProperty(\"Count\")!.GetValue(attribute) + \":\" +",
      "    attribute.GetType().GetField(\"Label\")!.GetValue(attribute) + \":\" +",
      "    attribute.GetType().GetProperty(\"Wide\")!.GetValue(attribute) + \":\" +",
      "    attribute.GetType().GetField(\"UnsignedWide\")!.GetValue(attribute));"
    ].join("\n"));
    const execution = spawnSync(
      "dotnet",
      ["run", "--project", harnessProject, "--configuration", "Release", "--", assemblyPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(execution.status, 0, execution.stderr || execution.stdout || execution.error?.message);
    assert.equal(execution.stdout.trim().split(/\r?\n/).at(-1), "7:updated:-9007199254740993:9007199254740993");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("added embedded resources load and retain their payload in .NET", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-resource-runtime-"));
  try {
    const libraryProject = join(directory, "ResourceLibrary.csproj");
    const libraryOutput = join(directory, "library");
    await writeFile(libraryProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <DebugType>none</DebugType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "ResourceLibrary.cs"),
      "public static class ResourceLibrary { public static int Answer() => 42; }");
    const libraryBuild = spawnSync(
      "dotnet",
      ["build", libraryProject, "--configuration", "Release", "--output", libraryOutput, "--nologo"],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(
      libraryBuild.status,
      0,
      libraryBuild.stderr || libraryBuild.stdout || libraryBuild.error?.message
    );
    const resourceBytes = Uint8Array.of(4, 8, 15, 16, 23, 42);
    const libraryPath = join(libraryOutput, "ResourceLibrary.dll");
    const assembly = parseAssembly(Uint8Array.from(await readFile(libraryPath)));
    assembly.addManifestResource({
      name: "AddedPayload",
      flags: 1,
      data: resourceBytes
    });
    const rewrittenLibraryPath = join(libraryOutput, "ResourceLibrary.Rewritten.dll");
    await writeFile(rewrittenLibraryPath, assembly.serialize());

    const appProject = join(directory, "ResourceReader.csproj");
    await writeFile(appProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <OutputType>Exe</OutputType>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Program.cs"), [
      "using System;",
      "using System.IO;",
      "using System.Reflection;",
      "var target = Assembly.LoadFrom(args[0]);",
      "using var stream = target.GetManifestResourceStream(\"AddedPayload\")",
      "    ?? throw new InvalidOperationException(\"Added resource was not found\");",
      "using var output = new MemoryStream();",
      "stream.CopyTo(output);",
      "Console.WriteLine(Convert.ToHexString(output.ToArray()));"
    ].join("\n"));
    const execution = spawnSync(
      "dotnet",
      ["run", "--project", appProject, "--configuration", "Release", "--", rewrittenLibraryPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(
      execution.status,
      0,
      execution.stdout || execution.stderr || execution.error?.message
    );
    assert.equal(execution.stdout.trim().split(/\r?\n/).at(-1), "04080F10172A");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("strong-name signed PE32+ assemblies load and execute in .NET", {
  skip: dotnetAvailable ? false : ".NET SDK/runtime is unavailable"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "jsilnet-pe32plus-signing-"));
  try {
    const libraryDirectory = join(directory, "library");
    const libraryProject = join(directory, "RuntimeLibrary.csproj");
    await writeFile(libraryProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "    <PlatformTarget>x64</PlatformTarget>",
      "    <Optimize>false</Optimize>",
      "    <DebugType>embedded</DebugType>",
      "    <EmbedAllSources>true</EmbedAllSources>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "RuntimeLibrary.cs"), [
      "public static class RuntimeLibrary",
      "{",
      "    public static int Answer() => 42;",
      "    public static T Echo<T>(T value) => value;",
      "    public static int WithLocal(int value) { int adjusted = value + 1; return adjusted; }",
      "}",
      "public class Outer",
      "{",
      "    public enum Mode : int { Value = 2 }",
      "}",
      "[System.AttributeUsage(System.AttributeTargets.Class)]",
      "public sealed class EnumDataAttribute : System.Attribute",
      "{",
      "    public EnumDataAttribute(Outer.Mode mode) { }",
      "}",
      "[EnumData(Outer.Mode.Value)]",
      "public class NestedEnumTarget { }",
      "[System.AttributeUsage(System.AttributeTargets.Class)]",
      "public abstract class GenericBaseAttribute<T> : System.Attribute { }",
      "public sealed class GenericDataAttribute<T> : GenericBaseAttribute<T>",
      "{",
      "    public GenericDataAttribute(int value) { }",
      "}",
      "[GenericData<int>(42)]",
      "public class GenericDataTarget { }"
    ].join("\n"));
    const libraryBuild = spawnSync(
      "dotnet",
      ["build", libraryProject, "--configuration", "Release", "--output", libraryDirectory],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(
      libraryBuild.status,
      0,
      libraryBuild.stderr || libraryBuild.stdout || libraryBuild.error?.message
    );

    const assemblyPath = join(libraryDirectory, "RuntimeLibrary.dll");
    const assemblyBytes = Uint8Array.from(await readFile(assemblyPath));
    const assembly = parseAssembly(assemblyBytes);
    assert.equal(assembly.pe.optionalHeaderMagic, 0x20b);
    const enumDataAttribute = assembly.customAttributes.find((attribute) =>
      assembly.types.some((type) =>
        type.name === "EnumDataAttribute" &&
        type.methodRids.includes(attribute.constructor.rid) &&
        attribute.constructor.table === 6
      )
    );
    assert.ok(enumDataAttribute);
    assert.equal(
      assembly.parseCustomAttribute(enumDataAttribute.rid).fixedArguments[0],
      2
    );
    const genericAttributeType = assembly.types.find((type) =>
      type.name === "GenericDataAttribute`1"
    );
    const genericAttribute = assembly.customAttributes.find((attribute) => {
      if (attribute.constructor.table !== 10) return false;
      const constructor = assembly.memberRefs.find((reference) =>
        reference.rid === attribute.constructor.rid
      );
      const signature = constructor?.parent.table === 27
        ? assembly.typeSpecs[constructor.parent.rid - 1]?.parsedSignature
        : null;
      return signature?.kind === "genericInstance" &&
        signature.genericType.table === 2 &&
        signature.genericType.rid === genericAttributeType?.rid;
    });
    assert.ok(genericAttributeType);
    assert.ok(genericAttribute);
    assert.deepEqual(assembly.parseCustomAttribute(genericAttribute.rid).fixedArguments, [42]);
    const genericMutationAssembly = parseAssembly(assemblyBytes);
    const genericMutationOwner = genericMutationAssembly.types.find((type) =>
      type.name === "GenericDataTarget"
    );
    assert.ok(genericMutationOwner);
    const genericMutationPdbIndex = genericMutationAssembly.pe.debugDirectoryEntries.findIndex(
      (entry) => entry.embeddedPortablePdb
    );
    const genericMutationPdb =
      genericMutationAssembly.pe.debugDirectoryEntries[genericMutationPdbIndex]
        .embeddedPortablePdb;
    stripPortablePdbMethodCustomDebugInformation(genericMutationPdb);
    genericMutationAssembly.replaceEmbeddedPortablePdb(
      genericMutationPdbIndex,
      serializeEmbeddedPortablePdb(genericMutationPdb)
    );
    const genericMutationToken = genericMutationAssembly.addMethod({
      owner: { table: "TypeDef", rid: genericMutationOwner.rid },
      name: "EchoAddedGeneric",
      flags: 0x0096,
      signature: Uint8Array.of(0x10, 0x01, 0x01, 0x1e, 0x00, 0x1e, 0x00),
      body: Uint8Array.of(0x0a, 0x02, 0x2a)
    });
    const genericMutationRid = genericMutationToken & 0x00ffffff;
    genericMutationAssembly.addGenericParam({
      owner: { table: "MethodDef", rid: genericMutationRid },
      name: "T",
      number: 0
    });
    const genericMutationPath = join(libraryDirectory, "RuntimeLibrary.GenericAdded.dll");
    const genericMutationBytes = genericMutationAssembly.serialize();
    const reparsedGenericMutation = parseAssembly(genericMutationBytes);
    assert.equal(
      reparsedGenericMutation.methods[genericMutationRid - 1].genericParams[0].name,
      "T"
    );
    assert.equal(
      reparsedGenericMutation.pe.debugDirectoryEntries.find((entry) =>
        entry.embeddedPortablePdb
      ).embeddedPortablePdb.rowCounts.get(6),
      reparsedGenericMutation.methods.length
    );
    await writeFile(genericMutationPath, genericMutationBytes);
    const invalidGenericAttributeAssembly = parseAssembly(assemblyBytes);
    const invalidGenericAttributeType = invalidGenericAttributeAssembly.types.find((type) =>
      type.name === "GenericDataAttribute`1"
    );
    const invalidGenericAttributeBase = invalidGenericAttributeAssembly.types.find((type) =>
      type.name === "GenericBaseAttribute`1"
    );
    const invalidGenericAttribute = invalidGenericAttributeAssembly.customAttributes.find((attribute) => {
      if (attribute.constructor.table !== 10) return false;
      const constructor = invalidGenericAttributeAssembly.memberRefs.find((reference) =>
        reference.rid === attribute.constructor.rid
      );
      const signature = constructor?.parent.table === 27
        ? invalidGenericAttributeAssembly.typeSpecs[constructor.parent.rid - 1]?.parsedSignature
        : null;
      return signature?.kind === "genericInstance" &&
        signature.genericType.table === 2 &&
        signature.genericType.rid === invalidGenericAttributeType?.rid;
    });
    const genericObjectTypeRef = invalidGenericAttributeAssembly.typeRefs.find((type) =>
      type.namespace === "System" && type.name === "Object"
    );
    assert.ok(invalidGenericAttributeType);
    assert.ok(invalidGenericAttributeBase);
    assert.ok(invalidGenericAttribute);
    assert.ok(genericObjectTypeRef);
    invalidGenericAttributeBase.extends = {
      table: 1,
      rid: genericObjectTypeRef.rid
    };
    assert.throws(
      () => invalidGenericAttributeAssembly.parseCustomAttribute(invalidGenericAttribute.rid),
      /does not derive from System.Attribute/
    );
    const invalidAttributeAssembly = parseAssembly(assemblyBytes);
    const invalidAttribute = invalidAttributeAssembly.customAttributes.find((attribute) =>
      invalidAttributeAssembly.types.some((type) =>
        type.name === "EnumDataAttribute" &&
        type.methodRids.includes(attribute.constructor.rid) &&
        attribute.constructor.table === 6
      )
    );
    const invalidAttributeType = invalidAttributeAssembly.types.find((type) =>
      type.name === "EnumDataAttribute"
    );
    const objectTypeRef = invalidAttributeAssembly.typeRefs.find((type) =>
      type.namespace === "System" && type.name === "Object"
    );
    assert.ok(invalidAttribute);
    assert.ok(invalidAttributeType);
    assert.ok(objectTypeRef);
    invalidAttributeType.extends = { table: 1, rid: objectTypeRef.rid };
    assert.throws(
      () => invalidAttributeAssembly.parseCustomAttribute(invalidAttribute.rid),
      /does not derive from System.Attribute/
    );
    const embeddedPdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    assert.ok(embeddedPdb);
    const unsafeMethodAdd = parseAssembly(await readFile(assemblyPath));
    const nonTailOwner = unsafeMethodAdd.types.find((type) =>
      type.methodRids.length > 0 &&
      type.methodRids.at(-1) < unsafeMethodAdd.methods.length
    );
    assert.ok(nonTailOwner);
    const unsafePdb = unsafeMethodAdd.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    ).embeddedPortablePdb;
    const unsafeMethodRid = nonTailOwner.methodRids.at(-1) + 1;
    const unsafeDocument = unsafePdb.tables.get(48)[0];
    assert.ok(unsafeDocument?.Language);
    const unsafeCustomDebugRows = (unsafePdb.tables.rows.get(55) ?? [])
      .map((row) => ({ ...row }));
    unsafeCustomDebugRows.push({
      rid: unsafeCustomDebugRows.length + 1,
      Parent: {
        raw: encodeCodedIndex(6, unsafeMethodRid, "HasCustomDebugInformation"),
        target: { table: 6, rid: unsafeMethodRid }
      },
      Kind: unsafeDocument.Language,
      Value: 0
    });
    unsafeCustomDebugRows.sort((left, right) => left.Parent.raw - right.Parent.raw);
    unsafeCustomDebugRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    unsafePdb.tables.rows.set(55, unsafeCustomDebugRows);
    unsafePdb.tables.counts[55] = unsafeCustomDebugRows.length;
    unsafePdb.tables.valid |= 1n << 55n;
    const beforeUnsafeMethodAdd = unsafeMethodAdd.serialize();
    assert.throws(() => unsafeMethodAdd.insertMethod({
      owner: { table: "TypeDef", rid: nonTailOwner.rid },
      name: "DebugInfoUnsafe",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x01),
      body: Uint8Array.of(0x06, 0x2a)
    }), /cannot update method-scoped CustomDebugInformation/);
    assert.deepEqual(unsafeMethodAdd.serialize(), beforeUnsafeMethodAdd);

    const localSignatureEdit = parseAssembly(await readFile(assemblyPath));
    const localSignatureMethod = localSignatureEdit.methods.find((method) =>
      localSignatureEdit.getMethodBody(method.rid)?.localVarSigToken !== 0
    );
    assert.ok(localSignatureMethod);
    const localSignatureRid =
      localSignatureEdit.getMethodBody(localSignatureMethod.rid).localVarSigToken & 0x00ffffff;
    const localSignature = localSignatureEdit.standAloneSigs.find((entry) =>
      entry.rid === localSignatureRid && entry.parsedSignature.kind === "locals"
    );
    assert.ok(localSignature);
    const originalLocalSignaturePdb = localSignatureEdit.pe.debugDirectoryEntries.find(
      (entry) => entry.type === 17
    ).embeddedPortablePdb;
    const originalLocalSignatureValues = originalLocalSignaturePdb.methodDebugInformation
      .map((row) => row.localSignatureRid);
    assert.ok(originalLocalSignatureValues.includes(localSignatureRid));
    const originalStandAloneSigCount = localSignatureEdit.standAloneSigs.length;
    localSignatureEdit.insertStandAloneSig({
      beforeRid: 1,
      signature: localSignature.signature
    });
    const insertedLocalSignatureAssembly = parseAssembly(localSignatureEdit.serialize());
    const insertedLocalSignaturePdb = insertedLocalSignatureAssembly.pe.debugDirectoryEntries
      .find((entry) => entry.type === 17).embeddedPortablePdb;
    assert.equal(
      insertedLocalSignaturePdb.rowCounts.get(17),
      originalStandAloneSigCount + 1
    );
    assert.deepEqual(
      insertedLocalSignaturePdb.methodDebugInformation.map((row) => row.localSignatureRid),
      originalLocalSignatureValues.map((rid) => rid === 0 ? 0 : rid + 1)
    );
    const insertedLocalSignaturePath = join(libraryDirectory, "RuntimeLibrary.SignatureInserted.dll");
    await writeFile(insertedLocalSignaturePath, localSignatureEdit.serialize());
    localSignatureEdit.removeStandAloneSig(1);
    const restoredLocalSignatureAssembly = parseAssembly(localSignatureEdit.serialize());
    const restoredLocalSignaturePdb = restoredLocalSignatureAssembly.pe.debugDirectoryEntries
      .find((entry) => entry.type === 17).embeddedPortablePdb;
    assert.equal(
      restoredLocalSignaturePdb.rowCounts.get(17),
      originalStandAloneSigCount
    );
    assert.deepEqual(
      restoredLocalSignaturePdb.methodDebugInformation.map((row) => row.localSignatureRid),
      originalLocalSignatureValues
    );
    const restoredLocalSignaturePath = join(libraryDirectory, "RuntimeLibrary.SignatureRestored.dll");
    await writeFile(restoredLocalSignaturePath, localSignatureEdit.serialize());

    const shiftedMethodAdd = parseAssembly(await readFile(assemblyPath));
    const shiftedOwner = shiftedMethodAdd.types.find((type) =>
      type.methodRids.length > 0 &&
      type.methodRids.at(-1) < shiftedMethodAdd.methods.length
    );
    assert.ok(shiftedOwner);
    const originalMethodCount = shiftedMethodAdd.methods.length;
    const originalShiftedPdb = shiftedMethodAdd.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    ).embeddedPortablePdb;
    stripPortablePdbMethodCustomDebugInformation(originalShiftedPdb);
    const originalMethodDebugInformation = originalShiftedPdb.methodDebugInformation;
    const originalLocalScopes = originalShiftedPdb.tables.get(50) ?? [];
    const originalStateMachineMethods = originalShiftedPdb.tables.get(54) ?? [];
    originalShiftedPdb.entryPointToken = 0x06000000 + originalMethodCount;
    const shiftedRid = shiftedOwner.methodRids.at(-1) + 1;
    const shiftedMethod = shiftedMethodAdd.insertMethod({
      owner: { table: "TypeDef", rid: shiftedOwner.rid },
      name: "DebugInfoShifted",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x01),
      body: Uint8Array.of(0x06, 0x2a)
    });
    assert.equal(shiftedMethod.token, 0x06000000 + shiftedRid);
    assert.equal(
      shiftedMethod.tokenMap.get(0x06000000 + originalMethodCount),
      0x06000000 + originalMethodCount + 1
    );
    const shiftedMethodBytes = shiftedMethodAdd.serialize();
    const reparsedShiftedMethodAdd = parseAssembly(shiftedMethodBytes);
    const shiftedPdb = reparsedShiftedMethodAdd.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    ).embeddedPortablePdb;
    assert.equal(shiftedPdb.rowCounts.get(6), originalMethodCount + 1);
    assert.equal(
      shiftedPdb.entryPointToken,
      0x06000000 + originalMethodCount + 1
    );
    assert.equal(shiftedPdb.methodDebugInformation.length, originalMethodCount + 1);
    const shiftedLocalScopes = shiftedPdb.tables.get(50) ?? [];
    assert.equal(shiftedLocalScopes.length, originalLocalScopes.length);
    for (const scope of originalLocalScopes) {
      const newMethodRid = scope.Method.rid >= shiftedRid
        ? scope.Method.rid + 1
        : scope.Method.rid;
      assert.equal(shiftedLocalScopes[scope.rid - 1].Method.rid, newMethodRid);
    }
    const shiftedStateMachineMethods = shiftedPdb.tables.get(54) ?? [];
    assert.equal(shiftedStateMachineMethods.length, originalStateMachineMethods.length);
    for (const stateMachine of originalStateMachineMethods) {
      const shiftedRow = shiftedStateMachineMethods[stateMachine.rid - 1];
      for (const column of ["MoveNextMethod", "KickoffMethod"]) {
        const newMethodRid = stateMachine[column].rid >= shiftedRid
          ? stateMachine[column].rid + 1
          : stateMachine[column].rid;
        assert.equal(shiftedRow[column].rid, newMethodRid);
      }
    }
    assert.deepEqual(
      shiftedPdb.methodDebugInformation[shiftedRid - 1].sequencePoints,
      []
    );
    for (let rid = 1; rid <= originalMethodCount; rid++) {
      const newRid = rid >= shiftedRid ? rid + 1 : rid;
      assert.deepEqual(
        shiftedPdb.methodDebugInformation[newRid - 1].sequencePoints,
        originalMethodDebugInformation[rid - 1].sequencePoints
      );
    }
    const shiftedMethodPath = join(libraryDirectory, "RuntimeLibrary.MethodShifted.dll");
    await writeFile(shiftedMethodPath, shiftedMethodBytes);

    const methodAdd = parseAssembly(await readFile(assemblyPath));
    const methodAddSourcePdb = methodAdd.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    ).embeddedPortablePdb;
    stripPortablePdbMethodCustomDebugInformation(methodAddSourcePdb);
    const tailOwner = [...methodAdd.types].reverse().find((type) =>
      type.methodRids.at(-1) === methodAdd.methods.length
    );
    assert.ok(tailOwner);
    assert.equal(methodAdd.methods.length, originalMethodCount);
    const addedMethodToken = methodAdd.addMethod({
      owner: { table: "TypeDef", rid: tailOwner.rid },
      name: "DebugInfoSafe",
      flags: 0x0096,
      signature: Uint8Array.of(0x00, 0x00, 0x01),
      body: Uint8Array.of(0x06, 0x2a)
    });
    assert.equal(addedMethodToken, 0x06000000 + originalMethodCount + 1);
    const methodAddBytes = methodAdd.serialize();
    const reparsedMethodAdd = parseAssembly(methodAddBytes);
    const methodAddPdb = reparsedMethodAdd.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    assert.ok(methodAddPdb);
    assert.equal(methodAddPdb.rowCounts.get(6), originalMethodCount + 1);
    assert.equal(methodAddPdb.methodDebugInformation.length, originalMethodCount + 1);
    assert.deepEqual(methodAddPdb.methodDebugInformation.at(-1).sequencePoints, []);
    const methodAddPath = join(libraryDirectory, "RuntimeLibrary.MethodAdded.dll");
    await writeFile(methodAddPath, methodAddBytes);

    const refreshedOriginalPdb = refreshEmbeddedPortablePdbId(embeddedPdb);
    const reparsedRefreshedPdb = parseEmbeddedPortablePdbData(
      refreshedOriginalPdb.bytes,
      0,
      refreshedOriginalPdb.bytes.length
    );
    assert.deepEqual(
      refreshEmbeddedPortablePdbId(reparsedRefreshedPdb).id,
      refreshedOriginalPdb.id
    );
    const embeddedPdbDebugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.type === 17
    );
    const codeViewDebugIndex = assembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.type === 2 && entry.codeView?.format === "RSDS"
    );
    assert.notEqual(codeViewDebugIndex, -1);
    assembly.replaceCodeViewPath(codeViewDebugIndex, "updated.pdb");
    const embeddedPdbEntry = assembly.pe.debugDirectoryEntries[embeddedPdbDebugIndex];
    const embeddedPdbOffset = embeddedPdbEntry.pointerToRawData !== 0
      ? embeddedPdbEntry.pointerToRawData
      : assembly.pe.rvaToOffset(
        embeddedPdbEntry.addressOfRawData,
        embeddedPdbEntry.sizeOfData
      );
    const originalEmbeddedPdb = assembly.pe.bytes.slice(
      embeddedPdbOffset,
      embeddedPdbOffset + embeddedPdbEntry.sizeOfData
    );
    assert.throws(
      () => assembly.replaceEmbeddedPortablePdb(
        embeddedPdbDebugIndex,
        new Uint8Array(embeddedPdbEntry.sizeOfData + 1)
      ),
      /MPDB header/
    );
    assembly.replaceEmbeddedPortablePdb(embeddedPdbDebugIndex, originalEmbeddedPdb);
    const rewrittenPdbBytes = serializeEmbeddedPortablePdb(embeddedPdb);
    const reparsedPdb = parseEmbeddedPortablePdbData(
      rewrittenPdbBytes,
      0,
      rewrittenPdbBytes.length
    );
    assert.deepEqual(reparsedPdb.id, embeddedPdb.id);
    assert.deepEqual(reparsedPdb.rowCounts, embeddedPdb.rowCounts);
    assert.deepEqual(reparsedPdb.documents, embeddedPdb.documents);
    assert.deepEqual(reparsedPdb.methodDebugInformation, embeddedPdb.methodDebugInformation);
    assert.deepEqual(reparsedPdb.stateMachineMethods, embeddedPdb.stateMachineMethods);
    assert.deepEqual(reparsedPdb.customDebugInformation, embeddedPdb.customDebugInformation);
    assert.throws(
      () => replaceEmbeddedPortablePdbSourceLink(embeddedPdb, {
        documents: { "**/*.cs": 42 }
      }),
      /string mappings/
    );
    const sourceLinkRecord = embeddedPdb.customDebugInformation.find((record) =>
      record.sourceLink
    );
    if (sourceLinkRecord) {
      const sourceLink = {
        ...sourceLinkRecord.sourceLink,
        documents: {
          ...sourceLinkRecord.sourceLink.documents,
          "**/*.cs": "https://example.invalid/source/*"
        }
      };
      const sourceLinkPdbBytes = replaceEmbeddedPortablePdbSourceLink(
        embeddedPdb,
        sourceLink
      );
      const sourceLinkPdb = parseEmbeddedPortablePdbData(
        sourceLinkPdbBytes,
        0,
        sourceLinkPdbBytes.length
      );
      assert.deepEqual(
        sourceLinkPdb.customDebugInformation.find((record) =>
          record.rid === sourceLinkRecord.rid
        ).sourceLink,
        sourceLink
      );
    } else {
      const sourceLinkPdb = {
        documents: { "**/*.cs": "https://example.invalid/source/*" }
      };
      const sourceLinkPdbBytes = addEmbeddedPortablePdbSourceLink(
        embeddedPdb,
        sourceLinkPdb
      );
      const reparsedSourceLink = parseEmbeddedPortablePdbData(
        sourceLinkPdbBytes,
        0,
        sourceLinkPdbBytes.length
      );
      assert.deepEqual(
        reparsedSourceLink.customDebugInformation.find((record) =>
          record.kind === "cc110556-a091-4d38-9fec-25ab9a351a6a"
        ).sourceLink,
        sourceLinkPdb
      );
      assert.throws(
        () => addEmbeddedPortablePdbSourceLink(reparsedSourceLink, sourceLinkPdb),
        /already has a module-scoped SourceLink record/
      );
      const sourceLinkFreePdbBytes = removeEmbeddedPortablePdbSourceLink(reparsedSourceLink);
      const sourceLinkFreePdb = parseEmbeddedPortablePdbData(
        sourceLinkFreePdbBytes,
        0,
        sourceLinkFreePdbBytes.length
      );
      assert.equal(sourceLinkFreePdb.customDebugInformation.some((record) =>
        record.kind === "cc110556-a091-4d38-9fec-25ab9a351a6a"
      ), false);
      const sourceLinkAssembly = parseAssembly(assemblyBytes);
      const sourceLinkDebugIndex = sourceLinkAssembly.pe.debugDirectoryEntries.findIndex((entry) =>
        entry.embeddedPortablePdb
      );
      sourceLinkAssembly.addEmbeddedPortablePdbSourceLink(
        sourceLinkDebugIndex,
        sourceLinkPdb
      );
      const sourceLinkAssemblyReparsed = parseAssembly(sourceLinkAssembly.serialize());
      const sourceLinkAssemblyEntry = sourceLinkAssemblyReparsed.pe.debugDirectoryEntries
        .find((entry) => entry.embeddedPortablePdb);
      assert.deepEqual(sourceLinkAssemblyEntry.embeddedPortablePdb.customDebugInformation.find(
        (record) => record.kind === "cc110556-a091-4d38-9fec-25ab9a351a6a"
      ).sourceLink, sourceLinkPdb);
      sourceLinkAssemblyReparsed.removeEmbeddedPortablePdbSourceLink(
        sourceLinkAssemblyReparsed.pe.debugDirectoryEntries.indexOf(sourceLinkAssemblyEntry)
      );
      assert.equal(parseAssembly(sourceLinkAssemblyReparsed.serialize())
        .pe.debugDirectoryEntries.find((entry) => entry.embeddedPortablePdb)
        .embeddedPortablePdb.customDebugInformation.some((record) =>
          record.kind === "cc110556-a091-4d38-9fec-25ab9a351a6a"
        ), false);
    }
    const embeddedSourceRecord = embeddedPdb.customDebugInformation.find((record) =>
      record.embeddedSource instanceof Uint8Array
    );
    assert.ok(embeddedSourceRecord);
    const changedSource = Uint8Array.from(embeddedSourceRecord.embeddedSource);
    changedSource[0] ^= 1;
    const changedSourcePdbBytes = replaceEmbeddedPortablePdbSource(
      embeddedPdb,
      embeddedSourceRecord.Parent.target.rid,
      changedSource
    );
    const changedSourcePdb = parseEmbeddedPortablePdbData(
      changedSourcePdbBytes,
      0,
      changedSourcePdbBytes.length
    );
    assert.deepEqual(
      changedSourcePdb.customDebugInformation.find((record) =>
        record.rid === embeddedSourceRecord.rid
      ).embeddedSource,
      changedSource
    );
    const changedDocument = changedSourcePdb.documents.find((document) =>
      document.rid === embeddedSourceRecord.Parent.target.rid
    );
    assert.ok(changedDocument);
    assert.deepEqual(
      Uint8Array.from(changedSourcePdb.heaps.getBlob(changedDocument.Hash)),
      Uint8Array.from(createHash("sha256").update(changedSource).digest())
    );
    const sourceFreeRows = new Map(embeddedPdb.tables.rows);
    const sourceFreeDebugRows = embeddedPdb.tables.rows.get(55)
      .filter((row) => row.rid !== embeddedSourceRecord.rid)
      .map((row, index) => ({ ...row, rid: index + 1 }));
    sourceFreeRows.set(55, sourceFreeDebugRows);
    const sourceFreeCounts = [...embeddedPdb.tables.counts];
    sourceFreeCounts[55] = sourceFreeDebugRows.length;
    const sourceFreePdbBytes = serializeEmbeddedPortablePdb({
      ...embeddedPdb,
      customDebugInformation: embeddedPdb.customDebugInformation.filter((record) =>
        record.rid !== embeddedSourceRecord.rid
      ),
      tables: {
        ...embeddedPdb.tables,
        valid: sourceFreeDebugRows.length > 0
          ? embeddedPdb.tables.valid
          : embeddedPdb.tables.valid & ~(1n << 55n),
        counts: sourceFreeCounts,
        rows: sourceFreeRows
      }
    });
    const sourceFreePdb = parseEmbeddedPortablePdbData(
      sourceFreePdbBytes,
      0,
      sourceFreePdbBytes.length
    );
    const addedSourcePdbBytes = addEmbeddedPortablePdbSource(
      sourceFreePdb,
      embeddedSourceRecord.Parent.target.rid,
      changedSource
    );
    const addedSourcePdb = parseEmbeddedPortablePdbData(
      addedSourcePdbBytes,
      0,
      addedSourcePdbBytes.length
    );
    assert.deepEqual(
      addedSourcePdb.customDebugInformation.find((record) =>
        record.kind === embeddedSourceRecord.kind &&
        record.Parent.target.rid === embeddedSourceRecord.Parent.target.rid
      ).embeddedSource,
      changedSource
    );
    const addedSourceDocument = addedSourcePdb.documents.find((document) =>
      document.rid === embeddedSourceRecord.Parent.target.rid
    );
    assert.deepEqual(
      Uint8Array.from(addedSourcePdb.heaps.getBlob(addedSourceDocument.Hash)),
      Uint8Array.from(createHash("sha256").update(changedSource).digest())
    );
    assert.throws(() => addEmbeddedPortablePdbSource(
      addedSourcePdb,
      embeddedSourceRecord.Parent.target.rid,
      changedSource
    ), /already has an EmbeddedSource record/);
    const sourceRemovedPdbBytes = removeEmbeddedPortablePdbSource(
      addedSourcePdb,
      embeddedSourceRecord.Parent.target.rid
    );
    const sourceRemovedPdb = parseEmbeddedPortablePdbData(
      sourceRemovedPdbBytes,
      0,
      sourceRemovedPdbBytes.length
    );
    assert.equal(sourceRemovedPdb.customDebugInformation.some((record) =>
      record.kind === embeddedSourceRecord.kind &&
      record.Parent.target.rid === embeddedSourceRecord.Parent.target.rid
    ), false);
    const sourceAddedAssembly = parseAssembly(assemblyBytes);
    const sourceAddedDebugIndex = sourceAddedAssembly.pe.debugDirectoryEntries.findIndex((entry) =>
      entry.embeddedPortablePdb
    );
    sourceAddedAssembly.replaceEmbeddedPortablePdb(sourceAddedDebugIndex, sourceFreePdbBytes);
    const sourceAddedReparsed = parseAssembly(sourceAddedAssembly.serialize());
    const sourceAddedPdbEntryIndex = sourceAddedReparsed.pe.debugDirectoryEntries.findIndex(
      (entry) => entry.embeddedPortablePdb
    );
    sourceAddedReparsed.addEmbeddedPortablePdbSource(
      sourceAddedPdbEntryIndex,
      embeddedSourceRecord.Parent.target.rid,
      changedSource
    );
    const sourceAddedFinal = parseAssembly(sourceAddedReparsed.serialize());
    const sourceAddedFinalEntry = sourceAddedFinal.pe.debugDirectoryEntries.find(
      (entry) => entry.embeddedPortablePdb
    );
    assert.ok(sourceAddedFinalEntry.embeddedPortablePdb.customDebugInformation.some((record) =>
      record.kind === embeddedSourceRecord.kind &&
      record.Parent.target.rid === embeddedSourceRecord.Parent.target.rid
    ));
    sourceAddedFinal.removeEmbeddedPortablePdbSource(
      sourceAddedFinal.pe.debugDirectoryEntries.indexOf(sourceAddedFinalEntry),
      embeddedSourceRecord.Parent.target.rid
    );
    assert.equal(parseAssembly(sourceAddedFinal.serialize()).pe.debugDirectoryEntries
      .find((entry) => entry.embeddedPortablePdb)
      .embeddedPortablePdb.customDebugInformation.some((record) =>
        record.kind === embeddedSourceRecord.kind &&
        record.Parent.target.rid === embeddedSourceRecord.Parent.target.rid
      ), false);
    const nilHashRows = new Map(embeddedPdb.tables.rows);
    nilHashRows.set(48, embeddedPdb.tables.rows.get(48).map((row) =>
      row.rid === changedDocument.rid ? { ...row, HashAlgorithm: 0 } : { ...row }
    ));
    assert.throws(() => replaceEmbeddedPortablePdbSource(
      { ...embeddedPdb, tables: { ...embeddedPdb.tables, rows: nilHashRows } },
      changedDocument.rid,
      changedSource
    ), /hash algorithm.*unsupported/);
    assembly.replaceEmbeddedPortablePdbSource(
      embeddedPdbDebugIndex,
      embeddedSourceRecord.Parent.target.rid,
      changedSource
    );
    let expectedCustomDebugInformation = changedSourcePdb.customDebugInformation;
    const originalDocumentName = embeddedPdb.documents[0].name;
    const renamedDocument = replaceEmbeddedPortablePdbDocumentName(
      embeddedPdb,
      embeddedPdb.documents[0].rid,
      "renamed-source.cs",
      "\\"
    );
    const renamedPdb = parseEmbeddedPortablePdbData(
      renamedDocument,
      0,
      renamedDocument.length
    );
    assert.equal(renamedPdb.documents[0].name, "renamed-source.cs");
    assert.deepEqual(renamedPdb.id, embeddedPdb.id);
    assert.deepEqual(renamedPdb.methodDebugInformation, embeddedPdb.methodDebugInformation);
    assert.equal(embeddedPdb.documents[0].name, originalDocumentName);
    assert.throws(
      () => replaceEmbeddedPortablePdbDocumentName(embeddedPdb, 0, "source.cs", "\\"),
      /Invalid Portable PDB Document row ID/
    );
    assert.throws(
      () => replaceEmbeddedPortablePdbDocumentName(embeddedPdb, 1, "\ud800", "\\"),
      /valid Unicode/
    );
    assert.throws(
      () => replaceEmbeddedPortablePdbDocumentName(
        {
          ...embeddedPdb,
          documents: [
            ...embeddedPdb.documents,
            { ...embeddedPdb.documents[0], rid: embeddedPdb.documents.length + 1,
              name: "duplicate.cs" }
          ]
        },
        embeddedPdb.documents[0].rid,
        "duplicate.cs",
        "\\"
      ),
      /already exists/
    );
    assert.ok(embeddedPdb.tables.counts[48] > 0);
    assert.ok(embeddedPdb.tables.counts[49] > 0);
    assert.ok(embeddedPdb.heaps.blobs);
    assert.ok(embeddedPdb.documents.some((document) => document.name.length > 0));
    assert.ok(embeddedPdb.methodDebugInformation.some((row) => row.sequencePoints.length > 0));
    const methodDebugInfo = embeddedPdb.methodDebugInformation.find((row) =>
      row.sequencePoints.length > 0 &&
      !embeddedPdb.customDebugInformation.some((record) =>
        record.Parent.target?.table === 6 && record.Parent.target.rid === row.rid
      )
    );
    assert.ok(methodDebugInfo);
    const sequencePointContext = {
      documentRid: methodDebugInfo.Document.rid,
      documentCount: embeddedPdb.documents.length,
      localSignatureCount: assembly.tables.counts[17]
    };
    const sequencePointBlob = encodePortablePdbSequencePoints(methodDebugInfo, sequencePointContext);
    assert.deepEqual(
      decodePortablePdbSequencePoints(sequencePointBlob, sequencePointContext),
      {
        localSignatureRid: methodDebugInfo.localSignatureRid,
        points: methodDebugInfo.sequencePoints
      }
    );
    const changedPoints = methodDebugInfo.sequencePoints.map((point) => ({ ...point }));
    const visiblePointIndex = changedPoints.findIndex((point) => !point.hidden);
    assert.notEqual(visiblePointIndex, -1);
    changedPoints[visiblePointIndex].startLine++;
    changedPoints[visiblePointIndex].endLine++;
    const changedPdbBytes = replaceEmbeddedPortablePdbSequencePoints(
      embeddedPdb,
      methodDebugInfo.rid,
      {
        localSignatureRid: methodDebugInfo.localSignatureRid,
        points: changedPoints
      }
    );
    const changedPdb = parseEmbeddedPortablePdbData(
      changedPdbBytes,
      0,
      changedPdbBytes.length
    );
    assert.equal(
      changedPdb.methodDebugInformation[methodDebugInfo.rid - 1].sequencePoints[visiblePointIndex].startLine,
      changedPoints[visiblePointIndex].startLine
    );
    let expectedMethodDebugInformation = embeddedPdb.methodDebugInformation;
    assembly.replaceEmbeddedPortablePdbSequencePoints(
      embeddedPdbDebugIndex,
      methodDebugInfo.rid,
      {
        localSignatureRid: methodDebugInfo.localSignatureRid,
        points: changedPoints
      }
    );
    const combinedPdbBytes = replaceEmbeddedPortablePdbSequencePoints(
      parseEmbeddedPortablePdbData(
        changedSourcePdbBytes,
        0,
        changedSourcePdbBytes.length
      ),
      methodDebugInfo.rid,
      {
        localSignatureRid: methodDebugInfo.localSignatureRid,
        points: changedPoints
      }
    );
    const combinedPdb = parseEmbeddedPortablePdbData(
      combinedPdbBytes,
      0,
      combinedPdbBytes.length
    );
    const methodBodyBeforePdbRemap = assembly.getMethodBody(methodDebugInfo.rid);
    assert.ok(methodBodyBeforePdbRemap);
    const methodScopes = combinedPdb.tables.rows.get(50)
      .filter((scope) => scope.Method.rid === methodDebugInfo.rid)
      .map((scope) => ({
        rid: scope.rid,
        startOffset: scope.StartOffset + 2,
        length: scope.Length
      }));
    const pdbWithRemappedOffsetsBytes = replaceEmbeddedPortablePdbMethodOffsets(
      combinedPdb,
      methodDebugInfo.rid,
      {
        sequencePoints: changedPoints.map((point) => ({ ...point, offset: point.offset + 2 })),
        localSignatureRid: methodDebugInfo.localSignatureRid,
        scopes: methodScopes
      }
    );
    const pdbWithRemappedOffsets = parseEmbeddedPortablePdbData(
      pdbWithRemappedOffsetsBytes,
      0,
      pdbWithRemappedOffsetsBytes.length
    );
    expectedMethodDebugInformation = pdbWithRemappedOffsets.methodDebugInformation;
    expectedCustomDebugInformation = pdbWithRemappedOffsets.customDebugInformation;
    assembly.insertInstruction(methodDebugInfo.rid, 0, "nop");
    assembly.insertInstruction(methodDebugInfo.rid, 0, "nop");
    assembly.replaceCodeViewPath(codeViewDebugIndex, "final.pdb");
    assembly.replaceStrongNamePublicKey(
      generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey
    );
    const signedBytes = assembly.serialize();
    const signed = parseAssembly(signedBytes);
    assert.equal(signed.verifyStrongNameSignature(), true);
    const rewrittenPdb = signed.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    const expectedPdb = refreshEmbeddedPortablePdbId(rewrittenPdb);
    const normalizeMethodDebugInformation = (rows) => rows.map((row) => {
      const { SequencePoints, ...method } = row;
      return method;
    });
    assert.deepEqual(
      normalizeMethodDebugInformation(rewrittenPdb?.methodDebugInformation ?? []),
      normalizeMethodDebugInformation(expectedMethodDebugInformation)
    );
    assert.deepEqual(rewrittenPdb?.customDebugInformation, expectedCustomDebugInformation);
    assert.deepEqual(rewrittenPdb?.id, expectedPdb.id);
    assert.deepEqual(rewrittenPdb?.documents, combinedPdb.documents);
    const rewrittenScopes = rewrittenPdb.tables.rows.get(50)
      .filter((scope) => scope.Method.rid === methodDebugInfo.rid)
      .map((scope) => ({
        rid: scope.rid,
        startOffset: scope.StartOffset,
        length: scope.Length
      }));
    assert.deepEqual(rewrittenScopes, methodScopes);
    const checksumEntry = signed.pe.debugDirectoryEntries.find((entry) => entry.type === 19);
    assert.ok(checksumEntry);
    const checksumOffset = checksumEntry.pointerToRawData !== 0
      ? checksumEntry.pointerToRawData
      : signed.pe.rvaToOffset(checksumEntry.addressOfRawData, checksumEntry.sizeOfData);
    const checksumBytes = signed.pe.bytes.subarray(
      checksumOffset,
      checksumOffset + checksumEntry.sizeOfData
    );
    const checksumNameEnd = checksumBytes.indexOf(0);
    const checksumName = new TextDecoder("ascii", { fatal: true })
      .decode(checksumBytes.subarray(0, checksumNameEnd));
    assert.deepEqual(
      checksumBytes.subarray(checksumNameEnd + 1),
      expectedPdb.hashes.get(checksumName)
    );
    assert.equal(
      signed.pe.debugDirectoryEntries[codeViewDebugIndex].codeView.path,
      "final.pdb"
    );
    const rewrittenPdbEntry = signed.pe.debugDirectoryEntries[embeddedPdbDebugIndex];
    assert.ok(rewrittenPdbEntry.sizeOfData > 0);
    assert.notEqual(rewrittenPdbEntry.pointerToRawData, embeddedPdbEntry.pointerToRawData);
    assert.equal(
      signed.pe.rvaToOffset(rewrittenPdbEntry.addressOfRawData, rewrittenPdbEntry.sizeOfData),
      rewrittenPdbEntry.pointerToRawData
    );
    await writeFile(assemblyPath, signedBytes);

    const harnessProject = join(directory, "RuntimeHarness.csproj");
    await writeFile(harnessProject, [
      "<Project Sdk=\"Microsoft.NET.Sdk\">",
      "  <PropertyGroup>",
      "    <OutputType>Exe</OutputType>",
      `    <TargetFramework>${targetFramework}</TargetFramework>`,
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "Program.cs"), [
      "using System;",
      "using System.IO;",
      "using System.Linq;",
      "using System.Reflection;",
      "var assembly = Assembly.LoadFile(Path.GetFullPath(args[0]));",
      "var type = assembly.GetType(\"RuntimeLibrary\")",
      "    ?? throw new InvalidOperationException(\"RuntimeLibrary was not found\");",
      "Console.WriteLine(type.GetMethod(\"Answer\")!.Invoke(null, null));",
      "Console.WriteLine(type.GetMethod(\"Echo\")!.MakeGenericMethod(typeof(string)).Invoke(null, new object[] { \"generic\" }));",
      "var mutatedGenericAssembly = Assembly.LoadFile(Path.GetFullPath(args[5]));",
      "var addedGenericMethod = mutatedGenericAssembly.GetType(\"GenericDataTarget\")!.GetMethod(\"EchoAddedGeneric\")!;",
      "Console.WriteLine(addedGenericMethod.MakeGenericMethod(typeof(string)).Invoke(null, new object[] { \"mutated\" }));",
      "var methodAddedAssembly = Assembly.LoadFile(Path.GetFullPath(args[1]));",
      "var addedMethod = methodAddedAssembly.GetTypes()",
      "    .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))",
      "    .Single(method => method.Name == \"DebugInfoSafe\");",
      "addedMethod.Invoke(null, null);",
      "Console.WriteLine(\"method-added\");",
      "var shiftedAssembly = Assembly.LoadFile(Path.GetFullPath(args[2]));",
      "var shiftedMethod = shiftedAssembly.GetTypes()",
      "    .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))",
      "    .Single(method => method.Name == \"DebugInfoShifted\");",
      "shiftedMethod.Invoke(null, null);",
      "Console.WriteLine(\"method-shifted\");",
      "var signatureInserted = Assembly.LoadFile(Path.GetFullPath(args[3]));",
      "var signatureInsertedMethod = signatureInserted.GetType(\"RuntimeLibrary\")!.GetMethod(\"WithLocal\")!;",
      "Console.WriteLine(\"local-sig-inserted:\" + signatureInsertedMethod.Invoke(null, new object[] { 41 }));",
      "var signatureRestored = Assembly.LoadFile(Path.GetFullPath(args[4]));",
      "var signatureRestoredMethod = signatureRestored.GetType(\"RuntimeLibrary\")!.GetMethod(\"WithLocal\")!;",
      "Console.WriteLine(\"local-sig-restored:\" + signatureRestoredMethod.Invoke(null, new object[] { 41 }));"
    ].join("\n"));

    const runtime = spawnSync(
      "dotnet",
      [
        "run",
        "--project",
        harnessProject,
        "--configuration",
        "Release",
        "--",
        assemblyPath,
        methodAddPath,
        shiftedMethodPath,
        insertedLocalSignaturePath,
        restoredLocalSignaturePath,
        genericMutationPath
      ],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(runtime.status, 0, runtime.stderr || runtime.stdout || runtime.error?.message);
    const runtimeOutput = runtime.stdout.trim().split(/\r?\n/);
    assert.equal(runtimeOutput.at(-7), "42");
    assert.equal(runtimeOutput.at(-6), "generic");
    assert.equal(runtimeOutput.at(-5), "mutated");
    assert.equal(runtimeOutput.at(-4), "method-added");
    assert.equal(runtimeOutput.at(-3), "method-shifted");
    assert.equal(runtimeOutput.at(-2), "local-sig-inserted:42");
    assert.equal(runtimeOutput.at(-1), "local-sig-restored:42");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
