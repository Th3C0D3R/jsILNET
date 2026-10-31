import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodePortablePdbSequencePoints,
  encodePortablePdbSequencePoints,
  parseAssembly,
  parseClassicPdb,
  parsePE,
  replaceEmbeddedPortablePdbDocumentName,
  replaceClassicPdbStringTableName,
  replaceClassicPdbSymbolName,
  replaceEmbeddedPortablePdbSequencePoints,
  replaceEmbeddedPortablePdbSourceLink,
  replaceEmbeddedPortablePdbSource,
  serializeEmbeddedPortablePdb
} from "../src/index.js";
import { parseEmbeddedPortablePdbData } from "../src/pe/headers.js";
import {
  refreshEmbeddedPortablePdbId,
  replaceEmbeddedPortablePdbMethodOffsets
} from "../src/metadata/portable-pdb.js";
import { appendBlobHeap } from "../src/metadata/writer.js";

const dotnetVersion = spawnSync("dotnet", ["--version"], { encoding: "utf8" });
const dotnetAvailable = dotnetVersion.status === 0;
const targetFramework = dotnetAvailable
  ? `net${dotnetVersion.stdout.trim().split(".")[0]}.0`
  : null;

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
    await writeFile(join(directory, "Class1.cs"),
      "public static class ClassicPdb { public static int Answer() => 42; }");
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
    assert.ok(pdb.dbi.modules.some((module) =>
      module.c13?.lines.some((line) =>
        line.blocks.some((block) =>
          block.lines.length > 0 && block.fileName?.endsWith("Class1.cs")
        )
      )
    ));
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
      "    <DebugType>embedded</DebugType>",
      "    <EmbedAllSources>true</EmbedAllSources>",
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "RuntimeLibrary.cs"), [
      "public static class RuntimeLibrary",
      "{",
      "    public static int Answer() => 42;",
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
      "public class NestedEnumTarget { }"
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
    const assembly = parseAssembly(await readFile(assemblyPath));
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
    const embeddedPdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    assert.ok(embeddedPdb);
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
      const streams = new Map([...embeddedPdb.metadataRoot.streams].map(([name, stream]) =>
        [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
      ));
      const [guid1, guid2, guid3, guid4, guid5] =
        "cc110556-a091-4d38-9fec-25ab9a351a6a".split("-");
      const sourceLinkGuid = Uint8Array.from([
        ...guid1.match(/../g).reverse().map((part) => Number.parseInt(part, 16)),
        ...guid2.match(/../g).reverse().map((part) => Number.parseInt(part, 16)),
        ...guid3.match(/../g).reverse().map((part) => Number.parseInt(part, 16)),
        ...guid4.match(/../g).map((part) => Number.parseInt(part, 16)),
        ...guid5.match(/../g).map((part) => Number.parseInt(part, 16))
      ]);
      const guidStream = streams.get("#GUID");
      const sourceLinkKindIndex = guidStream.bytes.length / 16 + 1;
      const expandedGuidStream = new Uint8Array(guidStream.bytes.length + 16);
      expandedGuidStream.set(guidStream.bytes);
      expandedGuidStream.set(sourceLinkGuid, guidStream.bytes.length);
      guidStream.bytes = expandedGuidStream;
      const blobStream = streams.get("#Blob");
      const sourceLinkValue = appendBlobHeap(
        blobStream.bytes,
        new TextEncoder().encode(JSON.stringify({ documents: { "**/*.cs": "old" } }))
      );
      blobStream.bytes = sourceLinkValue.heap;
      const parent = { raw: 39, target: { table: 0, rid: 1 } };
      const sourceLinkRow = {
        table: 55,
        tableName: "CustomDebugInformation",
        rid: 1,
        Parent: parent,
        Kind: sourceLinkKindIndex,
        Value: sourceLinkValue.index
      };
      const debugRows = embeddedPdb.tables.rows.get(55) ?? [];
      const rows = new Map(embeddedPdb.tables.rows);
      rows.set(55, [
        sourceLinkRow,
        ...debugRows.map((row) => ({ ...row, rid: row.rid + 1 }))
      ]);
      const sourceLinkPdb = {
        ...embeddedPdb,
        metadataRoot: { ...embeddedPdb.metadataRoot, streams },
        tables: {
          ...embeddedPdb.tables,
          valid: embeddedPdb.tables.valid | (1n << 55n),
          counts: [...embeddedPdb.tables.counts],
          rows
        },
        customDebugInformation: [
          {
            rid: 1,
            Parent: { target: { table: 0, rid: 1 } },
            kind: "cc110556-a091-4d38-9fec-25ab9a351a6a",
            sourceLink: { documents: { "**/*.cs": "old" } }
          },
          ...embeddedPdb.customDebugInformation.map((record) => ({
            ...record,
            rid: record.rid + 1
          }))
        ]
      };
      const updatedSourceLink = {
        documents: { "**/*.cs": "https://example.invalid/source/*" }
      };
      const sourceLinkPdbBytes = replaceEmbeddedPortablePdbSourceLink(
        sourceLinkPdb,
        updatedSourceLink
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
        updatedSourceLink
      );
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
      "using System.Reflection;",
      "var assembly = Assembly.LoadFile(Path.GetFullPath(args[0]));",
      "var type = assembly.GetType(\"RuntimeLibrary\")",
      "    ?? throw new InvalidOperationException(\"RuntimeLibrary was not found\");",
      "Console.WriteLine(type.GetMethod(\"Answer\")!.Invoke(null, null));"
    ].join("\n"));

    const runtime = spawnSync(
      "dotnet",
      ["run", "--project", harnessProject, "--configuration", "Release", "--", assemblyPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(runtime.status, 0, runtime.stderr || runtime.stdout || runtime.error?.message);
    assert.equal(runtime.stdout.trim().split(/\r?\n/).at(-1), "42");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
