import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseAssembly,
  parseClassicPdb,
  parsePE,
  replaceClassicPdbStringTableName,
  replaceClassicPdbSymbolName
} from "../src/index.js";

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
    const replacementPath = sourceFile.fileName.replace("Class1.cs", "Other1.cs");
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
      "  </PropertyGroup>",
      "</Project>"
    ].join("\n"));
    await writeFile(join(directory, "RuntimeLibrary.cs"), [
      "public static class RuntimeLibrary",
      "{",
      "    public static int Answer() => 42;",
      "}"
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
    const embeddedPdb = assembly.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    assert.ok(embeddedPdb);
    assert.ok(embeddedPdb.tables.counts[48] > 0);
    assert.ok(embeddedPdb.tables.counts[49] > 0);
    assert.ok(embeddedPdb.heaps.blobs);
    assert.ok(embeddedPdb.documents.some((document) => document.name.length > 0));
    assert.ok(embeddedPdb.methodDebugInformation.some((row) => row.sequencePoints.length > 0));
    assembly.replaceStrongNamePublicKey(
      generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey
    );
    const signedBytes = assembly.serialize();
    const signed = parseAssembly(signedBytes);
    assert.equal(signed.verifyStrongNameSignature(), true);
    const rewrittenPdb = signed.pe.debugDirectoryEntries.find((entry) =>
      entry.type === 17
    )?.embeddedPortablePdb;
    assert.deepEqual(rewrittenPdb?.id, embeddedPdb.id);
    assert.deepEqual(rewrittenPdb?.documents, embeddedPdb.documents);
    assert.deepEqual(rewrittenPdb?.methodDebugInformation, embeddedPdb.methodDebugInformation);
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
