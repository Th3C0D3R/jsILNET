import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAssembly, parsePE } from "../src/index.js";

const dotnetVersion = spawnSync("dotnet", ["--version"], { encoding: "utf8" });
const dotnetAvailable = dotnetVersion.status === 0;
const targetFramework = dotnetAvailable
  ? `net${dotnetVersion.stdout.trim().split(".")[0]}.0`
  : null;

test("rewritten IL assemblies load and execute in the installed .NET runtime", {
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
    const assemblyPath = join(directory, "Fixture.dll");
    await writeFile(assemblyPath, assembly.serialize());
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
      "var type = assembly.GetTypes().Single(candidate =>",
      "    candidate.GetMethods(flags).Any(method => method.Name == \"RuntimeSmoke\"));",
      "var smoke = type.GetMethod(\"RuntimeSmoke\", flags)",
      "    ?? throw new InvalidOperationException(\"RuntimeSmoke was not found\");",
      "var field = type.GetField(\"RuntimeAnswer\", flags)",
      "    ?? throw new InvalidOperationException(\"RuntimeAnswer was not found\");",
      "Console.WriteLine($\"{smoke.Invoke(null, null)}:{field.GetRawConstantValue()}:{inserted.Invoke(null, null)}\");"
    ].join("\n"));

    const result = spawnSync(
      "dotnet",
      ["run", "--project", projectPath, "--configuration", "Release", "--", assemblyPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
    assert.equal(result.stdout.trim().split(/\r?\n/).at(-1), "42:42:43");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
