import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAssembly } from "../src/index.js";

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
    const assembly = parseAssembly(
      await readFile(new URL("./fixtures/Fixture.dll", import.meta.url))
    );
    const owner = assembly.types.at(-1);
    assembly.addMethod({
      owner: { table: "TypeDef", rid: owner.rid },
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
      "var type = assembly.GetTypes().Single(candidate =>",
      "    candidate.GetMethods(flags).Any(method => method.Name == \"RuntimeSmoke\"));",
      "if (type.IsGenericTypeDefinition)",
      "    type = type.MakeGenericType(Enumerable.Repeat(typeof(object), type.GetGenericArguments().Length).ToArray());",
      "var smoke = type.GetMethod(\"RuntimeSmoke\", flags)",
      "    ?? throw new InvalidOperationException(\"RuntimeSmoke was not found\");",
      "Console.WriteLine(smoke.Invoke(null, null));"
    ].join("\n"));

    const result = spawnSync(
      "dotnet",
      ["run", "--project", projectPath, "--configuration", "Release", "--", assemblyPath],
      { encoding: "utf8", timeout: 120_000 }
    );
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
    assert.equal(result.stdout.trim().split(/\r?\n/).at(-1), "42");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
