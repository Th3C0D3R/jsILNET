import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseAssembly } from "jsilnet";

const [inputPath, outputPath, ...extraArgs] = process.argv.slice(2);

if (!inputPath || extraArgs.length > 0) {
  console.error("Usage: node example/inspect.js <assembly.dll> [roundtrip.dll]");
  process.exitCode = 1;
} else {
  if (outputPath && resolve(inputPath) === resolve(outputPath)) {
    throw new Error("Choose a separate output path so the input assembly is not overwritten");
  }

  const input = new Uint8Array(await readFile(inputPath));
  const assembly = parseAssembly(input);

  console.log(`Types: ${assembly.types.length}`);
  console.log(`Methods: ${assembly.methods.length}`);
  for (const method of assembly.methods.slice(0, 10)) {
    const instructions = method.rva === 0 ? [] : assembly.getInstructions(method.rid);
    console.log(`\n${method.name} (RID ${method.rid})`);
    for (const instruction of instructions.slice(0, 12)) {
      const offset = instruction.offset.toString(16).padStart(4, "0");
      console.log(`  IL_${offset}: ${instruction.opcode.name}`);
    }
    if (instructions.length > 12) console.log("  ...");
  }

  if (outputPath) {
    const output = assembly.toBuffer();
    parseAssembly(output);
    await writeFile(outputPath, output);
    console.log(`\nWrote and reparsed ${outputPath}`);
    console.log(`Byte-identical round trip: ${Buffer.compare(input, output) === 0}`);
  }
}
