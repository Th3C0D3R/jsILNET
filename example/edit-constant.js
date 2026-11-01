import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseAssembly } from "jsilnet";

const [inputPath, methodName, rawValue, outputPath, ...extraArgs] = process.argv.slice(2);
const value = Number(rawValue);

if (!inputPath || !methodName || !/^-?\d+$/.test(rawValue ?? "") ||
    !Number.isInteger(value) || value < -128 || value > 127 ||
    !outputPath || extraArgs.length > 0) {
  console.error(
    "Usage: node example/edit-constant.js <assembly.dll> <method-name> <signed-byte> <output.dll>"
  );
  process.exitCode = 1;
} else {
  if (resolve(inputPath) === resolve(outputPath)) {
    throw new Error("Choose a separate output path so the input assembly is not overwritten");
  }

  const assembly = parseAssembly(new Uint8Array(await readFile(inputPath)));
  const matches = assembly.methods.filter((method) => method.name === methodName);
  if (matches.length !== 1) {
    throw new Error(`Expected one method named ${methodName}, found ${matches.length}`);
  }

  const method = matches[0];
  const instruction = assembly
    .getInstructions(method.rid)
    .find((item) => item.opcode.name === "ldc.i4.s");
  if (!instruction) {
    throw new Error(`Method ${methodName} has no ldc.i4.s instruction to edit`);
  }

  assembly.setInstructionOperand(method.rid, instruction.offset, value);
  const output = assembly.toBuffer();
  const reparsed = parseAssembly(output);
  const updatedMethod = reparsed.methods.find((item) => item.rid === method.rid);
  const updatedInstruction = reparsed
    .getInstructions(updatedMethod.rid)
    .find((item) => item.offset === instruction.offset);
  if (updatedInstruction?.operand.value !== value) {
    throw new Error("Edited constant did not survive serialization and reparsing");
  }

  await writeFile(outputPath, output);
  console.log(`Changed ${methodName}'s ldc.i4.s constant to ${value}`);
  console.log(`Wrote and reparsed ${outputPath}`);
}
