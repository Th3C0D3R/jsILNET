import {
  Assembly,
  FormatError,
  UnsupportedFormatError,
  parseAssembly
} from "jsilnet";

declare const input: Uint8Array;
const assembly: Assembly = parseAssembly(input);
const typeNames: string[] = assembly.types.map((type) =>
  type.namespace ? `${type.namespace}.${type.name}` : type.name
);
const methodNames: string[] = assembly.methods.map((method) => method.name);
const body = assembly.methods[0]
  ? assembly.getMethodBody(assembly.methods[0].rid)
  : null;
const instructions = body?.instructions ?? [];
if (instructions[0]?.operand?.kind === "branch") {
  assembly.setInstructionOperand(
    assembly.methods[0].rid,
    instructions[0].offset,
    instructions[0].operand.targetOffset
  );
}
const output: Uint8Array = assembly.serialize();
const buffer: Uint8Array = assembly.toBuffer();
const errors: Error[] = [
  new FormatError("bad input", { offset: 0, context: "test" }),
  new UnsupportedFormatError("unsupported")
];

void typeNames;
void methodNames;
void output;
void buffer;
void errors;
