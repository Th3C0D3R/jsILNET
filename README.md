# jsILNET

`jsILNET` is a dependency-free JavaScript library for inspecting and rewriting .NET assemblies. It reads PE/CLI formats directly and does not require a .NET runtime.

## Requirements

- Node.js 20 or later
- ECMAScript modules

## Install

```sh
npm install jsilnet
```

## Quick start

Read an assembly, inspect its metadata, and write an unchanged round trip:

```js
import { readFile, writeFile } from "node:fs/promises";
import { parseAssembly } from "jsilnet";

const input = new Uint8Array(await readFile("input.dll"));
const assembly = parseAssembly(input);

console.log(`Types: ${assembly.types.length}`);
console.log(`Methods: ${assembly.methods.length}`);

await writeFile("roundtrip.dll", assembly.toBuffer());
```

## Example: edit an existing IL operand

This example updates an existing `ldc.i4.s` operand in a method named `Answer` and writes the rewritten assembly:

```js
import { readFile, writeFile } from "node:fs/promises";
import { parseAssembly } from "jsilnet";

const assembly = parseAssembly(new Uint8Array(await readFile("input.dll")));
const method = assembly.methods.find((item) => item.name === "Answer");
if (!method) throw new Error("Method Answer was not found");

const instruction = assembly
  .getInstructions(method.rid)
  .find((item) => item.opcode.name === "ldc.i4.s");
if (!instruction) throw new Error("No ldc.i4.s instruction was found");

assembly.setInstructionOperand(method.rid, instruction.offset, 43);
await writeFile("output.dll", assembly.toBuffer());
```

Edits are validated against the supported input profile; unsupported or unsafe rewrites fail explicitly. See the [Current capabilities](REFERENCE.md#current-capabilities) and [API surface](REFERENCE.md#api-surface) references for supported features, APIs, and limitations.

## Documentation

- [Runnable example](example/README.md)
- [Current capabilities](REFERENCE.md#current-capabilities)
- [API surface](REFERENCE.md#api-surface)
- [Architecture and implementation status](ARCHITECTURE.md)

## Development

```sh
npm install
npm test
npm run check
```
