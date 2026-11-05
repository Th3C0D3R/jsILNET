# jsILNET

`jsILNET` is a JavaScript library for inspecting and rewriting .NET assemblies. It reads PE/CLI formats directly and does not require a .NET runtime. The package provides a synchronous Node.js API and a Promise-based browser API backed by a Web Worker.

## Requirements

- Node.js 20 or later
- ECMAScript modules
- Web Workers for the browser entry point (`jsilnet/browser`)

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

## Browser usage

In a browser application using a package-aware bundler with module Worker support, import the separate browser entry point:

```js
import { parseAssembly } from "jsilnet/browser";

async function roundTripFile(file) {
  const assembly = await parseAssembly(file); // File and Blob inputs are supported.
  try {
    const state = await assembly.getState();
    console.log(`Assembly modified: ${state.modified}`);
    const bytes = await assembly.serialize();
    return new Blob([bytes], { type: "application/octet-stream" });
  } finally {
    assembly.dispose();
  }
}
```

The browser API is Promise-based and runs parsing, editing, and serialization in a Web Worker; the default Node.js entry point remains synchronous. Assembly methods must be awaited, `getState()` returns a snapshot, and `serialize()` returns a `Uint8Array`. Resolver callbacks such as `resolveEnum` and `resolveType` may be synchronous or asynchronous. Calling `dispose()` terminates the Worker and releases its Assembly state.

`parseAssembly` also accepts `Uint8Array` and `ArrayBuffer`. For full-buffer byte inputs, `{ transferInput: true }` transfers the input to the Worker and detaches it from the caller; subarray views are copied.

## Live Demo
The browser-only demo in `live-demo/` inspects and patches .NET assemblies without uploading them. Build it with `npm run build --prefix live-demo`, then serve `live-demo/dist/` from any static web host. See [`live-demo/README.md`](live-demo/README.md) for local preview instructions.

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
npm run check:browser
```
