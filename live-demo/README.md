# jsILNET Live Demo

This Vercel subproject provides a small web interface for inspecting .NET assemblies and changing an existing `ldc.i4.s` operand. Parsing and editing run in a Node.js function; the browser does not bundle jsILNET.

Uploads are held in memory for the request and are not saved. The demo accepts assemblies up to 3 MiB, displays up to 200 types, and scans up to the first 200 methods for editable constants. Editing keeps the instruction width unchanged and reparses the output before returning it.

## Run locally

Requirements: Node.js 20 or later and the Vercel CLI.

From this directory:

```sh
npm install
npm test
npx vercel dev
```

Open the local URL printed by Vercel CLI. The repository's `test/fixtures/Fixture.dll` is a small assembly with an editable `Answer` method.

## Deploy to Vercel

1. Push this repository to GitHub.
2. In Vercel, import the repository as a new project.
3. Set **Root Directory** to `live-demo` and enable **Include source files outside of the Root Directory in the Build Step**. The project uses the local `jsilnet` package from the repository root.
4. Use the **Other** framework preset. Leave the build command and output directory unset.
5. Select a Node.js version supported by Vercel that is 20 or later.
6. Deploy. Vercel serves `index.html` as the page and the functions in `api/` as the inspection and edit endpoints.

The project has no secrets or environment variables to configure. Pushes to the connected branch trigger new deployments.

## Demo behavior

- Inspect displays the assembly name, version, type and method counts, a type list, and methods containing an `ldc.i4.s` instruction.
- Patch and download changes the selected instruction's signed-byte value, verifies the serialized assembly by parsing it again, and downloads `edited-assembly.dll`.
- Other assembly content remains untouched by this demo operation. The original upload is never overwritten or retained.
