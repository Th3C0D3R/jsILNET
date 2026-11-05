# jsILNET Live Demo

This static demo inspects .NET assemblies and edits an existing `ldc.i4.s` operand entirely in the browser. Parsing, instruction scanning, editing, and serialization run asynchronously in Web Workers. Files are not uploaded or retained.

The demo accepts DLL and EXE files up to 3 MiB, scans up to the first 200 methods, and displays up to 100 editable instructions. It reparses the output in a separate worker before starting the download.

## Build and preview

Requirements: Node.js 20 or later.

From the repository root, install the root and demo dependencies, then build and preview:

```sh
npm install
npm install --prefix live-demo
npm run build --prefix live-demo
npm run serve --prefix live-demo
```

Open the local address printed by the server. The repository's `test/fixtures/Fixture.dll` contains an editable `Answer` method.

The build output is `live-demo/dist/`. Deploy that directory to any static web host that serves JavaScript modules and workers from the same origin. The demo has no server-side API or runtime service.
