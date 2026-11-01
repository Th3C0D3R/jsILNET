# Runnable example

This example builds a small managed assembly, inspects it with jsILNET, writes a
byte-identical round trip, and edits an existing IL constant. The library itself
does not require .NET; the .NET SDK is only used here to create the sample DLL.

From the repository root, run:

```sh
dotnet build example/Sample.csproj -c Release
node example/inspect.js example/bin/Release/net10.0/Sample.dll example/bin/Release/net10.0/Sample.roundtrip.dll
node example/edit-constant.js example/bin/Release/net10.0/Sample.dll Answer 43 example/bin/Release/net10.0/Sample.edited.dll
```

`inspect.js` lists metadata and IL instructions, then optionally saves and
reparses an unchanged output. `edit-constant.js` updates the `ldc.i4.s`
instruction in the named method, saves the rewritten DLL, and reparses it to
confirm the edit survived.

To try the scripts with your own assembly, replace the sample DLL path with a
managed `.dll` that matches jsILNET's supported input profile. Both scripts
require Node.js 20 or later.
