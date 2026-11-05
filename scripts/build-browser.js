import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = new URL("../", import.meta.url);
const outdir = fileURLToPath(new URL("../dist/browser/", import.meta.url));

await build({
  entryPoints: {
    index: fileURLToPath(new URL("src/browser/index.js", root)),
    worker: fileURLToPath(new URL("src/browser/worker.js", root))
  },
  outdir,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  logLevel: "info"
});
