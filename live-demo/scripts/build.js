import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const demoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(demoRoot, "..");
const outputDirectory = resolve(demoRoot, "dist");

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await build({
  entryPoints: [resolve(demoRoot, "app.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  outfile: resolve(outputDirectory, "app.js"),
});

await Promise.all([
  cp(resolve(demoRoot, "index.html"), resolve(outputDirectory, "index.html")),
  cp(resolve(demoRoot, "styles.css"), resolve(outputDirectory, "styles.css")),
  cp(resolve(repositoryRoot, "dist", "browser", "worker.js"), resolve(outputDirectory, "worker.js")),
]);
