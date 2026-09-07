import { access, cp, mkdir, readdir, rm } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = resolve(root, "dist");

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

const rootEntries = await readdir(root, { withFileTypes: true });
const staticExtensions = new Set([".html", ".css", ".js"]);

for (const entry of rootEntries) {
  if (!entry.isFile()) continue;
  if (entry.name === "_headers") {
    await cp(resolve(root, entry.name), resolve(output, entry.name));
    continue;
  }
  const extension = entry.name.slice(entry.name.lastIndexOf("."));
  if (!staticExtensions.has(extension)) continue;
  await cp(resolve(root, entry.name), resolve(output, entry.name));
}

for (const directory of ["assets", "admin"]) {
  const source = resolve(root, directory);
  try {
    await access(source);
  } catch {
    continue;
  }
  await cp(source, resolve(output, directory), { recursive: true });
}

// Use the same pinned Markdown parser in the editor and on the server; no external CDN.
await cp(resolve(root, "node_modules/marked/lib/marked.umd.js"), resolve(output, "admin/marked.js"));
const codecOutput = resolve(output, "admin/webp-codec");
await mkdir(codecOutput, { recursive: true });
for (const name of ["webp_enc.js", "webp_enc.wasm"]) {
  await cp(resolve(root, "node_modules/@jsquash/webp/codec/enc", name), resolve(codecOutput, name));
}
for (const name of ["meta.js", "LICENSE"]) {
  await cp(resolve(root, "node_modules/@jsquash/webp", name), resolve(codecOutput, name));
}
await cp(resolve(root, "node_modules/@jsquash/webp/codec/LICENSE.codec.md"), resolve(codecOutput, "LICENSE.codec.md"));
console.log("Static site copied to dist/.");
