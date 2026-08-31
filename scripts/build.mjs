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

console.log("Static site copied to dist/.");
