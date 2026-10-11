import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
assert.equal("private" in manifest, false, "package must not encode a private publication rule");
for (const directory of ["src", "test"]) assert.ok((await readdir(resolve(root, directory))).length > 0, `${directory} must survive a clean copy`);
process.stdout.write("clean-copy layout verified\n");
