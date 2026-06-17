// copy-foreigns.mjs — copy the JS foreign providers that purs-wasm references
// in index.mjs but doesn't emit under -E -e. Reads the real import list out of
// the built wasm, then sources each provider from src/ (your FFI) or .spago
// (dependency FFI), writing it under the flat dotted name the loader expects.
//
//   node copy-foreigns.mjs [outDir=output-bench]

import { readFileSync, copyFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";

const outDir = process.argv[2] ?? "output-bench";

const mod = await WebAssembly.compile(readFileSync(`${outDir}/index.wasm`));
const modules = [...new Set(WebAssembly.Module.imports(mod).map((i) => i.module))];

mkdirSync(`${outDir}/foreign`, { recursive: true });

const find = (pattern) => {
  try {
    return (
      execSync(`find . -path '${pattern}' 2>/dev/null | head -1`).toString().trim() || null
    );
  } catch {
    return null;
  }
};

let missing = 0;
for (const m of modules) {
  const rel = m.replaceAll(".", "/") + ".js"; // Data.Int.Bits -> Data/Int/Bits.js
  const src =
    find(`./src/${m}.js`) ??          // flat user FFI:   src/Bench.js
    find(`./src/${rel}`) ??           // nested user FFI: src/Crypto/SHA3.js
    find(`./.spago/p/*/src/${rel}`);  // dependency FFI in the package set
  if (src) {
    copyFileSync(src, `${outDir}/foreign/${m}.js`);
    console.log(`  ${m}  <-  ${src}`);
  } else {
    console.error(`  MISSING: ${m}  (no src/${rel} or .spago/.../${rel})`);
    missing++;
  }
}

console.log(
  missing
    ? `\n${missing} provider(s) missing — see above.`
    : `\nAll ${modules.length} foreign provider(s) copied.`
);