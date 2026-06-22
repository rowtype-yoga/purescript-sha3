import { exports } from "./output-bench/index.mjs";
import { performance } from "node:perf_hooks";

// Warm up so V8 tiers up the wasm before any measurement.
for (let i = 0; i < 200; i++) exports.hashOnceV(256, 256, i);

function bench(label, variant, n, iters) {
  let acc = 0;
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) acc += exports.hashOnceV(variant, n, i);
  const ms = performance.now() - t0;
  const secs = ms / 1000;
  const ops = iters / secs;
  const mbs = (iters * n) / 1048576 / secs;
  console.log(
    `  ${label}\t${iters} it\t${ms.toFixed(3)} ms\t` +
      `${ops.toFixed(0)} ops/s\t${mbs.toFixed(4)} MB/s\t[acc ${acc}]`
  );
}

console.log("SHA-3 benchmarks (wasm backend, JS-side timing)\n");
console.log("-- SHA3-256 size sweep --");
bench("32 B",   256, 32,      500);
bench("64 B",   256, 64,      500);
bench("136 B",  256, 136,     500);
bench("512 B",  256, 512,     200);
bench("1 KiB",  256, 1024,    100);
bench("4 KiB",  256, 4096,    30);
bench("64 KiB", 256, 65536,   5);
bench("1 MiB",  256, 1048576, 2);
console.log("\n-- variants (256 B) --");
bench("SHA3-224", 224, 256, 200);
bench("SHA3-256", 256, 256, 200);
bench("SHA3-384", 384, 256, 200);
bench("SHA3-512", 512, 256, 200);
