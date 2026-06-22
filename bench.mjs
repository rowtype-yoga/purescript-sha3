import { exports as wasm } from "./output-bench/index.mjs";
import { performance } from "node:perf_hooks";

// Warm up so V8 tiers up the wasm before any measurement.
for (let i = 0; i < 200; i++) wasm.hashOnceV(256, 256, i);

let sink = 0; // keep the wasm calls observably live; printed to stderr at the end

function bench(label, variant, n, iters) {
  let acc = 0;
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) acc += wasm.hashOnceV(variant, n, i);
  const ms = performance.now() - t0;
  sink ^= acc;
  const secs = ms / 1000;
  const ops = iters / secs;
  const mbs = (iters * n) / 1048576 / secs;
  console.log(
    "  " + label.padEnd(12) +
    String(iters).padStart(4) + " iters  " +
    ms.toFixed(3).padStart(10) + " ms  " +
    ops.toFixed(0).padStart(8) + " ops/s  " +
    mbs.toFixed(4).padStart(9) + " MB/s"
  );
}

function section(title) {
  const width = 56;
  console.log("\n── " + title + " " + "─".repeat(Math.max(0, width - 4 - title.length)));
}

console.log("═".repeat(59));
console.log("  SHA-3 Benchmarks (WasmGC backend, JS-side timing)");
console.log("═".repeat(59));

section("SHA3-256 (small inputs)");
bench("32 B",        256, 32,  500);
bench("64 B",        256, 64,  500);
bench("136 B (1×r)", 256, 136, 500);

section("SHA3-256 (multi-block)");
bench("512 B", 256, 512,  200);
bench("1 KiB", 256, 1024, 100);
bench("4 KiB", 256, 4096, 30);

section("SHA3-256 (large inputs)");
bench("64 KiB", 256, 65536,   5);
bench("1 MiB",  256, 1048576, 2);

section("SHA3 variants (256 B input)");
bench("SHA3-224", 224, 256, 200);
bench("SHA3-256", 256, 256, 200);
bench("SHA3-384", 384, 256, 200);
bench("SHA3-512", 512, 256, 200);

console.error("checksum:", sink >>> 0);