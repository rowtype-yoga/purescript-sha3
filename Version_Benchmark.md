═══════════════════════════════════════════════════════════
  SHA-3 Benchmarks (WasmGC backend, JS-side timing)
═══════════════════════════════════════════════════════════

── SHA3-256 (small inputs) ─────────────────────────────
  32 B         500 iters      36.698 ms     13625 ops/s     0.4158 MB/s
  64 B         500 iters      37.296 ms     13406 ops/s     0.8182 MB/s
  136 B (1×r)  500 iters      72.490 ms      6897 ops/s     0.8946 MB/s

── SHA3-256 (multi-block) ──────────────────────────────
  512 B        200 iters      60.659 ms      3297 ops/s     1.6099 MB/s
  1 KiB        100 iters      54.165 ms      1846 ops/s     1.8029 MB/s
  4 KiB         30 iters      64.105 ms       468 ops/s     1.8281 MB/s

── SHA3-256 (large inputs) ─────────────────────────────
  64 KiB         5 iters     166.131 ms        30 ops/s     1.8810 MB/s
  1 MiB          2 iters    1183.512 ms         2 ops/s     1.6899 MB/s

── SHA3 variants (256 B input) ─────────────────────────
  SHA3-224     200 iters      32.760 ms      6105 ops/s     1.4905 MB/s
  SHA3-256     200 iters      32.098 ms      6231 ops/s     1.5212 MB/s
  SHA3-384     200 iters      48.703 ms      4107 ops/s     1.0026 MB/s
  SHA3-512     200 iters      57.629 ms      3470 ops/s     0.8473 MB/s