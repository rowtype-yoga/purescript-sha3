═══════════════════════════════════════════════════════════
  SHA-3 Benchmarks (WasmGC backend, JS-side timing)
═══════════════════════════════════════════════════════════

── SHA3-256 (small inputs) ─────────────────────────────
  32 B         500 iters       4.442 ms    112566 ops/s     3.4352 MB/s
  64 B         500 iters       5.481 ms     91224 ops/s     5.5679 MB/s
  136 B (1×r)  500 iters       7.954 ms     62861 ops/s     8.1531 MB/s

── SHA3-256 (multi-block) ──────────────────────────────
  512 B        200 iters       6.449 ms     31015 ops/s    15.1438 MB/s
  1 KiB        100 iters       6.654 ms     15028 ops/s    14.6762 MB/s
  4 KiB         30 iters       7.727 ms      3882 ops/s    15.1656 MB/s

── SHA3-256 (large inputs) ─────────────────────────────
  64 KiB         5 iters      18.284 ms       273 ops/s    17.0912 MB/s
  1 MiB          2 iters      90.675 ms        22 ops/s    22.0568 MB/s

── SHA3 variants (256 B input) ─────────────────────────
  SHA3-224     200 iters       2.483 ms     80564 ops/s    19.6689 MB/s
  SHA3-256     200 iters       3.651 ms     54780 ops/s    13.3740 MB/s
  SHA3-384     200 iters       5.354 ms     37354 ops/s     9.1196 MB/s
  SHA3-512     200 iters       5.166 ms     38714 ops/s     9.4516 MB/s