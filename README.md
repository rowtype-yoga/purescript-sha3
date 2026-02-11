# SHA-3 for PureScript — Chez Scheme Backend

A PureScript implementation of SHA-3 (FIPS 202) targeting the
[purescm](https://github.com/purescm/purescm) Chez Scheme backend,
with a heavily optimized Scheme FFI that achieves **50 MB/s** SHA3-256
throughput — faster than js-sha3 on the same hardware.

## Why a Chez Backend?

The JavaScript backend limits PureScript's `Int` to 32-bit signed range
`[-2^31, 2^31-1]`. Keccak-f[1600] operates on 25 × **64-bit** lanes,
so the JS version splits every lane into `{ hi :: Int, lo :: Int }` pairs
and threads two-halves arithmetic through every operation.

On Chez Scheme, integers are arbitrary-precision with hardware fixnums
up to 61 bits. The PureScript interface exposes single-integer lanes:

```purescript
type Word64 = Int

foreign import w64xor  :: Word64 -> Word64 -> Word64
foreign import w64rotL :: Word64 -> Int -> Word64
```

However, the **performance-critical FFI** (Keccak.ss) goes further —
it splits each 64-bit lane into two 32-bit halves internally to keep
all values within Chez's fixnum range (`< 2^60`), avoiding bignum heap
allocation entirely in the hot path.

## Optimization Strategy

The initial naive port (single 64-bit integers per lane) achieved only
0.53 MB/s due to bignum allocation on every bitwise operation. Four
rounds of optimization brought this to **50.4 MB/s** — a **360×**
improvement over pure PureScript:

| Version | SHA3-256 1 MiB | keccakF1600 ops/s | vs baseline |
|---|---|---|---|
| Pure PureScript | 0.14 MB/s | 1,137 | 1× |
| Naive 64-bit FFI | 0.53 MB/s | 4,395 | 3.8× |
| 32-bit fixnum pairs | 2.7 MB/s | 20,934 | 19× |
| + `(optimize-level 3)` | 13.7 MB/s | 99,972 | 98× |
| **Fully unrolled** | **50.4 MB/s** | **405,814** | **360×** |

For comparison against JS implementations on the same machine:

| Implementation | SHA3-256 1 MiB |
|---|---|
| **Chez Scheme FFI (this library)** | **50.4 MB/s** |
| js-sha3 (fully unrolled JS) | ~48 MB/s |
| Node.js FFI (this library) | 28.1 MB/s |
| noble/hashes (loop-based JS) | ~18 MB/s |

### Key Techniques

- **Fixnum-only arithmetic**: Each 64-bit lane stored as two 32-bit
  halves in a `vector(50)`. All operations use `fxlogxor`, `fxlogand`,
  `fxsrl`, and a safe `sll32` macro that pre-masks inputs to prevent
  fixnum overflow. Zero heap allocation in the permutation hot path.

- **Fully unrolled permutation**: All 25 ρ+π rotations and 25 χ outputs
  are expanded as straight-line code with hardcoded shift amounts.
  No inner loops, no scratch vectors — all intermediates are `let*`
  locals (stack/register allocated).

- **`(optimize-level 3)`**: Maximum Chez compiler optimization —
  aggressive inlining, constant folding, and unsafe arithmetic.

- **Bytevector I/O**: The sponge absorb/squeeze phases operate on
  native bytevectors, converting to/from flexvectors only at the
  PureScript boundary.

## Architecture

```
src/
  Crypto/
    SHA3.purs          -- Public API (Hashable, Digest, SHA3 variants, SHAKE)
    SHA3.ss            -- Chez FFI: stringToUtf8, bytesToHex, hexToBytes
    Keccak.purs        -- Sponge construction + Keccak-f[1600] (PureScript interface)
    Keccak.ss          -- Chez FFI: unrolled permutation + bytevector sponge
    Word64.purs        -- Word64 type + operations (PureScript interface)
    Word64.ss          -- Chez FFI: w64xor, w64and, w64rotL, etc.
test/
  Test/
    Main.purs          -- Entry point (tests, optional benchmarks)
    Main.ss            -- Chez FFI: BENCH env var check
    SHA3.purs          -- NIST test vectors
    SHA3/
      Bench.purs       -- Throughput benchmarks
      Bench.ss         -- Chez FFI: performanceNow, defer, intToNumber
```

`Keccak.purs` delegates to optimized FFI functions (`spongeOptimized`,
`keccakF1600Optimized`) when available, falling back to the pure
PureScript implementation otherwise. The `Word64` module is used by
the pure PureScript path; the optimized Keccak.ss bypasses it entirely.

## Building

Requires [purescm](https://github.com/purescm/purescm) and Chez Scheme.

```bash
spago build
purescm run --main Test.Main            # tests only
BENCH=1 purescm run --main Test.Main    # tests + benchmarks
```

## Test Vectors

All test vectors are from NIST FIPS 202 and match the JS backend exactly:
SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, multi-block inputs.

## Notes on Chez Scheme's Integer Model

- **Fixnums**: On 64-bit Chez, fixnums cover `[-2^60, 2^60-1]` (61 bits,
  3 tag bits). The optimized FFI keeps all values within 32 bits to
  guarantee fixnum-only operation.
- **Bignums**: Values exceeding fixnum range (like round constants with
  bit 63 set) promote to bignums transparently. The unoptimized path
  (`Word64.ss`) uses bignums; the optimized `Keccak.ss` avoids them
  by splitting lanes into 32-bit hi/lo pairs and storing round constants
  as pre-split 32-bit vectors.
- **Safe shifts**: `fxsll` raises an exception if the result exceeds
  fixnum range. The `sll32` macro pre-masks input bits to guarantee
  the shifted result stays within 32 bits:
  ```scheme
  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (fxsll (fxlogand x (fxsrl #xFFFFFFFF n)) n)]))
  ```

## FFI Conventions

Each `.ss` file uses the purescm library convention:

```scheme
(library (Crypto.Keccak foreign)
  (export spongeOptimized keccakF1600Optimized ...)
  (import (chezscheme) (srfi :214))
  ...)
```

The library name is `(<ModuleName> foreign)` where `<ModuleName>` matches
the PureScript module name. All functions must be curried (nested lambdas)
to match PureScript's calling convention. PureScript `Array` maps to
SRFI 214 flexvectors in purescm.

## References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA-3 Standard
- [Errata](https://csrc.nist.gov/publications/detail/fips/202/final) — Algorithm 10 Step 1 correction (`0 ≤ i < 2m`)