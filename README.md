# purescript-sha3

SHA-3 (FIPS 202) cryptographic hash functions and extendable-output functions for PureScript, with optimized native FFI for the **JavaScript** (Node.js) and **Chez Scheme** ([purescm](https://github.com/purescm/purescm)) backends, plus an experimental, FFI-free **WebAssembly (GC)** backend.

Verified against NIST test vectors on all three backends (the WebAssembly backend currently covers the four fixed-length variants, see [WebAssembly (GC) backend](#webassembly-gc-backend-experimental)).



### Features

- SHA3-224, SHA3-256, SHA3-384, SHA3-512 hash functions
- SHAKE128, SHAKE256 extendable-output functions (XOFs)
- `Hashable` typeclass for `String` and `Buffer`/`Array Int` inputs
- `Digest` newtype with `Eq` and `Show` instances
- Hex encoding/decoding
- Fully unrolled Keccak-f[1600] permutation in both JS and Scheme FFI
- **60 MB/s** SHA3-256 throughput on Chez Scheme, **28 MB/s** on Node.js, **~22 MB/s** on the experimental WasmGC backend (pure PureScript, no FFI or npm)
- Experimental **WebAssembly (GC)** backend: the same algorithm in pure PureScript, with **no FFI and no npm** in the dependency graph



### Install

Add to your `spago.yaml` dependencies:

```yaml
workspace:
  extra_packages:
    sha3:
      git: https://github.com/rowtype-yoga/purescript-sha3.git
      ref: main
      subdir: null

package:
  dependencies:
    - sha3
```

##### Nix

A flake is provided for development:

```bash
nix develop
spago build
spago test            # tests only
spago test -- --bench # tests + benchmarks
```



### Examples


##### Hash a string

```haskell
import Crypto.SHA3 (SHA3(..), hash, toString)

toString (hash SHA3_256 "purescript ftw")
-- "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```


##### Hash a Buffer (JS backend)

```haskell
import Crypto.SHA3 (sha3_256, toString)
import Node.Buffer as Buffer

main = do
  buf <- Buffer.fromArray [0xDE, 0xAD, 0xBE, 0xEF]
  log (toString (sha3_256 buf))
```


##### Compare digests

```haskell
import Crypto.SHA3 (SHA3(..), hash)

sameDigest = hash SHA3_256 "hello" == hash SHA3_256 "hello"
-- true

differentDigest = hash SHA3_256 "hello" == hash SHA3_256 "world"
-- false
```


##### SHAKE128/SHAKE256 (variable-length output)

```haskell
import Crypto.SHA3 (shake128, shake256)

-- JS backend (Buffer)
import Node.Buffer as Buffer
main = do
  msg <- Buffer.fromString "some input" Buffer.UTF8
  let out = shake256 64 msg  -- 64 bytes of output
  log (bufferToHex out)

-- Chez backend (Array Int)
let out = shake256 64 [0x73, 0x6F, 0x6D, 0x65]
```


##### Hex decoding

```haskell
import Crypto.SHA3 (SHA3(..), hash, toString, fromHex)

main = do
  let digest = hash SHA3_256 "hello"
  let hex    = toString digest
  let round  = fromHex hex  -- Just (Digest ...)
  log (show (map toString round))
```



### API

| Function | Type | Description |
|---|---|---|
| `hash` | `SHA3 -> a -> Digest` | Hash any `Hashable` (String, Buffer, or Array Int) |
| `sha3_224` | input `-> Digest` | SHA3-224 (28 bytes) |
| `sha3_256` | input `-> Digest` | SHA3-256 (32 bytes) |
| `sha3_384` | input `-> Digest` | SHA3-384 (48 bytes) |
| `sha3_512` | input `-> Digest` | SHA3-512 (64 bytes) |
| `shake128` | `Int ->` input `-> Array Int` | SHAKE128 XOF, variable output |
| `shake256` | `Int ->` input `-> Array Int` | SHAKE256 XOF, variable output |
| `toString` | `Digest -> String` | Hex-encode a digest |
| `fromHex` | `String -> Maybe Digest` | Decode hex to a digest |

On the JS backend, `input` is `Buffer`; on the Chez backend, `input` is `Array Int`.
The WebAssembly backend exposes a smaller, `Bytes`-based surface, see below.



### Running tests

##### JavaScript (Node.js)

```bash
spago test            # tests only
spago test -- --bench # tests + benchmarks
```

##### Chez Scheme (purescm)

```bash
purescm run --main Test.Main            # tests only
BENCH=1 purescm run --main Test.Main    # tests + benchmarks
```

```
SHA-3 (FIPS 202) Test Suite

  ✓ SHA3-224("")
  ✓ SHA3-224("abc")
  ✓ SHA3-256("")
  ✓ SHA3-256("abc")
  ✓ SHA3-256(multi-block)
  ✓ SHA3-384("")
  ✓ SHA3-384("abc")
  ✓ SHA3-512("")
  ✓ SHA3-512("abc")
  ✓ SHAKE128("", 32)
  ✓ SHAKE256("", 64)
  ✓ SHA3-256(200 × 0xA3)
  ✓ Digest Eq (same input)
  ✓ Digest Eq (different input)
  ✓ fromHex roundtrip

15 passed, 0 failed
```



### WebAssembly (GC) backend (experimental)

A third backend compiles the **pure-PureScript** implementation to a single WebAssembly-GC
module via the [purs-wasm](https://github.com/purs-wasm) compiler backend (using the
[`harryprayiv/purescript-backend-wasm`](https://github.com/harryprayiv/purescript-backend-wasm)
fork). Unlike the JS and Chez backends there is **no FFI and no npm in the dependency graph**.
The Keccak-f[1600] permutation, sponge, padding, and hex encoding are all written in PureScript
over `wasm-base`'s `Wasm.Array` / `Wasm.String` primitives, `Data.Int.Bits`, native
`Wasm.Int64` operations for the 64-bit Keccak lanes, and an unboxed packed `Wasm.Int64Array`
(`(array (mut i64))`) for the 25-lane permutation state. The only host calls are the optional Node
console/clock glue, which use Node builtins.

This backend lives on the `wasm` branch and is **experimental**: it tracks the in-development
WasmGC proposal and is run under Node with `--experimental-wasm-custom-descriptors`.

**API (subset).** The WebAssembly backend currently exposes only the four fixed-length hashes
over a `Bytes` newtype:

```purescript
module Crypto.SHA3
  ( Bytes(..)
  , sha3_224, sha3_256, sha3_384, sha3_512
  , fromUtf8, unBytes, toHex
  ) where
```

```haskell
import Crypto.SHA3 (fromUtf8, sha3_256, toHex)

toHex (sha3_256 (fromUtf8 "abc"))
-- "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```

`Bytes` is a zero-cost newtype over `String` (on wasm a `String` is already a packed UTF-8 byte
buffer). SHAKE, the `Digest` / `Hashable` typeclass sugar, and `fromHex` are **not yet ported**:
SHAKE needs a multi-block squeeze loop and the rest is presentation API, both tracked as
follow-ups.

**Validation.** All four fixed-length variants pass their NIST vectors on the WebAssembly
backend, including the multi-block and 200×0xA3 cases, byte-for-byte identical to the JS and
Chez backends.

**Performance.** Measured on the WasmGC backend via JS-side timing (a JS loop calling into the
compiled module, the same measurement style as the Node figure, so WasmGC vs Node is apples to
apples; the Chez figure uses a different harness and is approximate):

| Input        | MB/s  |
|---|---|
| 32 B         |  3.44 |
| 64 B         |  5.57 |
| 136 B (1×r)  |  8.15 |
| 512 B        | 15.14 |
| 1 KiB        | 14.68 |
| 4 KiB        | 15.17 |
| 64 KiB       | 17.09 |
| 1 MiB        | 22.06 |

Throughput ramps with input size (small inputs are still dominated by per-call overhead) and
plateaus around **15–22 MB/s** for SHA3-256, reaching **22.06 MB/s** on 1 MiB. That is roughly
**158× the pure-PureScript-on-JS** baseline (0.14 MB/s), about **1.2× faster than loop-based JS**
(noble/hashes, ~18 MB/s), within **~1.3× of the Node.js FFI** backend (28.1 MB/s), and about
**a third of Chez Scheme's** throughput (60.64 MB/s).

The jump from the previous **~1.8 MB/s** came from moving the 25-lane Keccak state off a boxed
`Array Int64` and onto an unboxed packed `Wasm.Int64Array` (`(array (mut i64))`). Each lane is now
a raw `i64` slot, so `getLane` / `setLane` is a single `array.get` / `array.set` with no
`struct.new`, and the permutation no longer allocates per round. That is a ~12× gain on top of the
earlier switch to native `Wasm.Int64` ops (`i64.rotl` and friends), which had itself doubled
throughput from ~0.96 to ~1.8 MB/s, so cumulatively ~150× over the original emulated i32-pair
arithmetic. The remaining gap to the FFI backends is the cost of experimental WasmGC under V8: the
per-access `ref.cast` on the array handle and the array bounds checks a linear-memory
implementation would not pay. The value of this backend is a **zero-FFI / zero-npm dependency
graph** and correctness, and it is now also competitive on throughput rather than an order of
magnitude behind.

Per-variant throughput on a 256 B input (small-input regime, so per-call overhead dominates):

| Variant   | MB/s  |
|---|---|
| SHA3-224  | 19.67 |
| SHA3-256  | 13.37 |
| SHA3-384  |  9.12 |
| SHA3-512  |  9.45 |

The spread tracks rate: SHA3-384 (104-byte rate) and SHA3-512 (72-byte rate) need 3 and 4
permutations for a 256 B message versus 2 for SHA3-224/256, so they are correspondingly slower per
byte. At this input size the run is only a few milliseconds, so the 224-vs-256 ordering is within
measurement noise; the 1 MiB figure above is the stable headline number.

**Build.** Requires the patched `purs-wasm` fork (it carries the `Data.Int.Bits` wasm intrinsics,
native `Wasm.Int64` support, packed unboxed numeric arrays (`Wasm.Int64Array` / `Wasm.I32Array` /
`Wasm.F64Array`), and a codegen fix for discarded `Effect` performs of non-foreign functions).
Roughly:

```bash
spago build                                                        # emits corefn
purs-wasm build -p node -E -e Main -O output-wasm                  # -> single WasmGC module
node --experimental-wasm-custom-descriptors output-wasm/index.mjs  # runs the NIST vectors
```

Note: under the `-E -e` path purs-wasm emits foreign *import references* into `index.mjs` but not
the provider `.js` files, so a small post-build step copies each referenced provider from
`.spago` / `src` into `output-wasm/foreign/` before running.



### Performance

SHA3-256 throughput on 1 MiB input (higher is better):

| Implementation | MB/s |
|---|---|
| **Chez Scheme FFI (this library)** | **60.64** |
| js-sha3 (reference JS, fully unrolled) | ~48 |
| **Node.js FFI (this library)** | **28.1** |
| **Pure PureScript → WasmGC (this library, purs-wasm)** | **22.06** |
| noble/hashes (JS, loop-based) | ~18 |
| Pure PureScript (no FFI) | 0.14 |

The Chez backend achieves its throughput through fixnum-only 32-bit pair arithmetic
(avoiding Chez's bignum allocation for values exceeding 2^60), a fully
unrolled permutation with all 25 ρ+π rotations and χ outputs expanded
as straight-line code, and `(optimize-level 3)` for maximum compiler
inlining. The JS backend uses a similar fully unrolled permutation with
Buffer-native sponge I/O.

The WasmGC figure is the experimental pure-PureScript backend (see
[above](#webassembly-gc-backend-experimental)). With the unboxed packed-`i64` lane state it now
lands between the Node.js FFI backend and loop-based JS libraries despite carrying no FFI or npm.
It is measured on the development machine while the FFI figures are from the original benchmarks
(and the Chez figure uses a different harness), so the cross-backend comparison is approximate; the
WasmGC and Node figures share the same JS-side timing method and are the most directly comparable
pair.



### Architecture

```
src/
  Crypto/
    SHA3.purs          -- Public API (Hashable, Digest, SHA3 variants, SHAKE)
    SHA3.js            -- JS FFI: bufferToHex, bufferFromHex, stringToUtf8Buffer
    SHA3.ss            -- Chez FFI: stringToUtf8, bytesToHex, hexToBytes
    Keccak.purs        -- Sponge construction + Keccak-f[1600] (PureScript interface)
    Keccak.js          -- JS FFI: fully unrolled permutation, Buffer-native sponge
    Keccak.ss          -- Chez FFI: fixnum-only unrolled permutation, bytevector sponge
    Word64.purs        -- Word64 operations (Chez backend)
    Word64.ss          -- Chez FFI: w64xor, w64and, w64rotL, etc.
```

Each backend's `.js` or `.ss` file implements the same PureScript interface, so
the `*.purs` modules work unchanged across the JS and Chez backends.

The experimental **WebAssembly (GC)** backend lives on the `wasm` branch and takes a different
shape: instead of per-backend FFI, `Crypto.Keccak` and `Crypto.SHA3` are rewritten as
**pure PureScript** over `wasm-base` primitives (`Wasm.Array` / `Wasm.String`, `Data.Int.Bits`,
native `Wasm.Int64`, and an unboxed packed `Wasm.Int64Array` for the 25-lane permutation state),
so there are no `.js` / `.ss` companions. The whole permutation and sponge compile straight to
WasmGC. It exposes the `Bytes`-based subset API described above.



### References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): SHA-3 Standard
- [Errata](https://csrc.nist.gov/publications/detail/fips/202/final): Algorithm 10 Step 1 correction (`0 ≤ i < 2m`)