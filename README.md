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
- **50 MB/s** SHA3-256 throughput on Chez Scheme, **28 MB/s** on Node.js
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
over `wasm-base`'s `Wasm.Array` / `Wasm.String` primitives, `Data.Int.Bits`, and native
`Wasm.Int64` operations for the 64-bit Keccak lanes. The only host calls are the optional Node
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
compiled module, the same measurement style as the Node figure):

| Input | MB/s |
|---|---|
| 32 B   | 0.43 |
| 512 B  | 1.52 |
| 64 KiB | 1.88 |
| 1 MiB  | 1.83 |

Throughput ramps with input size (small inputs are dominated by per-call and allocation overhead)
and plateaus near **~1.8 MB/s** for SHA3-256. Rewriting the 64-bit Keccak lanes to use native
`Wasm.Int64` (`i64.rotl` and friends) in place of the earlier emulated i32-pair arithmetic roughly
doubled throughput, up from ~0.96 MB/s. That puts it at roughly **13× the pure-PureScript-on-JS**
figure (0.14 MB/s), but still **15× to 28× below the native FFI backends**. The remaining gap is
the cost of experimental WasmGC under V8 together with the still-boxed lane array: each Keccak lane
lives in a boxed `Array Int64`, so the permutation allocates on every round. An unboxed packed-i64
array would close more of it. The value of this backend is **correctness and a zero-FFI / zero-npm
dependency graph**, not raw speed.

**Build.** Requires the patched `purs-wasm` fork (it carries the `Data.Int.Bits` wasm intrinsics,
native `Wasm.Int64` support, and a codegen fix for discarded `Effect` performs of non-foreign
functions). Roughly:

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
| noble/hashes (JS, loop-based) | ~18 |
| **Pure PureScript → WasmGC (this library, purs-wasm)** | **~1.83** |
| Pure PureScript (no FFI) | 0.14 |

The Chez backend achieves its throughput through fixnum-only 32-bit pair arithmetic
(avoiding Chez's bignum allocation for values exceeding 2^60), a fully
unrolled permutation with all 25 ρ+π rotations and χ outputs expanded
as straight-line code, and `(optimize-level 3)` for maximum compiler
inlining. The JS backend uses a similar fully unrolled permutation with
Buffer-native sponge I/O.

The WasmGC figure is the experimental pure-PureScript backend (see
[above](#webassembly-gc-backend-experimental)); it is measured on the development machine and
the FFI figures are from the original benchmarks, so the cross-backend comparison is approximate.



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
native `Wasm.Int64`), so there are no `.js` / `.ss` companions. The whole permutation and sponge
compile straight to WasmGC. It exposes the `Bytes`-based subset API described above.



### References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): SHA-3 Standard
- [Errata](https://csrc.nist.gov/publications/detail/fips/202/final): Algorithm 10 Step 1 correction (`0 ≤ i < 2m`)