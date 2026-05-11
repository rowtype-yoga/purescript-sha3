# purescript-sha3

SHA-3 (FIPS 202) cryptographic hash functions and extendable-output functions for PureScript, with optimized native FFI for both the **JavaScript** (Node.js) and **Chez Scheme** ([purescm](https://github.com/purescm/purescm)) backends.

Verified against NIST test vectors on both backends. 



### Features

- SHA3-224, SHA3-256, SHA3-384, SHA3-512 hash functions
- SHAKE128, SHAKE256 extendable-output functions (XOFs)
- `Hashable` typeclass for `String` and `Buffer`/`Array Int` inputs
- `Digest` newtype with `Eq` and `Show` instances
- Hex encoding/decoding
- Fully unrolled Keccak-f[1600] permutation in both JS and Scheme FFI
- **50 MB/s** SHA3-256 throughput on Chez Scheme, **28 MB/s** on Node.js



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



### Performance

SHA3-256 throughput on 1 MiB input (higher is better):

| Implementation | MB/s |
|---|---|
| **Chez Scheme FFI (this library)** | **50.4** |
| js-sha3 (reference JS, fully unrolled) | ~48 |
| **Node.js FFI (this library)** | **28.1** |
| noble/hashes (JS, loop-based) | ~18 |
| Pure PureScript (no FFI) | 0.14 |

The Chez backend achieves this through fixnum-only 32-bit pair arithmetic
(avoiding Chez's bignum allocation for values exceeding 2^60), a fully
unrolled permutation with all 25 ρ+π rotations and χ outputs expanded
as straight-line code, and `(optimize-level 3)` for maximum compiler
inlining. The JS backend uses a similar fully unrolled permutation with
Buffer-native sponge I/O.



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
the `*.purs` modules work unchanged across backends.



### References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA-3 Standard
- [Errata](https://csrc.nist.gov/publications/detail/fips/202/final) — Algorithm 10 Step 1 correction (`0 ≤ i < 2m`)