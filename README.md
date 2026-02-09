# purescript-sha3

Pure PureScript implementation of SHA-3 (FIPS 202) cryptographic hash functions and extendable-output functions.

No native dependencies — the full Keccak-f[1600] permutation and sponge construction are implemented in PureScript, verified against NIST test vectors.



### Features

- SHA3-224, SHA3-256, SHA3-384, SHA3-512 hash functions
- SHAKE128, SHAKE256 extendable-output functions (XOFs)
- `Hashable` typeclass for `String` and `Buffer` inputs
- `Digest` newtype with `Eq` and `Show` instances
- Hex encoding/decoding



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
```



### Examples


##### Hash a string

```haskell
import Crypto.SHA3 (SHA3(..), hash, toString)

toString (hash SHA3_256 "purescript ftw")
-- "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```


##### Hash a Buffer

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
import Node.Buffer as Buffer

main = do
  msg <- Buffer.fromString "some input" Buffer.UTF8
  let out = shake256 64 msg  -- 64 bytes of output
  log (bufferToHex out)
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


##### Export digest to Buffer

```haskell
import Crypto.SHA3 (SHA3(..), hash, exportToBuffer)
import Node.FS.Sync (writeFile)

main = do
  let digest = hash SHA3_512 "important data"
  writeFile "digest.bin" (exportToBuffer digest)
```



### API

| Function | Type | Description |
|---|---|---|
| `hash` | `SHA3 -> a -> Digest` | Hash any `Hashable` (String or Buffer) |
| `sha3_224` | `Buffer -> Digest` | SHA3-224 (28 bytes) |
| `sha3_256` | `Buffer -> Digest` | SHA3-256 (32 bytes) |
| `sha3_384` | `Buffer -> Digest` | SHA3-384 (48 bytes) |
| `sha3_512` | `Buffer -> Digest` | SHA3-512 (64 bytes) |
| `shake128` | `Int -> Buffer -> Buffer` | SHAKE128 XOF, variable output |
| `shake256` | `Int -> Buffer -> Buffer` | SHAKE256 XOF, variable output |
| `toString` | `Digest -> String` | Hex-encode a digest |
| `fromHex` | `String -> Maybe Digest` | Decode hex to a digest |
| `exportToBuffer` | `Digest -> Buffer` | Extract raw Buffer |
| `importFromBuffer` | `Buffer -> Maybe Digest` | Wrap a Buffer as a Digest |



### Running tests

```bash
nix develop
spago test
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



### References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA-3 Standard
- [Errata](https://csrc.nist.gov/publications/detail/fips/202/final) — Algorithm 10 Step 1 correction (`0 ≤ i < 2m`)