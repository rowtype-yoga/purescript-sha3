# purescript-sha3 — phpurs (PHP) backend

SHA-3 (FIPS 202) hash functions and SHAKE XOFs for PureScript, compiled to
native PHP via [phpurs](https://github.com/0x000000000000000000001/phpurs).
Same public API as the other backend branches (`Crypto.SHA3`,
`Crypto.Keccak`); the hot path is a hand-optimized PHP FFI.

## Quick start

```
nix develop
npm install          # installs phpurs (builds itself on install)
run-tests            # spago build + JIT-enabled PHP run
run-bench            # same, with BENCH=1
```

Without the flake: `npm run test` / `npm run bench` (requires purs, spago,
node, and php ≥ 8.0 with 64-bit ints on PATH).

## Performance

Measured on PHP 8.3, SHA3-256, 1 MiB input:

| Mode                          | Throughput |
| ----------------------------- | ---------- |
| Interpreted (`php file.php`)  | ~7.5 MB/s  |
| OPcache + tracing JIT         | ~35–43 MB/s |

JIT flags (what `php-jit` / the npm scripts pass):

```
php -d opcache.enable_cli=1 -d opcache.jit=tracing -d opcache.jit_buffer_size=64M
```

On long-lived FPM/web deployments OPcache is typically already on, so the
JIT numbers are the realistic ones there.

## Design notes (why the FFI looks the way it does)

* **Native 64-bit lanes.** PHP integers are signed 64-bit with well-defined
  wrapping shifts, so each lane is one int — half the ops of the JS
  backend's hi/lo 32-bit split, and none of the Chez branch's explicit
  masking to `[0, 2^64)`. PHP's `>>` is arithmetic (sign-extending), so
  every rotation masks the shifted-in sign bits with a precomputed literal.
* **Fully unrolled permutation over locals.** The 24-round body is unrolled
  across 25 local variables. PHP locals compile to fixed VM slots; array
  reads/writes go through hashtable machinery and are far slower, so the
  round body touches no arrays. The unrolled body was generated
  programmatically from the FIPS 202 rho/pi tables, not hand-transcribed.
* **State crosses the per-block function boundary as a by-ref array.**
  Measured alternative — 25 by-ref scalar parameters — is ~4.5× *slower*
  under the JIT: by-ref parameters force reference-wrapped zvals the JIT
  can't keep in registers. The 50 array ops per 136-byte block are noise
  next to the ~5,000 integer ops of the permutation.
* **pack/unpack for lane I/O.** The whole padded input is decoded with one
  `unpack('P*', ...)` call (little-endian uint64, C speed); squeezing uses
  `pack('P', ...)`. No per-byte PHP loops anywhere.
* **`ByteArray` is a raw PHP binary string.** PHP strings are byte strings,
  so `bytesToHex`/`hexToByteArray`/equality/length are single builtins
  (`bin2hex`, `hex2bin`, `===`, `strlen`).
* **Two's-complement lanes.** A lane with bit 63 set shows as a negative
  Int. Bit-identical for Keccak's XOR/AND/rotate algebra; only visible if
  you print raw `keccakF1600` state.

## Caveats

* Requires 64-bit PHP (`PHP_INT_SIZE === 8`); the FFI throws otherwise.
* `unfoldable` (a transitive dep via `arrays`) has JS FFI and no phpurs
  port yet. Nothing in this library or its tests reaches it, and DCE via
  `--main` drops it, but calling `Data.Unfoldable` functions on this
  backend will fatal at runtime with a null-callable error.
* phpurs is experimental; the `spago.yaml` pins its core-library ports at
  `master` because no tagged releases exist yet. Pin to commit hashes if
  you need reproducibility beyond what `spago.lock` gives you.

## Verification

The PHP core was validated against NIST FIPS 202 vectors: SHA3-224/256/384/
512 for empty, `"abc"`, and multi-block inputs; SHAKE128/256 including
multi-permutation squeezes (512-byte output); the padding edge case where
the domain suffix and final `0x80` share a byte (`len % rate == rate - 1`);
and exact-rate inputs. The PureScript test suite (`Test.SHA3`) carries the
same vectors.
# purescript-sha3 — phpurs (PHP) backend

SHA-3 (FIPS 202) hash functions and SHAKE XOFs for PureScript, compiled to
native PHP via [phpurs](https://github.com/0x000000000000000000001/phpurs).
Same public API as the other backend branches (`Crypto.SHA3`,
`Crypto.Keccak`); the hot path is a hand-optimized PHP FFI.

## Quick start

```
nix develop
npm install          # installs phpurs (builds itself on install)
run-tests            # spago build + JIT-enabled PHP run
run-bench            # same, with BENCH=1
```

Without the flake: `npm run test` / `npm run bench` (requires purs, spago,
node, and php ≥ 8.0 with 64-bit ints on PATH).

## Performance

Measured on PHP 8.3, SHA3-256, 1 MiB input:

| Mode                          | Throughput |
| ----------------------------- | ---------- |
| Interpreted (`php file.php`)  | ~7.5 MB/s  |
| OPcache + tracing JIT         | ~35–43 MB/s |

JIT flags (what `php-jit` / the npm scripts pass):

```
php -d opcache.enable_cli=1 -d opcache.jit=tracing -d opcache.jit_buffer_size=64M
```

On long-lived FPM/web deployments OPcache is typically already on, so the
JIT numbers are the realistic ones there.

## Design notes (why the FFI looks the way it does)

* **Native 64-bit lanes.** PHP integers are signed 64-bit with well-defined
  wrapping shifts, so each lane is one int — half the ops of the JS
  backend's hi/lo 32-bit split, and none of the Chez branch's explicit
  masking to `[0, 2^64)`. PHP's `>>` is arithmetic (sign-extending), so
  every rotation masks the shifted-in sign bits with a precomputed literal.
* **Fully unrolled permutation over locals.** The 24-round body is unrolled
  across 25 local variables. PHP locals compile to fixed VM slots; array
  reads/writes go through hashtable machinery and are far slower, so the
  round body touches no arrays. The unrolled body was generated
  programmatically from the FIPS 202 rho/pi tables, not hand-transcribed.
* **State crosses the per-block function boundary as a by-ref array.**
  Measured alternative — 25 by-ref scalar parameters — is ~4.5× *slower*
  under the JIT: by-ref parameters force reference-wrapped zvals the JIT
  can't keep in registers. The 50 array ops per 136-byte block are noise
  next to the ~5,000 integer ops of the permutation.
* **pack/unpack for lane I/O.** The whole padded input is decoded with one
  `unpack('P*', ...)` call (little-endian uint64, C speed); squeezing uses
  `pack('P', ...)`. No per-byte PHP loops anywhere.
* **`ByteArray` is a raw PHP binary string.** PHP strings are byte strings,
  so `bytesToHex`/`hexToByteArray`/equality/length are single builtins
  (`bin2hex`, `hex2bin`, `===`, `strlen`).
* **Two's-complement lanes.** A lane with bit 63 set shows as a negative
  Int. Bit-identical for Keccak's XOR/AND/rotate algebra; only visible if
  you print raw `keccakF1600` state.

## Caveats

* Requires 64-bit PHP (`PHP_INT_SIZE === 8`); the FFI throws otherwise.
* Missing foreigns are **not** dead-code-eliminated: phpurs compiles
  every module in the closure and maps absent FFI members to null
  globals, which throw `Unknown thunk` on first call. Two known gaps:
  `unfoldable` (via `arrays`) has JS FFI and no phpurs port, and
  upstream `phpurs-functions` ships only `runFn2`/`runFn3`. The
  `functions` override in `spago.yaml` therefore points at a fork with
  a complete `Data.Function.Uncurried` FFI (`arrays` needs `runFn4`
  and `runFn5`); nothing here reaches `Data.Unfoldable`.
* phpurs is experimental; the `spago.yaml` pins its core-library ports at
  `master` because no tagged releases exist yet. Pin to commit hashes if
  you need reproducibility beyond what `spago.lock` gives you.

## Known upstream issues

* phpurs codegen emits `continue` inside `switch` blocks (PHP treats
  that as `break` and warns). For the code paths exercised here the
  behaviors coincide — the NIST vectors passing is the empirical
  evidence — but it is one refactor away from a silent miscompile and
  deserves an upstream issue (`continue 2` is what the codegen means).
  Do not suppress the warnings; they are the only visibility into it.
* Several phpurs-* ports have copy-paste bugs in their
  partial-application fallbacks (e.g. `phpurs-arrays` `indexImpl`
  captures `&$unconsImpl`, `findMapImpl` captures `&$indexImpl`).
  Dormant unless those foreigns are partially applied. PR fodder.

## Verification

The PHP core was validated against NIST FIPS 202 vectors: SHA3-224/256/384/
512 for empty, `"abc"`, and multi-block inputs; SHAKE128/256 including
multi-permutation squeezes (512-byte output); the padding edge case where
the domain suffix and final `0x80` share a byte (`len % rate == rate - 1`);
and exact-rate inputs. The PureScript test suite (`Test.SHA3`) carries the
same vectors.