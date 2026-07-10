# purescript-sha3 (purerl + NIF branch)

SHA-3 (FIPS 202) hash functions and extendable-output functions for PureScript on the **Erlang/OTP** backend via [purerl](https://github.com/purerl/purerl), with the Keccak permutation implemented as a **C NIF** running on BEAM dirty schedulers.

Verified against NIST test vectors at both the Erlang level and the PureScript level, and cross-checked against OTP's `crypto:hash` (OpenSSL) as an independent oracle.

This branch exists as part of a cross-backend comparison. The pure-PureScript, JavaScript, Chez Scheme, and WASM implementations live on their own branches.


### Design

The BEAM has no mutable arrays and boxes integers above 60 bits, which makes it a poor host for a tight bitwise permutation. The idiomatic BEAM answer to CPU-bound inner loops is a NIF, so this branch takes that path deliberately: the PureScript surface is as thin as possible and the sponge plus Keccak-f[1600] live in about 150 lines of C.

```
PureScript API (Crypto.SHA3)
  -> purerl codegen (.erl)
    -> foreign module (crypto_sHA3@foreign)
      -> sha3_nif:hash/4 (Erlang stub)
        -> sha3_nif.so (C, ERL_NIF_DIRTY_JOB_CPU_BOUND)
```

Two caveats inherent to NIFs, stated up front:

- A crash in the NIF takes down the whole VM. There is no supervisor that saves you. This is the qualitative cost of leaving BEAM's fault isolation, and it is unlike the failure mode of every other backend in this project, where a bad FFI call throws an exception.
- The hash function is marked dirty (`ERL_NIF_DIRTY_JOB_CPU_BOUND`) so long inputs do not stall the normal schedulers. Dirty dispatch has a fixed per-call cost that shows up on small inputs.


### Toolchain

Pinned in the flake and not interchangeable:

| Tool | Version | Why pinned |
|---|---|---|
| purs | 0.15.14 | paired with purerl 0.0.22 |
| purerl | 0.0.22 | reads corefn from exactly this purs |
| Erlang/OTP | 27 | BeamAsm JIT, `binary:encode_hex/2` |

Dependencies are limited to `prelude`, `effect`, `console`, `functions`, and `partial`, each overridden in `spago.yaml` with the purerl fork (the registry packages ship JavaScript FFI, which purerl cannot use). The overrides point at the fork master branches; `spago.lock` pins the resolved commits and is committed.


### Build and test

```bash
nix develop      # or direnv
build-nif        # compile c_src/sha3_nif.c to priv/sha3_nif.so
test-nif         # Erlang-level NIST vectors + crypto:hash oracle, no spago needed
build-erl        # spago build with purerl backend, then erlc everything to ebin/
test-erl         # Erlang-level vectors, then PureScript-level vectors
```

`test-nif` validates the C in isolation. If it is green and `test-erl` is not, the problem is in the purerl or FFI layer, not the crypto.


### Example

```haskell
import Crypto.SHA3 (fromString, sha3_256, toHex)

toHex (sha3_256 (fromString "abc"))
-- "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```

On this backend `Binary` is an Erlang `binary()`. Since purerl represents `String` as a utf8 binary, `fromString` is the identity function.


### API

| Function | Type |
|---|---|
| `sha3_224` .. `sha3_512` | `Binary -> Binary` |
| `shake128`, `shake256` | `Int -> Binary -> Binary` |
| `fromString` | `String -> Binary` |
| `toHex` | `Binary -> String` |

The `Hashable` / `Digest` layer from the main branch is not ported here yet. The surface is intentionally minimal until the dependency situation on purerl improves.


### Performance

SHA3-256 throughput on 100 MB input:

| Implementation | MB/s |
|---|---|
| crypto:hash (OTP built-in, OpenSSL NIF) | TBD |
| C NIF (this branch) | TBD |
| Hand-written Erlang (argument-threaded, unrolled) | not yet implemented |
| Pure PureScript via purerl | not yet implemented |

`crypto:hash` is included as the ceiling: it is what BEAM users actually reach for, and omitting it would make this column misleading. The hand-written Erlang row is the one that measures the BEAM itself rather than C; it is planned as a separate branch.

Measure with:

```erlang
erl -pa ebin -noshell -eval '
  Bin = binary:copy(<<"x">>, 100000000),
  {T1, _} = timer:tc(fun() -> sha3_nif:hash(Bin, 136, 32, 16#06) end),
  {T2, _} = timer:tc(fun() -> crypto:hash(sha3_256, Bin) end),
  io:format("nif:    ~.1f MB/s~ncrypto: ~.1f MB/s~n",
            [100.0/(T1/1000000), 100.0/(T2/1000000)]),
  init:stop().'
```


### Notes on purerl FFI conventions

Two things learned the hard way, recorded so nobody relearns them:

- Foreign export arity encodes the PureScript type. An export of arity N is treated as N curried arrows. A foreign value of type `Fn4 a b c d e` has zero arrows, so it must be exported as arity 0 returning an arity-4 fun. Exporting it as arity 4 curries it and `runFn4` fails with `badarity`.
- Module name mangling lowercases the first character of each dot-separated segment and joins with underscores, preserving interior capitals. `Crypto.SHA3` becomes `crypto_sHA3`, so the foreign module is `-module(crypto_sHA3@foreign).` Check `output/<Module>/` if in doubt.


### Layout

```
c_src/
  sha3_nif.c           C implementation: sponge + Keccak-f[1600], dirty NIF
erl_src/
  sha3_nif.erl         NIF loader and stub (hash/4)
  sha3_test.erl        Erlang-level NIST vectors, cross-checked vs crypto:hash
src/
  Crypto/
    SHA3.purs          Public API
    SHA3.erl           Foreign module, delegates to sha3_nif
test/
  Test/
    Main.purs          PureScript-level FIPS 202 vectors
```


### References

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), SHA-3 Standard
- [purerl](https://github.com/purerl/purerl), PureScript Erlang backend
- [erl_nif](https://www.erlang.org/doc/man/erl_nif.html), NIF API documentation