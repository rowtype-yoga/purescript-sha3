module Bench where

import Prelude

import Crypto.SHA3 (Bytes(..), fromUtf8, sha3_224, sha3_256, sha3_384, sha3_512, toHex)
import Data.Int.Bits ((.&.))
import Effect (Effect)
import Effect.Console (log)
import Wasm.String (byteAt, unsafeNew, unsafeSetByte) as WS

-- Auto-run on import; the real timing lives in the JS driver, so this is just a marker.
main :: Effect Unit
main = log "Bench module loaded — run bench.mjs to time."

-- Hash an n-byte buffer (one byte salted by `salt`) and return digest byte 0.
-- Pure and exported: the JS driver calls it in a timed loop with a changing salt,
-- so V8 can't hoist or memoise the wasm call. Direct application per branch (no
-- first-class function value) to keep the backend on the straightforward path.
-- Caller must pass n >= 1.
hashOnceV :: Int -> Int -> Int -> Int
hashOnceV variant n salt =
  let
    buf = WS.unsafeSetByte (WS.unsafeNew n) (salt `mod` n) (salt .&. 0xFF)
    b = Bytes buf
    Bytes digest = case variant of
      224 -> sha3_224 b
      384 -> sha3_384 b
      512 -> sha3_512 b
      _ -> sha3_256 b
  in
    WS.byteAt digest 0

-- Returns 0 if every known SHA-3 vector matches, else the 1-based index of the
-- first one that fails. Pure and exported; the JS driver calls it and expects 0.
-- All string comparison happens in wasm (only the Int result crosses to JS), so
-- this tests the real i64 codegen without depending on String marshalling.
checkVectors :: Int -> Int
checkVectors _ =
  if toHex (sha3_256 (fromUtf8 "")) /= v256empty then 1
  else if toHex (sha3_256 (fromUtf8 "abc")) /= v256abc then 2
  else if toHex (sha3_512 (fromUtf8 "abc")) /= v512abc then 3
  else 0
  where
  v256empty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
  v256abc = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
  v512abc = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"