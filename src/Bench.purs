module Bench where

import Prelude

import Crypto.SHA3 (Bytes(..), sha3_224, sha3_256, sha3_384, sha3_512)
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