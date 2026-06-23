module Crypto.SHA3
  ( Bytes(..)
  , sha3_224
  , sha3_256
  , sha3_384
  , sha3_512
  , fromUtf8
  , unBytes
  , toHex
  ) where

import Prelude

import Crypto.SHA3.Keccak (State, getLane, keccakF, setLane)
import Data.Int.Bits (zshr, (.&.), (.|.))
import Wasm.Int64 as I
import Wasm.I64Array (unsafeNew) as IA
import Wasm.String (byteAt, byteLength, unsafeNew, unsafeSetByte) as WS


-- | A byte string. On the wasm backend a `String` (`$Str`) is exactly a packed
-- | byte buffer, so this newtype is zero-cost.
newtype Bytes = Bytes String

unBytes :: Bytes -> String
unBytes (Bytes s) = s

-- | Interpret a String as its UTF-8 bytes (identity wrap on wasm).
fromUtf8 :: String -> Bytes
fromUtf8 = Bytes

sha3_224 :: Bytes -> Bytes
sha3_224 = hashBytes 144 28

-- | SHA3-256: rate 136 bytes (capacity 512 bits), 32-byte raw digest.
sha3_256 :: Bytes -> Bytes
sha3_256 = hashBytes 136 32

sha3_384 :: Bytes -> Bytes
sha3_384 = hashBytes 104 48

-- | SHA3-512: rate 72 bytes (capacity 1024 bits), 64-byte raw digest.
sha3_512 :: Bytes -> Bytes
sha3_512 = hashBytes 72 64

-- | Lowercase hex rendering of a digest (or any bytes).
toHex :: Bytes -> String
toHex (Bytes digest) = go 0 (WS.unsafeNew (2 * n))
  where
  n = WS.byteLength digest
  go b acc
    | b < n =
        let
          v = WS.byteAt digest b
          acc1 = WS.unsafeSetByte acc (2 * b) (hexNibble (zshr v 4 .&. 0xF))
          acc2 = WS.unsafeSetByte acc1 (2 * b + 1) (hexNibble (v .&. 0xF))
        in
          go (b + 1) acc2
    | otherwise = acc

-- ---------------------------------------------------------------------------
-- Internal sponge core (NOT exported). The single-block squeeze is valid only
-- when outLen <= rate, true for every fixed-length SHA-3 (224/256/384/512).
-- ---------------------------------------------------------------------------

hashBytes :: Int -> Int -> Bytes -> Bytes
hashBytes rate outLen (Bytes input) =
  -- `IA.unsafeNew` zero-inits the 25 i64 lanes, so no explicit clear is needed
  -- before the first absorb.
  squeezeRaw outLen (absorbAll 0 (IA.unsafeNew 25))
  where
  len = WS.byteLength input
  padLen = (len / rate + 1) * rate
  nBlocks = padLen / rate
  -- Every SHA-3 rate (144/136/104/72) is a multiple of 8, so a block is exactly
  -- `nLanes` whole 64-bit lanes — no partial-lane bookkeeping.
  nLanes = rate / 8

  absorbAll i st
    | i < nBlocks = absorbAll (i + 1) (absorbBlock (i * rate) st)
    | otherwise = st

  -- Absorb a block one *lane* at a time: pack its 8 little-endian (padded) bytes
  -- into a single i64 and XOR it into the lane in one shot. That replaces the old
  -- byte-at-a-time loop (8 getLane/setLane round-trips per lane) with 8 cheap
  -- i64 shifts+ors and a single setLane — ~8x fewer lane writes on the hot
  -- absorb path, where large-input throughput is spent.
  absorbBlock offset st = keccakF (go 0 st)
    where
    go l s
      | l < nLanes = go (l + 1) (setLane s l (getLane s l `I.xor` laneAt (offset + l * 8)))
      | otherwise = s

  -- The 8-byte little-endian word starting at byte index `base`, with pad10*1 and
  -- the 0x06 domain suffix applied positionally by `paddedByteAt` (no scratch buffer).
  laneAt base = foldByte 0 (I.fromInt 0)
    where
    foldByte k acc
      | k < 8 =
          foldByte (k + 1)
            ( acc `I.or`
                I.shl (I.fromInt (paddedByteAt input len padLen (base + k))) (k * 8)
            )
      | otherwise = acc

-- Squeeze `n` raw bytes (single block) into a fresh wasm byte buffer.
squeezeRaw :: Int -> State -> Bytes
squeezeRaw n st = Bytes (go 0 (WS.unsafeNew n))
  where
  go b acc
    | b < n = go (b + 1) (WS.unsafeSetByte acc b (readByte st b))
    | otherwise = acc

-- pad10*1 with the SHA-3 0x06 domain suffix, computed positionally (no buffer).
paddedByteAt :: String -> Int -> Int -> Int -> Int
paddedByteAt input len padLen i =
  (if i < len then WS.byteAt input i else 0)
    .|. (if i == len then 0x06 else 0)
    .|. (if i == padLen - 1 then 0x80 else 0)

-- Read raw byte `b` of the state: lane `b >> 3`, byte position `b & 7`. The
-- power-of-two `/ 8` and `mod 8` are strength-reduced to a shift and a mask so
-- the squeeze loop never hits the (helper-call) i32 div/rem path.
readByte :: State -> Int -> Int
readByte st b =
  let
    l = zshr b 3
    p = b .&. 7
  in
    I.lowBits (I.zshr (getLane st l) (p * 8)) .&. 0xFF

hexNibble :: Int -> Int
hexNibble n = if n < 10 then 48 + n else 87 + n