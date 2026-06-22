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

import Crypto.SHA3.Keccak (State, clearState, getLane, keccakF, setLane)
import Data.Int.Bits (zshr, (.&.), (.|.))
import Wasm.Array (unsafeNew) as WA
import Wasm.Int64 as I
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
  squeezeRaw outLen (absorbAll 0 (clearState (WA.unsafeNew 25)))
  where
  len = WS.byteLength input
  padLen = (len / rate + 1) * rate
  nBlocks = padLen / rate

  absorbAll i st
    | i < nBlocks = absorbAll (i + 1) (absorbBlock (i * rate) st)
    | otherwise = st

  absorbBlock offset st = keccakF (xorBytes 0 st)
    where
    xorBytes b s
      | b < rate = xorBytes (b + 1) (xorByte s b (paddedByteAt input len padLen (offset + b)))
      | otherwise = s

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

-- Rate byte b -> lane (b / 8), little-endian byte position (b mod 8). With i64
-- lanes the whole lane is one word, so XOR-ing a byte in is a single shift + xor
-- (no lo/hi split). Byte values are 0..255, so `fromInt` needs no masking.
xorByte :: State -> Int -> Int -> State
xorByte s b v =
  let
    l = b / 8
    p = b `mod` 8
  in
    setLane s l (getLane s l `I.xor` I.shl (I.fromInt v) (I.fromInt (p * 8)))

readByte :: State -> Int -> Int
readByte st b =
  let
    l = b / 8
    p = b `mod` 8
  in
    I.toInt (I.zshr (getLane st l) (I.fromInt (p * 8))) .&. 0xFF

hexNibble :: Int -> Int
hexNibble n = if n < 10 then 48 + n else 87 + n