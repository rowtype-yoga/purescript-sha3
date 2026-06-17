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

import Crypto.SHA3.Keccak (State, clearState, getHi, getLo, keccakF, setHi, setLo)
import Data.Int.Bits (shl, xor, zshr, (.&.), (.|.))
import Wasm.Array (unsafeNew) as WA
import Wasm.String (byteAt, byteLength, unsafeNew, unsafeSetByte) as WS

-- | A byte string. On the wasm backend a `String` (`$Str`) is exactly a packed
-- | byte buffer, so this newtype is zero-cost — no representation overhead, it
-- | only stops text and raw bytes from being conflated at the type level.
-- | Build it from text with `fromUtf8`, from an existing wasm byte buffer with
-- | the `Bytes` constructor, and render a digest with `toHex`.
newtype Bytes = Bytes String

unBytes :: Bytes -> String
unBytes (Bytes s) = s

-- | Interpret a String as its UTF-8 bytes. On wasm a String is stored as UTF-8
-- | and `Wasm.String.byteAt` reads raw bytes, so this is the identity wrap. (On
-- | the JS backend a String is UTF-16, so non-ASCII would diverge — wasm is the
-- | intended target.)
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

-- | Lowercase hex rendering of a digest (or any bytes). Separate from hashing
-- | on purpose: callers who want the raw bytes never pay for, or have to parse,
-- | a hex string.
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
-- when outLen <= rate — true for every fixed-length SHA-3 (224/256/384/512 all
-- have digest < rate). SHAKE's arbitrary-length output would need a
-- permute-and-read loop and is deliberately out of scope.
-- ---------------------------------------------------------------------------

hashBytes :: Int -> Int -> Bytes -> Bytes
hashBytes rate outLen (Bytes input) =
  squeezeRaw outLen (absorbAll 0 (clearState (WA.unsafeNew 50)))
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

-- pad10*1 with the SHA-3 0x06 domain suffix, computed positionally (no buffer):
-- message bytes from the string, 0x06 at index `len`, 0x80 at the last index;
-- if those coincide the byte is 0x86.
paddedByteAt :: String -> Int -> Int -> Int -> Int
paddedByteAt input len padLen i =
  (if i < len then WS.byteAt input i else 0)
    .|. (if i == len then 0x06 else 0)
    .|. (if i == padLen - 1 then 0x80 else 0)

-- Rate byte b -> lane (b/8) at little-endian byte position (b mod 8): 0-3 in lo,
-- 4-7 in hi. Lane linear index L -> (x,y) = (L mod 5, L div 5).
xorByte :: State -> Int -> Int -> State
xorByte s b v =
  let
    l = b / 8
    p = b `mod` 8
    x = l `mod` 5
    y = l / 5
  in
    if p < 4 then setLo s x y (getLo s x y `xor` shl v (p * 8))
    else setHi s x y (getHi s x y `xor` shl v ((p - 4) * 8))

readByte :: State -> Int -> Int
readByte st b =
  let
    l = b / 8
    p = b `mod` 8
    x = l `mod` 5
    y = l / 5
    word = if p < 4 then getLo st x y else getHi st x y
  in
    zshr word ((p `mod` 4) * 8) .&. 0xFF

hexNibble :: Int -> Int
hexNibble n = if n < 10 then 48 + n else 87 + n