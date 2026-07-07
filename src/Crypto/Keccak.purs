-- | Internal Keccak-f[1600] permutation and sponge construction.
-- |
-- | PHP backend (phpurs): the hot path is native PHP in `Keccak.php`.
-- | PHP integers are native signed 64-bit with well-defined wrapping
-- | shifts, so each lane is a single Int — no hi/lo 32-bit splitting
-- | (as on JS) and no manual masking to [0, 2^64) (as on Chez).
-- |
-- | Lane values are two's-complement: a lane with bit 63 set shows as a
-- | negative Int. Bit-identical for the XOR/AND/rotate algebra Keccak
-- | uses; only relevant if you print raw state.
module Crypto.Keccak
  ( sponge
  , keccakF1600
  , ByteArray
  , spongeNativeBv
  , State
  ) where

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

type Bytes = Array Int

-- | The Keccak state: 25 lanes indexed by (x + 5*y).
-- | Each lane is a native 64-bit PHP integer.
type State = Array Int

-- | Opaque byte array — on PHP this IS a native binary string, zero wrapping.
foreign import data ByteArray :: Type

-------------------------------------------------------------------------------
-- FFI — optimized PHP implementations
-------------------------------------------------------------------------------

-- | Sponge over Array Int (byte-level test path; converts via pack/unpack).
foreign import spongeOptimized :: Int -> Int -> Int -> Bytes -> Bytes

-- | Native binary-string sponge: zero conversion overhead.
foreign import spongeNativeBv :: Int -> Int -> Int -> ByteArray -> ByteArray

-- | Keccak-f[1600] permutation. Exposed for benchmarking.
foreign import keccakF1600Optimized :: State -> State

-- Expose under the original names so existing code doesn't change.

sponge :: Int -> Int -> Int -> Bytes -> Bytes
sponge = spongeOptimized

keccakF1600 :: State -> State
keccakF1600 = keccakF1600Optimized