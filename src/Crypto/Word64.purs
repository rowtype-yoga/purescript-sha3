-- | Unsigned 64-bit word operations backed by Chez Scheme's native integers.
-- | This module provides the masked 64-bit operations that Keccak needs.
-- | All values are kept in the range [0, 2^64 - 1] by applying a
-- | `logand mask64` after every operation that could widen the result.
module Crypto.Word64
  ( Word64
  , w64zero
  , w64xor
  , w64and
  , w64or
  , w64complement
  , w64rotL
  , w64fromBytesLE
  , w64toBytesLE
  , w64fromInt
  ) where

import Prelude
import Data.Array ((!!))
import Data.Maybe (fromMaybe)

-------------------------------------------------------------------------------
-- The type: just an Int (which Chez Scheme represents as fixnum/bignum).
-------------------------------------------------------------------------------

-- | A 64-bit unsigned word. On Chez Scheme this is just an exact
-- | integer in [0, 2^64 - 1]. We keep it as a type alias for
-- | documentation but it's simply `Int` under the hood.
type Word64 = Int

-------------------------------------------------------------------------------
-- FFI: native Chez Scheme bitwise operations
--
-- These are defined in Word64.ss and use Chez's logand/logior/logxor/
-- lognot/ash directly. Each one masks the result to 64 bits.
-------------------------------------------------------------------------------

-- | The zero lane.
w64zero :: Word64
w64zero = 0

-- | XOR two 64-bit words.
foreign import w64xor :: Word64 -> Word64 -> Word64

-- | AND two 64-bit words.
foreign import w64and :: Word64 -> Word64 -> Word64

-- | OR two 64-bit words.
foreign import w64or :: Word64 -> Word64 -> Word64

-- | Bitwise complement, masked to 64 bits.
foreign import w64complement :: Word64 -> Word64

-- | Left-rotate a 64-bit word by n positions (0 ≤ n < 64).
foreign import w64rotL :: Word64 -> Int -> Word64

-- | Read 8 little-endian bytes from an array starting at the given offset,
-- | assembling them into a 64-bit word.
w64fromBytesLE :: Array Int -> Int -> Word64
w64fromBytesLE bytes offset =
  let
    b :: Int -> Int
    b i = fromMaybe 0 (bytes !! (offset + i))
  in
    _assembleBytesLE (b 0) (b 1) (b 2) (b 3) (b 4) (b 5) (b 6) (b 7)

-- | FFI helper: assemble 8 bytes into a Word64 using Chez shifts.
foreign import _assembleBytesLE
  :: Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Word64

-- | Decompose a 64-bit word into 8 little-endian bytes.
foreign import w64toBytesLE :: Word64 -> Array Int

-- | Promote a small non-negative Int to Word64 (identity on Chez).
w64fromInt :: Int -> Word64
w64fromInt = identity