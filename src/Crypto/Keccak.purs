-- | Internal Keccak-f[1600] permutation and sponge construction.
-- |
-- | This module delegates to optimized Chez Scheme FFI for the hot path
-- | (mutable vectors, bytevectors) while keeping the PureScript API pure.
module Crypto.Keccak
  ( sponge
  , keccakF1600
  ) where

import Crypto.Word64 (Word64)

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

type Bytes = Array Int
type State = Array Word64

-------------------------------------------------------------------------------
-- FFI — optimized Chez Scheme implementations
-------------------------------------------------------------------------------

-- | Optimized sponge: converts flexvector → bytevector internally,
-- | uses mutable state for the permutation, returns flexvector.
foreign import spongeOptimized :: Int -> Int -> Int -> Bytes -> Bytes

-- | Optimized keccakF1600: copies flexvector to mutable vector,
-- | runs permutation in place, returns new flexvector.
foreign import keccakF1600Optimized :: State -> State

-- Expose under the original names so SHA3.purs doesn't change.

sponge :: Int -> Int -> Int -> Bytes -> Bytes
sponge = spongeOptimized

keccakF1600 :: State -> State
keccakF1600 = keccakF1600Optimized