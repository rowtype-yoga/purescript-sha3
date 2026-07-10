module Crypto.SHA3
  ( Binary
  , fromString
  , toHex
  , sha3_224
  , sha3_256
  , sha3_384
  , sha3_512
  , shake128
  , shake256
  ) where

import Data.Function.Uncurried (Fn4, runFn4)

-- | An Erlang binary(). On this backend, String is also binary(),
-- | but we keep the type distinct so the API matches the other forks.
foreign import data Binary :: Type

foreign import fromString :: String -> Binary
foreign import toHex :: Binary -> String
foreign import hashImpl :: Fn4 Binary Int Int Int Binary

-- rate bytes, output bytes, domain separator per FIPS 202
sha3_224 :: Binary -> Binary
sha3_224 b = runFn4 hashImpl b 144 28 0x06

sha3_256 :: Binary -> Binary
sha3_256 b = runFn4 hashImpl b 136 32 0x06

sha3_384 :: Binary -> Binary
sha3_384 b = runFn4 hashImpl b 104 48 0x06

sha3_512 :: Binary -> Binary
sha3_512 b = runFn4 hashImpl b 72 64 0x06

shake128 :: Int -> Binary -> Binary
shake128 outLen b = runFn4 hashImpl b 168 outLen 0x1f

shake256 :: Int -> Binary -> Binary
shake256 outLen b = runFn4 hashImpl b 136 outLen 0x1f