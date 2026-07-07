-- | SHA-3 (FIPS 202) cryptographic hash functions and extendable-output functions.
-- |
-- | PHP backend (phpurs): ByteArray is a native PHP binary string, so hex
-- | codecs, equality, and length are single C-level builtins.
module Crypto.SHA3
  ( SHA3(..)
  , Digest
  , class Hashable
  , hash
  , sha3_224
  , sha3_256
  , sha3_384
  , sha3_512
  , shake128
  , shake256
  , toString
  , fromHex
  , toArray
  , fromArray
  ) where

import Prelude

import Crypto.Keccak (ByteArray, spongeNativeBv)
import Data.Maybe (Maybe(..))

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import stringToUtf8Bv   :: String -> ByteArray
foreign import arrayToByteArray  :: Array Int -> ByteArray
foreign import byteArrayToArray  :: ByteArray -> Array Int
foreign import bytesToHex        :: ByteArray -> String
foreign import hexToByteArray    :: String -> ByteArray
foreign import eqByteArray       :: ByteArray -> ByteArray -> Boolean
foreign import byteArrayLength   :: ByteArray -> Int

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

data SHA3 = SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512

newtype Digest = Digest ByteArray

instance eqDigest :: Eq Digest where
  eq (Digest a) (Digest b) = eqByteArray a b

instance showDigest :: Show Digest where
  show d = "(Digest " <> toString d <> ")"

-------------------------------------------------------------------------------
-- Hashable
-------------------------------------------------------------------------------

class Hashable a where
  hash :: SHA3 -> a -> Digest

instance hashableString :: Hashable String where
  hash variant s = hashBv variant (stringToUtf8Bv s)

instance hashableArray :: Hashable (Array Int) where
  hash variant arr = hashBv variant (arrayToByteArray arr)

hashBv :: SHA3 -> ByteArray -> Digest
hashBv variant bv =
  Digest (spongeNativeBv (variantRate variant) 0x06 (variantLength variant) bv)

-------------------------------------------------------------------------------
-- Convenience hash functions
-------------------------------------------------------------------------------

sha3_224 :: forall a. Hashable a => a -> Digest
sha3_224 = hash SHA3_224

sha3_256 :: forall a. Hashable a => a -> Digest
sha3_256 = hash SHA3_256

sha3_384 :: forall a. Hashable a => a -> Digest
sha3_384 = hash SHA3_384

sha3_512 :: forall a. Hashable a => a -> Digest
sha3_512 = hash SHA3_512

-------------------------------------------------------------------------------
-- SHAKE XOFs (variable-length output, Array Int API)
-------------------------------------------------------------------------------

shake128 :: Int -> Array Int -> Array Int
shake128 outputBytes arr =
  byteArrayToArray (spongeNativeBv 168 0x1F outputBytes (arrayToByteArray arr))

shake256 :: Int -> Array Int -> Array Int
shake256 outputBytes arr =
  byteArrayToArray (spongeNativeBv 136 0x1F outputBytes (arrayToByteArray arr))

-------------------------------------------------------------------------------
-- Serialization
-------------------------------------------------------------------------------

toString :: Digest -> String
toString (Digest bv) = bytesToHex bv

fromHex :: String -> Maybe Digest
fromHex hex =
  let bv = hexToByteArray hex
  in if byteArrayLength bv > 0 || hex == ""
     then Just (Digest bv)
     else Nothing

toArray :: Digest -> Array Int
toArray (Digest bv) = byteArrayToArray bv

fromArray :: Array Int -> Digest
fromArray arr = Digest (arrayToByteArray arr)

-------------------------------------------------------------------------------
-- Internal
-------------------------------------------------------------------------------

variantRate :: SHA3 -> Int
variantRate SHA3_224 = 144
variantRate SHA3_256 = 136
variantRate SHA3_384 = 104
variantRate SHA3_512 = 72

variantLength :: SHA3 -> Int
variantLength SHA3_224 = 28
variantLength SHA3_256 = 32
variantLength SHA3_384 = 48
variantLength SHA3_512 = 64