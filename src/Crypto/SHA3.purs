-- | SHA-3 (FIPS 202) cryptographic hash functions and extendable-output functions.
-- |
-- | Pure PureScript implementation of the Keccak-f[1600] permutation and
-- | sponge construction, as specified in NIST FIPS 202 (August 2015).
-- |
-- | Usage:
-- | ```purescript
-- | import Crypto.SHA3 (SHA3(..), hash, toString)
-- |
-- | digest = hash SHA3_256 "hello world"
-- | hex    = toString digest
-- | ```
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
  , exportToBuffer
  , importFromBuffer
  , toString
  , fromHex
  ) where

import Prelude

import Crypto.SHA3.Keccak as Keccak
import Data.Maybe (Maybe(..))
import Node.Buffer (Buffer)

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import bufferToArray   :: Buffer -> Array Int
foreign import bufferFromArray :: Array Int -> Buffer
foreign import bufferToHex     :: Buffer -> String
foreign import bufferFromHex   :: (Buffer -> Maybe Buffer) -> (forall a. Maybe a) -> String -> Maybe Buffer
foreign import stringToUtf8Buffer :: String -> Buffer
foreign import eqBuffer        :: Buffer -> Buffer -> Boolean

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | SHA-3 hash function variants.
data SHA3 = SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512

-- | The output of a SHA-3 hash function.
newtype Digest = Digest Buffer

instance eqDigest :: Eq Digest where
  eq (Digest a) (Digest b) = eqBuffer a b

instance showDigest :: Show Digest where
  show d = "(Digest " <> toString d <> ")"

-------------------------------------------------------------------------------
-- Hashable
-------------------------------------------------------------------------------

-- | Types that can be hashed with a SHA-3 function.
class Hashable a where
  hash :: SHA3 -> a -> Digest

instance hashableString :: Hashable String where
  hash variant value = hashBuffer variant (stringToUtf8Buffer value)

instance hashableBuffer :: Hashable Buffer where
  hash = hashBuffer

hashBuffer :: SHA3 -> Buffer -> Digest
hashBuffer variant buff =
  let
    bytes     = bufferToArray buff
    rateBytes = variantRate variant
    outBytes  = variantLength variant
    result    = Keccak.sponge rateBytes 0x06 outBytes bytes
  in
    Digest (bufferFromArray result)

-------------------------------------------------------------------------------
-- SHA-3 Hash Functions
-------------------------------------------------------------------------------

-- | SHA3-224: 224-bit (28-byte) digest, rate = 1152 bits.
sha3_224 :: Buffer -> Digest
sha3_224 = hash SHA3_224

-- | SHA3-256: 256-bit (32-byte) digest, rate = 1088 bits.
sha3_256 :: Buffer -> Digest
sha3_256 = hash SHA3_256

-- | SHA3-384: 384-bit (48-byte) digest, rate = 832 bits.
sha3_384 :: Buffer -> Digest
sha3_384 = hash SHA3_384

-- | SHA3-512: 512-bit (64-byte) digest, rate = 576 bits.
sha3_512 :: Buffer -> Digest
sha3_512 = hash SHA3_512

-------------------------------------------------------------------------------
-- SHA-3 Extendable-Output Functions (XOFs)
-------------------------------------------------------------------------------

-- | SHAKE128: 128-bit security, variable output length.
-- | First argument is the desired output length in bytes.
shake128 :: Int -> Buffer -> Buffer
shake128 outputBytes buff =
  bufferFromArray (Keccak.sponge 168 0x1F outputBytes (bufferToArray buff))

-- | SHAKE256: 256-bit security, variable output length.
-- | First argument is the desired output length in bytes.
shake256 :: Int -> Buffer -> Buffer
shake256 outputBytes buff =
  bufferFromArray (Keccak.sponge 136 0x1F outputBytes (bufferToArray buff))

-------------------------------------------------------------------------------
-- Serialization
-------------------------------------------------------------------------------

-- | Extract the raw buffer from a digest.
exportToBuffer :: Digest -> Buffer
exportToBuffer (Digest buff) = buff

-- | Wrap a buffer as a digest. No validation is performed on length.
importFromBuffer :: Buffer -> Maybe Digest
importFromBuffer = Just <<< Digest

-- | Hex-encode a digest.
toString :: Digest -> String
toString (Digest buff) = bufferToHex buff

-- | Decode a hex string to a digest.
fromHex :: String -> Maybe Digest
fromHex = map Digest <<< bufferFromHex Just Nothing

-------------------------------------------------------------------------------
-- Internal Helpers
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