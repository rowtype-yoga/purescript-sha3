-- | SHA-3 (FIPS 202) implementation in pure PureScript.
-- |
-- | Implements the full Keccak-f[1600] permutation and sponge construction
-- | as specified in NIST FIPS 202 (August 2015), including the errata
-- | correction to Algorithm 10 Step 1: `0 ≤ i < 2m` (not `2m - 1`).
-- |
-- | Provides:
-- |   - SHA3-224, SHA3-256, SHA3-384, SHA3-512 hash functions
-- |   - SHAKE128, SHAKE256 extendable-output functions (XOFs)
-- |   - Hex encoding/decoding utilities
-- |   - UTF-8 string encoding
-- |
-- | All functions operate on `Bytes` (Array Int where each Int is 0–255).
-- |
-- | Usage:
-- | ```purescript
-- | import Crypto.SHA3 (sha3_256, toHex, fromUtf8)
-- |
-- | digest = toHex (sha3_256 (fromUtf8 "hello"))
-- | ```
module Crypto.SHA3
  ( -- * Types
    Bytes
    -- * SHA-3 Hash Functions
  , sha3_224
  , sha3_256
  , sha3_384
  , sha3_512
    -- * SHA-3 Extendable-Output Functions (XOFs)
  , shake128
  , shake256
    -- * Hex Encoding / Decoding
  , toHex
  , fromHex
    -- * String Encoding
  , fromUtf8
    -- * Low-level (exposed for testing)
  , keccakF1600
  ) where

import Prelude

import Data.Array as A
import Data.Array ((!!))
import Data.Enum (fromEnum)
import Data.Foldable (foldl)
import Data.Int.Bits (shl, zshr, xor, (.&.), (.|.), complement)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.String.CodeUnits as SCU

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | A byte array. Each element must be in the range 0–255.
type Bytes = Array Int

-- | A 64-bit lane, represented as two 32-bit halves.
-- | The full 64-bit value is conceptually (hi << 32) | lo.
-- | `lo` holds bits 0–31, `hi` holds bits 32–63.
type Lane = { hi :: Int, lo :: Int }

-- | The Keccak state: 25 lanes indexed by (x + 5*y) for 0 ≤ x,y < 5.
type State = Array Lane

-------------------------------------------------------------------------------
-- Lane Operations
-------------------------------------------------------------------------------

-- | The zero lane (all 64 bits clear).
zeroLane :: Lane
zeroLane = { hi: 0, lo: 0 }

-- | Bitwise XOR of two lanes.
xorLane :: Lane -> Lane -> Lane
xorLane a b = { hi: xor a.hi b.hi, lo: xor a.lo b.lo }

-- | Bitwise AND of two lanes.
andLane :: Lane -> Lane -> Lane
andLane a b = { hi: a.hi .&. b.hi, lo: a.lo .&. b.lo }

-- | Bitwise complement (NOT) of a lane.
complementLane :: Lane -> Lane
complementLane a = { hi: complement a.hi, lo: complement a.lo }

-- | Left-rotate a lane by n bits (0 ≤ n < 64).
-- |
-- | For a 64-bit value split across two 32-bit halves, rotation requires
-- | shifting both halves and combining the overflow bits.
rotL :: Lane -> Int -> Lane
rotL lane n
  | n == 0 = lane
  | n == 32 = { hi: lane.lo, lo: lane.hi }
  | n < 32 =
      { hi: (lane.hi `shl` n) .|. (lane.lo `zshr` (32 - n))
      , lo: (lane.lo `shl` n) .|. (lane.hi `zshr` (32 - n))
      }
  | otherwise = -- 32 < n < 64
      let m = n - 32
      in { hi: (lane.lo `shl` m) .|. (lane.hi `zshr` (32 - m))
         , lo: (lane.hi `shl` m) .|. (lane.lo `zshr` (32 - m))
         }

-------------------------------------------------------------------------------
-- State Access Helpers
-------------------------------------------------------------------------------

-- | Read lane at coordinates (x, y) from the state.
-- | Index into flat array: x + 5*y.
at :: State -> Int -> Int -> Lane
at st x y = fromMaybe zeroLane (st !! (x + 5 * y))

-- | Build a 25-element state array from a function of (x, y).
stateFromFn :: (Int -> Int -> Lane) -> State
stateFromFn f = do
  y <- A.range 0 4
  x <- A.range 0 4
  pure (f x y)

-- | The initial state: all 25 lanes zeroed.
emptyState :: State
emptyState = A.replicate 25 zeroLane

-------------------------------------------------------------------------------
-- Byte ↔ Lane Conversions (Little-Endian)
--
-- Per FIPS 202 §3.1.2, the state string S maps to the state array as:
--   A[x, y, z] = S[w(5y + x) + z]
-- Bytes within each lane are in little-endian order.
-------------------------------------------------------------------------------

-- | Read 8 bytes from a byte array at the given offset into a Lane.
-- | Missing bytes (past end of array) are treated as 0.
bytesToLane :: Bytes -> Int -> Lane
bytesToLane bytes offset =
  let
    b :: Int -> Int
    b i = fromMaybe 0 (bytes !! (offset + i))
  in
    { lo: b 0 .|. (b 1 `shl` 8) .|. (b 2 `shl` 16) .|. (b 3 `shl` 24)
    , hi: b 4 .|. (b 5 `shl` 8) .|. (b 6 `shl` 16) .|. (b 7 `shl` 24)
    }

-- | Extract a Lane to 8 bytes in little-endian order.
laneToBytes :: Lane -> Bytes
laneToBytes lane =
  [ lane.lo .&. 0xFF
  , (lane.lo `zshr` 8) .&. 0xFF
  , (lane.lo `zshr` 16) .&. 0xFF
  , (lane.lo `zshr` 24) .&. 0xFF
  , lane.hi .&. 0xFF
  , (lane.hi `zshr` 8) .&. 0xFF
  , (lane.hi `zshr` 16) .&. 0xFF
  , (lane.hi `zshr` 24) .&. 0xFF
  ]

-------------------------------------------------------------------------------
-- XOR a Block of Bytes into the State
--
-- During absorption, the first r/8 bytes of each block are XOR'd into the
-- state lanes. Bytes map to lanes sequentially: bytes 0–7 → lane 0,
-- bytes 8–15 → lane 1, etc.
-------------------------------------------------------------------------------

-- | XOR a byte block (up to rateBytes long) into the state.
xorBytesIntoState :: Bytes -> Int -> State -> State
xorBytesIntoState block rateBytes st =
  let
    -- Number of full lanes to XOR
    numLanes = rateBytes / 8
  in
    A.mapWithIndex
      ( \i lane ->
          if i < numLanes then xorLane lane (bytesToLane block (i * 8))
          else lane
      )
      st

-- | Extract rateBytes bytes from the state (for squeezing).
extractBytes :: Int -> State -> Bytes
extractBytes rateBytes st =
  let
    numLanes = rateBytes / 8
    allBytes = A.concatMap laneToBytes (A.take numLanes st)
  in
    A.take rateBytes allBytes

-------------------------------------------------------------------------------
-- Round Constants (FIPS 202 §3.2.5, Algorithm 5/6)
--
-- The 24 round constants for Keccak-f[1600], precomputed from the rc(t)
-- linear feedback shift register. Each constant is a 64-bit lane value
-- that gets XOR'd into lane (0,0) during the ι step.
--
-- Representation note: PureScript Int is 32-bit signed. Values with bit 31
-- set appear as negative numbers, but bitwise operations work on the
-- underlying bit pattern regardless of sign interpretation.
-------------------------------------------------------------------------------

-- | Bit 31 as a 32-bit signed int (= 0x80000000 = -2147483648).
b31 :: Int
b31 = 1 `shl` 31

roundConstants :: Array Lane
roundConstants =
  -- RC[ 0] = 0x0000000000000001
  [ { hi: 0, lo: 1 }
  -- RC[ 1] = 0x0000000000008082
  , { hi: 0, lo: 0x8082 }
  -- RC[ 2] = 0x800000000000808A
  , { hi: b31, lo: 0x808A }
  -- RC[ 3] = 0x8000000080008000
  , { hi: b31, lo: b31 .|. 0x8000 }
  -- RC[ 4] = 0x000000000000808B
  , { hi: 0, lo: 0x808B }
  -- RC[ 5] = 0x0000000080000001
  , { hi: 0, lo: b31 .|. 1 }
  -- RC[ 6] = 0x8000000080008081
  , { hi: b31, lo: b31 .|. 0x8081 }
  -- RC[ 7] = 0x8000000000008009
  , { hi: b31, lo: 0x8009 }
  -- RC[ 8] = 0x000000000000008A
  , { hi: 0, lo: 0x8A }
  -- RC[ 9] = 0x0000000000000088
  , { hi: 0, lo: 0x88 }
  -- RC[10] = 0x0000000080008009
  , { hi: 0, lo: b31 .|. 0x8009 }
  -- RC[11] = 0x000000008000000A
  , { hi: 0, lo: b31 .|. 0x0A }
  -- RC[12] = 0x000000008000808B
  , { hi: 0, lo: b31 .|. 0x808B }
  -- RC[13] = 0x800000000000008B
  , { hi: b31, lo: 0x8B }
  -- RC[14] = 0x8000000000008089
  , { hi: b31, lo: 0x8089 }
  -- RC[15] = 0x8000000000008003
  , { hi: b31, lo: 0x8003 }
  -- RC[16] = 0x8000000000008002
  , { hi: b31, lo: 0x8002 }
  -- RC[17] = 0x8000000000000080
  , { hi: b31, lo: 0x80 }
  -- RC[18] = 0x000000000000800A
  , { hi: 0, lo: 0x800A }
  -- RC[19] = 0x800000008000000A
  , { hi: b31, lo: b31 .|. 0x0A }
  -- RC[20] = 0x8000000080008081
  , { hi: b31, lo: b31 .|. 0x8081 }
  -- RC[21] = 0x8000000000008080
  , { hi: b31, lo: 0x8080 }
  -- RC[22] = 0x0000000080000001
  , { hi: 0, lo: b31 .|. 1 }
  -- RC[23] = 0x8000000080008008
  , { hi: b31, lo: b31 .|. 0x8008 }
  ]

-------------------------------------------------------------------------------
-- ρ Rotation Offsets (FIPS 202 §3.2.2, Table 2)
--
-- Precomputed from Algorithm 2, reduced mod 64 (lane size for b=1600).
-- Indexed as rhoOffset[x + 5*y].
-------------------------------------------------------------------------------

rhoOffsets :: Array Int
rhoOffsets =
  -- y=0:  x=0  x=1  x=2  x=3  x=4
  [          0,   1,  62,  28,  27
  -- y=1:
  ,         36,  44,   6,  55,  20
  -- y=2:
  ,          3,  10,  43,  25,  39
  -- y=3:
  ,         41,  45,  15,  21,   8
  -- y=4:
  ,         18,   2,  61,  56,  14
  ]

-------------------------------------------------------------------------------
-- Step Mappings (FIPS 202 §3.2)
--
-- Each step mapping transforms a State → State. Together they form one
-- round: Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
-------------------------------------------------------------------------------

-- | θ (theta) — FIPS 202 Algorithm 1
-- |
-- | XORs each bit with the parities of two neighboring columns.
-- |
-- | 1. C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
-- | 2. D[x] = C[(x-1) mod 5] ⊕ ROT(C[(x+1) mod 5], 1)
-- | 3. A'[x,y] = A[x,y] ⊕ D[x]
theta :: State -> State
theta st =
  let
    -- Step 1: Column parities C[x] for x in 0..4
    c :: Int -> Lane
    c x = at st x 0 `xorLane` at st x 1 `xorLane` at st x 2
           `xorLane` at st x 3 `xorLane` at st x 4

    c0 = c 0
    c1 = c 1
    c2 = c 2
    c3 = c 3
    c4 = c 4

    cArr = [ c0, c1, c2, c3, c4 ]

    cAt :: Int -> Lane
    cAt i = fromMaybe zeroLane (cArr !! i)

    -- Step 2: D[x] = C[(x-1) mod 5] ⊕ ROT(C[(x+1) mod 5], 1)
    d :: Int -> Lane
    d x = cAt ((x + 4) `mod` 5) `xorLane` rotL (cAt ((x + 1) `mod` 5)) 1

    d0 = d 0
    d1 = d 1
    d2 = d 2
    d3 = d 3
    d4 = d 4

    dArr = [ d0, d1, d2, d3, d4 ]

    dAt :: Int -> Lane
    dAt i = fromMaybe zeroLane (dArr !! i)
  in
    -- Step 3: A'[x,y] = A[x,y] ⊕ D[x]
    stateFromFn (\x y -> at st x y `xorLane` dAt x)

-- | ρ (rho) — FIPS 202 Algorithm 2
-- |
-- | Rotates each lane by its precomputed offset from Table 2.
rho :: State -> State
rho st =
  A.mapWithIndex
    (\i lane -> rotL lane (fromMaybe 0 (rhoOffsets !! i)))
    st

-- | π (pi) — FIPS 202 Algorithm 3
-- |
-- | Rearranges lane positions: A'[x, y] = A[(x + 3y) mod 5, x]
pi :: State -> State
pi st = stateFromFn (\x y -> at st ((x + 3 * y) `mod` 5) x)

-- | χ (chi) — FIPS 202 Algorithm 4
-- |
-- | Non-linear step: A'[x,y] = A[x,y] ⊕ ((NOT A[(x+1) mod 5, y]) AND A[(x+2) mod 5, y])
chi :: State -> State
chi st = stateFromFn \x y ->
  at st x y `xorLane`
    (complementLane (at st ((x + 1) `mod` 5) y)
      `andLane` at st ((x + 2) `mod` 5) y)

-- | ι (iota) — FIPS 202 Algorithm 6
-- |
-- | XORs the round constant into lane (0, 0). The round constant depends
-- | on the round index ir.
iota :: Int -> State -> State
iota ir st =
  let
    rc = fromMaybe zeroLane (roundConstants !! ir)
    lane0 = fromMaybe zeroLane (st !! 0)
  in
    fromMaybe st (A.updateAt 0 (xorLane lane0 rc) st)

-------------------------------------------------------------------------------
-- Keccak-f[1600] Permutation (FIPS 202 §3.3, Algorithm 7)
--
-- 24 rounds of Rnd, where Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
-- Round indices run from 0 to 23 for Keccak-f[1600] (since 12 + 2l - nr = 0
-- when l = 6 and nr = 24).
-------------------------------------------------------------------------------

-- | One round of the Keccak permutation.
round :: Int -> State -> State
round ir = iota ir <<< chi <<< pi <<< rho <<< theta

-- | The full Keccak-f[1600] permutation: 24 rounds.
keccakF1600 :: State -> State
keccakF1600 st = foldl (\s ir -> round ir s) st (A.range 0 23)

-------------------------------------------------------------------------------
-- Padding: pad10*1 (FIPS 202 §5.1, Algorithm 9)
--
-- For byte-aligned messages, the padding combines the domain separation
-- suffix with pad10*1 into complete bytes, as described in Table 6:
--
--   SHA-3 hash:  suffix byte = 0x06,  final byte = 0x80
--   SHAKE XOF:   suffix byte = 0x1F,  final byte = 0x80
--
-- If only 1 padding byte is needed, it's (suffix | 0x80).
-------------------------------------------------------------------------------

-- | Pad a byte-aligned message for absorption into the sponge.
-- |
-- | Parameters:
-- |   - suffixByte: domain separation byte (0x06 for hash, 0x1F for XOF)
-- |   - rateBytes:  the rate in bytes (r/8)
-- |   - message:    the input bytes
-- |
-- | Returns the padded message whose length is a multiple of rateBytes.
padMessage :: Int -> Int -> Bytes -> Bytes
padMessage suffixByte rateBytes message =
  let
    msgLen = A.length message
    -- How many bytes needed to fill the current block
    q = rateBytes - (msgLen `mod` rateBytes)
  in
    if q == 1 then
      -- Single padding byte: combine suffix and final bit
      message <> [ suffixByte .|. 0x80 ]
    else
      -- First byte: suffix, middle bytes: 0x00, last byte: 0x80
      message <> [ suffixByte ] <> A.replicate (q - 2) 0 <> [ 0x80 ]

-------------------------------------------------------------------------------
-- Sponge Construction (FIPS 202 §4, Algorithm 8)
--
-- Z = SPONGE[f, pad, r](N, d)
--
-- The sponge absorbs r-bit blocks of the padded input, applying f after
-- each block, then squeezes out d bits of output, applying f between
-- each r-bit squeeze.
-------------------------------------------------------------------------------

-- | Core sponge function.
-- |
-- | Parameters:
-- |   - rateBytes:   rate in bytes (r/8)
-- |   - suffixByte:  domain separation (0x06 for SHA-3 hash, 0x1F for SHAKE)
-- |   - outputBytes: desired output length in bytes (d/8)
-- |   - message:     input bytes
-- |
-- | Returns the output byte array of length outputBytes.
sponge :: Int -> Int -> Int -> Bytes -> Bytes
sponge rateBytes suffixByte outputBytes message =
  let
    -- Step 1: Pad the message
    padded = padMessage suffixByte rateBytes message
    -- Step 2: Split into r-byte blocks
    numBlocks = A.length padded / rateBytes
    -- Steps 5-6: Absorb phase
    absorb :: State -> Int -> State
    absorb st blockIdx =
      let
        block = A.slice (blockIdx * rateBytes) ((blockIdx + 1) * rateBytes) padded
        xored = xorBytesIntoState block rateBytes st
      in
        keccakF1600 xored

    absorbed = foldl absorb emptyState (A.range 0 (numBlocks - 1))

    -- Steps 7-10: Squeeze phase
    initialSqueeze = { out: extractBytes rateBytes absorbed, st: absorbed }

    squeezed = squeezeLoop outputBytes rateBytes initialSqueeze
  in
    A.take outputBytes squeezed.out

-- | Squeeze loop: keep squeezing until we have enough output bytes.
squeezeLoop
  :: Int
  -> Int
  -> { out :: Bytes, st :: State }
  -> { out :: Bytes, st :: State }
squeezeLoop needed rateBytes acc
  | A.length acc.out >= needed = acc
  | otherwise =
      let
        newSt = keccakF1600 acc.st
        extracted = extractBytes rateBytes newSt
      in
        squeezeLoop needed rateBytes { out: acc.out <> extracted, st: newSt }

-------------------------------------------------------------------------------
-- SHA-3 Hash Functions (FIPS 202 §6.1)
--
-- SHA3-d(M) = KECCAK[2d](M || 01, d)
--
-- The "01" suffix is the two-bit domain separator for hash functions.
-- Combined with pad10*1, the first padding byte becomes 0x06.
--
-- Capacity c = 2d, so rate r = 1600 - 2d.
-------------------------------------------------------------------------------

-- | SHA3-224: 224-bit (28-byte) digest, rate = 1152 bits (144 bytes).
sha3_224 :: Bytes -> Bytes
sha3_224 = sponge 144 0x06 28

-- | SHA3-256: 256-bit (32-byte) digest, rate = 1088 bits (136 bytes).
sha3_256 :: Bytes -> Bytes
sha3_256 = sponge 136 0x06 32

-- | SHA3-384: 384-bit (48-byte) digest, rate = 832 bits (104 bytes).
sha3_384 :: Bytes -> Bytes
sha3_384 = sponge 104 0x06 48

-- | SHA3-512: 512-bit (64-byte) digest, rate = 576 bits (72 bytes).
sha3_512 :: Bytes -> Bytes
sha3_512 = sponge 72 0x06 64

-------------------------------------------------------------------------------
-- SHA-3 Extendable-Output Functions (FIPS 202 §6.2)
--
-- SHAKE128(M, d) = KECCAK[256](M || 1111, d)
-- SHAKE256(M, d) = KECCAK[512](M || 1111, d)
--
-- The "1111" suffix is the four-bit domain separator for XOFs.
-- Combined with pad10*1, the first padding byte becomes 0x1F.
-------------------------------------------------------------------------------

-- | SHAKE128: extendable output, 128-bit security, rate = 1344 bits (168 bytes).
-- |
-- | The `outputBytes` parameter specifies how many bytes of output to produce.
shake128 :: Int -> Bytes -> Bytes
shake128 outputBytes = sponge 168 0x1F outputBytes

-- | SHAKE256: extendable output, 256-bit security, rate = 1088 bits (136 bytes).
-- |
-- | The `outputBytes` parameter specifies how many bytes of output to produce.
shake256 :: Int -> Bytes -> Bytes
shake256 outputBytes = sponge 136 0x1F outputBytes

-------------------------------------------------------------------------------
-- Hex Encoding / Decoding
--
-- Follows the b2h convention from FIPS 202 Appendix B (Algorithm 11),
-- with the errata correction applied to Algorithm 10 Step 1:
-- the bound is `0 ≤ i < 2m` (not `0 ≤ i < 2m - 1`).
--
-- Note: The spec's h2b/b2h functions handle bit-level reversal within
-- bytes for SHA-3's internal bit ordering. For the public API, our
-- toHex/fromHex operate on standard byte values (0x00–0xFF) and produce
-- conventional hex strings, which is what users expect and what other
-- SHA-3 implementations output.
-------------------------------------------------------------------------------

hexChars :: Array Char
hexChars =
  [ '0', '1', '2', '3', '4', '5', '6', '7'
  , '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  ]

-- | Encode a byte array as a lowercase hexadecimal string.
toHex :: Bytes -> String
toHex bytes =
  let
    byteToHex :: Int -> String
    byteToHex b =
      let
        hi = (b `zshr` 4) .&. 0x0F
        lo = b .&. 0x0F
        hiChar = fromMaybe '0' (hexChars !! hi)
        loChar = fromMaybe '0' (hexChars !! lo)
      in
        SCU.singleton hiChar <> SCU.singleton loChar
  in
    A.foldMap byteToHex bytes

-- | Decode a hexadecimal string to a byte array.
-- | Returns Nothing if the string has odd length or contains non-hex characters.
fromHex :: String -> Maybe Bytes
fromHex str =
  let
    chars = SCU.toCharArray str
    len = A.length chars
  in
    if len `mod` 2 /= 0 then Nothing
    else parseHexPairs chars 0 []

-- | Parse consecutive pairs of hex characters into bytes.
parseHexPairs :: Array Char -> Int -> Bytes -> Maybe Bytes
parseHexPairs chars idx acc
  | idx >= A.length chars = Just acc
  | otherwise = do
      hiChar <- chars !! idx
      loChar <- chars !! (idx + 1)
      hi <- hexVal hiChar
      lo <- hexVal loChar
      parseHexPairs chars (idx + 2) (acc <> [ hi * 16 + lo ])

-- | Convert a hex character to its numeric value (0–15).
hexVal :: Char -> Maybe Int
hexVal c
  | c >= '0' && c <= '9' = Just (fromEnum c - fromEnum '0')
  | c >= 'a' && c <= 'f' = Just (fromEnum c - fromEnum 'a' + 10)
  | c >= 'A' && c <= 'F' = Just (fromEnum c - fromEnum 'A' + 10)
  | otherwise = Nothing

-------------------------------------------------------------------------------
-- UTF-8 String Encoding
--
-- Converts a PureScript String (JavaScript UTF-16) to UTF-8 bytes.
-- Handles the full Unicode range including surrogate pairs for code
-- points above U+FFFF.
-------------------------------------------------------------------------------

-- | Encode a String as UTF-8 bytes.
fromUtf8 :: String -> Bytes
fromUtf8 str =
  let
    chars = SCU.toCharArray str
    len = A.length chars
  in
    encodeChars chars 0 len []

-- | Walk through the char array, handling surrogate pairs and encoding
-- | each code point as 1–4 UTF-8 bytes.
encodeChars :: Array Char -> Int -> Int -> Bytes -> Bytes
encodeChars chars idx len acc
  | idx >= len = acc
  | otherwise =
      let
        c = fromMaybe 0 (map fromEnum (chars !! idx))
      in
        -- Check for surrogate pair (code points > U+FFFF)
        if c >= 0xD800 && c <= 0xDBFF then
          let
            lo = fromMaybe 0 (map fromEnum (chars !! (idx + 1)))
            cp = (c - 0xD800) * 0x400 + (lo - 0xDC00) + 0x10000
          in
            encodeChars chars (idx + 2) len (acc <> encodeCodePoint cp)
        else
          encodeChars chars (idx + 1) len (acc <> encodeCodePoint c)

-- | Encode a single Unicode code point as 1–4 UTF-8 bytes.
encodeCodePoint :: Int -> Bytes
encodeCodePoint cp
  | cp < 0x80 =
      [ cp ]
  | cp < 0x800 =
      [ 0xC0 .|. (cp `zshr` 6)
      , 0x80 .|. (cp .&. 0x3F)
      ]
  | cp < 0x10000 =
      [ 0xE0 .|. (cp `zshr` 12)
      , 0x80 .|. ((cp `zshr` 6) .&. 0x3F)
      , 0x80 .|. (cp .&. 0x3F)
      ]
  | otherwise =
      [ 0xF0 .|. (cp `zshr` 18)
      , 0x80 .|. ((cp `zshr` 12) .&. 0x3F)
      , 0x80 .|. ((cp `zshr` 6) .&. 0x3F)
      , 0x80 .|. (cp .&. 0x3F)
      ]