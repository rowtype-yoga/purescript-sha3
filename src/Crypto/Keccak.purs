-- | Internal Keccak-f[1600] permutation and sponge construction.
-- |
-- | This module implements the core algorithms from NIST FIPS 202.
-- | It is not intended for direct use — see `Crypto.SHA3` for the public API.
module Crypto.SHA3.Keccak
  ( sponge
  , keccakF1600
  ) where

import Prelude

import Data.Array as A
import Data.Array ((!!))
import Data.Foldable (foldl)
import Data.Int.Bits (shl, zshr, xor, (.&.), (.|.), complement)
import Data.Maybe (fromMaybe)

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

type Bytes = Array Int

-- | A 64-bit lane, split into two 32-bit halves (lo = bits 0–31, hi = 32–63).
type Lane = { hi :: Int, lo :: Int }

-- | The Keccak state: 25 lanes indexed by (x + 5*y).
type State = Array Lane

-------------------------------------------------------------------------------
-- Lane Operations
-------------------------------------------------------------------------------

zeroLane :: Lane
zeroLane = { hi: 0, lo: 0 }

xorLane :: Lane -> Lane -> Lane
xorLane a b = { hi: xor a.hi b.hi, lo: xor a.lo b.lo }

andLane :: Lane -> Lane -> Lane
andLane a b = { hi: a.hi .&. b.hi, lo: a.lo .&. b.lo }

complementLane :: Lane -> Lane
complementLane a = { hi: complement a.hi, lo: complement a.lo }

rotL :: Lane -> Int -> Lane
rotL lane n
  | n == 0 = lane
  | n == 32 = { hi: lane.lo, lo: lane.hi }
  | n < 32 =
      { hi: (lane.hi `shl` n) .|. (lane.lo `zshr` (32 - n))
      , lo: (lane.lo `shl` n) .|. (lane.hi `zshr` (32 - n))
      }
  | otherwise =
      let m = n - 32
      in { hi: (lane.lo `shl` m) .|. (lane.hi `zshr` (32 - m))
         , lo: (lane.hi `shl` m) .|. (lane.lo `zshr` (32 - m))
         }

-------------------------------------------------------------------------------
-- State Helpers
-------------------------------------------------------------------------------

at :: State -> Int -> Int -> Lane
at st x y = fromMaybe zeroLane (st !! (x + 5 * y))

stateFromFn :: (Int -> Int -> Lane) -> State
stateFromFn f = do
  y <- A.range 0 4
  x <- A.range 0 4
  pure (f x y)

emptyState :: State
emptyState = A.replicate 25 zeroLane

-------------------------------------------------------------------------------
-- Byte ↔ Lane (Little-Endian, per FIPS 202 §3.1.2)
-------------------------------------------------------------------------------

bytesToLane :: Bytes -> Int -> Lane
bytesToLane bytes offset =
  let
    b :: Int -> Int
    b i = fromMaybe 0 (bytes !! (offset + i))
  in
    { lo: b 0 .|. (b 1 `shl` 8) .|. (b 2 `shl` 16) .|. (b 3 `shl` 24)
    , hi: b 4 .|. (b 5 `shl` 8) .|. (b 6 `shl` 16) .|. (b 7 `shl` 24)
    }

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
-- State ↔ Bytes
-------------------------------------------------------------------------------

xorBytesIntoState :: Bytes -> Int -> State -> State
xorBytesIntoState block rateBytes st =
  let numLanes = rateBytes / 8
  in A.mapWithIndex
      ( \i lane ->
          if i < numLanes then xorLane lane (bytesToLane block (i * 8))
          else lane
      )
      st

extractBytes :: Int -> State -> Bytes
extractBytes rateBytes st =
  let numLanes = rateBytes / 8
  in A.take rateBytes (A.concatMap laneToBytes (A.take numLanes st))

-------------------------------------------------------------------------------
-- Round Constants (FIPS 202 §3.2.5)
-------------------------------------------------------------------------------

b31 :: Int
b31 = 1 `shl` 31

roundConstants :: Array Lane
roundConstants =
  [ { hi: 0, lo: 1 }
  , { hi: 0, lo: 0x8082 }
  , { hi: b31, lo: 0x808A }
  , { hi: b31, lo: b31 .|. 0x8000 }
  , { hi: 0, lo: 0x808B }
  , { hi: 0, lo: b31 .|. 1 }
  , { hi: b31, lo: b31 .|. 0x8081 }
  , { hi: b31, lo: 0x8009 }
  , { hi: 0, lo: 0x8A }
  , { hi: 0, lo: 0x88 }
  , { hi: 0, lo: b31 .|. 0x8009 }
  , { hi: 0, lo: b31 .|. 0x0A }
  , { hi: 0, lo: b31 .|. 0x808B }
  , { hi: b31, lo: 0x8B }
  , { hi: b31, lo: 0x8089 }
  , { hi: b31, lo: 0x8003 }
  , { hi: b31, lo: 0x8002 }
  , { hi: b31, lo: 0x80 }
  , { hi: 0, lo: 0x800A }
  , { hi: b31, lo: b31 .|. 0x0A }
  , { hi: b31, lo: b31 .|. 0x8081 }
  , { hi: b31, lo: 0x8080 }
  , { hi: 0, lo: b31 .|. 1 }
  , { hi: b31, lo: b31 .|. 0x8008 }
  ]

-------------------------------------------------------------------------------
-- ρ Offsets (FIPS 202 §3.2.2, Table 2)
-------------------------------------------------------------------------------

rhoOffsets :: Array Int
rhoOffsets =
  [  0,  1, 62, 28, 27
  , 36, 44,  6, 55, 20
  ,  3, 10, 43, 25, 39
  , 41, 45, 15, 21,  8
  , 18,  2, 61, 56, 14
  ]

-------------------------------------------------------------------------------
-- Step Mappings (FIPS 202 §3.2)
-------------------------------------------------------------------------------

theta :: State -> State
theta st =
  let
    c :: Int -> Lane
    c x = at st x 0 `xorLane` at st x 1 `xorLane` at st x 2
           `xorLane` at st x 3 `xorLane` at st x 4

    cArr = [ c 0, c 1, c 2, c 3, c 4 ]

    cAt :: Int -> Lane
    cAt i = fromMaybe zeroLane (cArr !! i)

    d :: Int -> Lane
    d x = cAt ((x + 4) `mod` 5) `xorLane` rotL (cAt ((x + 1) `mod` 5)) 1

    dArr = [ d 0, d 1, d 2, d 3, d 4 ]

    dAt :: Int -> Lane
    dAt i = fromMaybe zeroLane (dArr !! i)
  in
    stateFromFn (\x y -> at st x y `xorLane` dAt x)

rho :: State -> State
rho st =
  A.mapWithIndex
    (\i lane -> rotL lane (fromMaybe 0 (rhoOffsets !! i)))
    st

pi :: State -> State
pi st = stateFromFn (\x y -> at st ((x + 3 * y) `mod` 5) x)

chi :: State -> State
chi st = stateFromFn \x y ->
  at st x y `xorLane`
    (complementLane (at st ((x + 1) `mod` 5) y)
      `andLane` at st ((x + 2) `mod` 5) y)

iota :: Int -> State -> State
iota ir st =
  let
    rc = fromMaybe zeroLane (roundConstants !! ir)
    lane0 = fromMaybe zeroLane (st !! 0)
  in
    fromMaybe st (A.updateAt 0 (xorLane lane0 rc) st)

-------------------------------------------------------------------------------
-- Keccak-f[1600] (FIPS 202 §3.3)
-------------------------------------------------------------------------------

round :: Int -> State -> State
round ir = iota ir <<< chi <<< pi <<< rho <<< theta

keccakF1600 :: State -> State
keccakF1600 st = foldl (\s ir -> round ir s) st (A.range 0 23)

-------------------------------------------------------------------------------
-- Padding: pad10*1 (FIPS 202 §5.1)
-------------------------------------------------------------------------------

padMessage :: Int -> Int -> Bytes -> Bytes
padMessage suffixByte rateBytes message =
  let
    msgLen = A.length message
    q = rateBytes - (msgLen `mod` rateBytes)
  in
    if q == 1 then
      message <> [ suffixByte .|. 0x80 ]
    else
      message <> [ suffixByte ] <> A.replicate (q - 2) 0 <> [ 0x80 ]

-------------------------------------------------------------------------------
-- Sponge (FIPS 202 §4)
-------------------------------------------------------------------------------

sponge :: Int -> Int -> Int -> Bytes -> Bytes
sponge rateBytes suffixByte outputBytes message =
  let
    padded = padMessage suffixByte rateBytes message
    numBlocks = A.length padded / rateBytes

    absorb :: State -> Int -> State
    absorb st blockIdx =
      let
        block = A.slice (blockIdx * rateBytes) ((blockIdx + 1) * rateBytes) padded
        xored = xorBytesIntoState block rateBytes st
      in
        keccakF1600 xored

    absorbed = foldl absorb emptyState (A.range 0 (numBlocks - 1))

    initialSqueeze = { out: extractBytes rateBytes absorbed, st: absorbed }

    squeezed = squeezeLoop outputBytes rateBytes initialSqueeze
  in
    A.take outputBytes squeezed.out

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