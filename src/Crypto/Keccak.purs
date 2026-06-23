module Crypto.SHA3.Keccak
  ( State
  , clearState
  , getLane
  , setLane
  , keccakF
  ) where

import Prelude

import Data.Int.Bits (shl, (.|.))
import Wasm.Array (unsafeIndex) as WA
import Wasm.Int64 (Int64)
import Wasm.Int64 as I
import Wasm.I64Array (I64Array)
import Wasm.I64Array as IA

-- | A 25-lane PACKED `(array (mut i64))`. Lane (x,y) is at x + 5y. Unlike the old
-- | `Array Int64` (the universal `$Vals`, an `(array (mut eqref))` of boxed `$Int64`
-- | structs), the lanes here are raw `i64`: `getLane`/`setLane` lower to a plain
-- | `array.get`/`array.set` of an `i64`, and a round is allocation-free (no per-lane
-- | `struct.new $Int64`, no `ref.cast`, no unbox before each `i64.*`).
type State = I64Array

ix :: State -> Int -> Int64
ix = IA.unsafeIndex

st :: State -> Int -> Int64 -> State
st = IA.unsafeSet

xr :: Int64 -> Int64 -> Int64
xr = I.xor

nd :: Int64 -> Int64 -> Int64
nd = I.and

cmpl :: Int64 -> Int64
cmpl = I.complement

rot :: Int64 -> Int -> Int64
rot x n = I.rotl x (I.lowBits n)

rl1 :: Int64 -> Int64
rl1 x = I.rotl x (I.lowBits 1)

-- | Zero all 25 lanes. `IA.unsafeNew` already zero-initialises, so this is only needed
-- | if a buffer is reused; kept for sponge-entry parity.
clearState :: State -> State
clearState s = go 0 s
  where
  go i acc
    | i < 25 = go (i + 1) (st acc i (I.lowBits 0))
    | otherwise = acc

getLane :: State -> Int -> Int64
getLane = ix

setLane :: State -> Int -> Int64 -> State
setLane = st

hb :: Int
hb = shl 1 31

rcLo :: Array Int
rcLo =
  [ 1, 0x8082, 0x808A, hb .|. 0x8000, 0x808B, hb .|. 0x1
  , hb .|. 0x8081, 0x8009, 0x8A, 0x88, hb .|. 0x8009, hb .|. 0xA
  , hb .|. 0x808B, 0x8B, 0x8089, 0x8003, 0x8002, 0x80
  , 0x800A, hb .|. 0xA, hb .|. 0x8081, 0x8080, hb .|. 0x1, hb .|. 0x8008
  ]

rcHi :: Array Int
rcHi =
  [ 0, 0, hb, hb, 0, 0, hb, hb, 0, 0, 0, 0
  , 0, hb, hb, hb, hb, hb, 0, hb, hb, hb, 0, hb
  ]

loMask :: Int64
loMask = I.zshr (I.lowBits (-1)) (I.lowBits 32)

rcAt :: Int -> Int64
rcAt r =
  I.shl (I.lowBits (WA.unsafeIndex rcHi r)) (I.lowBits 32)
    `I.or` (I.lowBits (WA.unsafeIndex rcLo r) `I.and` loMask)

-- | One fully-unrolled round, out-of-place: reads ONLY `inp`, writes ONLY `out`
-- | (the two are always distinct buffers), so no read can observe a lane this round
-- | already wrote, regardless of how the optimiser schedules the bindings. theta is
-- | computed into the `d` locals, then rho+pi+chi are fused per output row (the five
-- | `rNbK` are that row's permuted, rotated, theta-applied lanes), and iota folds the
-- | round constant into lane 0. No `mod`/`div` and no inner allocation; every index
-- | is a constant, which lets the engine drop the array bounds checks.
roundInto :: Int -> State -> State -> State
roundInto rnd inp out =
  let
    -- theta column parities + D (reads inp only)
    c0 = ix inp 0 `xr` ix inp 5 `xr` ix inp 10 `xr` ix inp 15 `xr` ix inp 20
    c1 = ix inp 1 `xr` ix inp 6 `xr` ix inp 11 `xr` ix inp 16 `xr` ix inp 21
    c2 = ix inp 2 `xr` ix inp 7 `xr` ix inp 12 `xr` ix inp 17 `xr` ix inp 22
    c3 = ix inp 3 `xr` ix inp 8 `xr` ix inp 13 `xr` ix inp 18 `xr` ix inp 23
    c4 = ix inp 4 `xr` ix inp 9 `xr` ix inp 14 `xr` ix inp 19 `xr` ix inp 24
    d0 = c4 `xr` rl1 c1
    d1 = c0 `xr` rl1 c2
    d2 = c1 `xr` rl1 c3
    d3 = c2 `xr` rl1 c4
    d4 = c3 `xr` rl1 c0
    -- per-row fused rho+pi+chi (read inp+d, write out); no read/write aliasing
    r0b0 = (ix inp 0 `xr` d0)
    r0b1 = rot (ix inp 6 `xr` d1) 44
    r0b2 = rot (ix inp 12 `xr` d2) 43
    r0b3 = rot (ix inp 18 `xr` d3) 21
    r0b4 = rot (ix inp 24 `xr` d4) 14
    o0 = st out 0 ((r0b0 `xr` (cmpl r0b1 `nd` r0b2)) `xr` rcAt rnd)
    o1 = st o0 1 (r0b1 `xr` (cmpl r0b2 `nd` r0b3))
    o2 = st o1 2 (r0b2 `xr` (cmpl r0b3 `nd` r0b4))
    o3 = st o2 3 (r0b3 `xr` (cmpl r0b4 `nd` r0b0))
    o4 = st o3 4 (r0b4 `xr` (cmpl r0b0 `nd` r0b1))
    r1b0 = rot (ix inp 3 `xr` d3) 28
    r1b1 = rot (ix inp 9 `xr` d4) 20
    r1b2 = rot (ix inp 10 `xr` d0) 3
    r1b3 = rot (ix inp 16 `xr` d1) 45
    r1b4 = rot (ix inp 22 `xr` d2) 61
    o5 = st o4 5 (r1b0 `xr` (cmpl r1b1 `nd` r1b2))
    o6 = st o5 6 (r1b1 `xr` (cmpl r1b2 `nd` r1b3))
    o7 = st o6 7 (r1b2 `xr` (cmpl r1b3 `nd` r1b4))
    o8 = st o7 8 (r1b3 `xr` (cmpl r1b4 `nd` r1b0))
    o9 = st o8 9 (r1b4 `xr` (cmpl r1b0 `nd` r1b1))
    r2b0 = rot (ix inp 1 `xr` d1) 1
    r2b1 = rot (ix inp 7 `xr` d2) 6
    r2b2 = rot (ix inp 13 `xr` d3) 25
    r2b3 = rot (ix inp 19 `xr` d4) 8
    r2b4 = rot (ix inp 20 `xr` d0) 18
    o10 = st o9 10 (r2b0 `xr` (cmpl r2b1 `nd` r2b2))
    o11 = st o10 11 (r2b1 `xr` (cmpl r2b2 `nd` r2b3))
    o12 = st o11 12 (r2b2 `xr` (cmpl r2b3 `nd` r2b4))
    o13 = st o12 13 (r2b3 `xr` (cmpl r2b4 `nd` r2b0))
    o14 = st o13 14 (r2b4 `xr` (cmpl r2b0 `nd` r2b1))
    r3b0 = rot (ix inp 4 `xr` d4) 27
    r3b1 = rot (ix inp 5 `xr` d0) 36
    r3b2 = rot (ix inp 11 `xr` d1) 10
    r3b3 = rot (ix inp 17 `xr` d2) 15
    r3b4 = rot (ix inp 23 `xr` d3) 56
    o15 = st o14 15 (r3b0 `xr` (cmpl r3b1 `nd` r3b2))
    o16 = st o15 16 (r3b1 `xr` (cmpl r3b2 `nd` r3b3))
    o17 = st o16 17 (r3b2 `xr` (cmpl r3b3 `nd` r3b4))
    o18 = st o17 18 (r3b3 `xr` (cmpl r3b4 `nd` r3b0))
    o19 = st o18 19 (r3b4 `xr` (cmpl r3b0 `nd` r3b1))
    r4b0 = rot (ix inp 2 `xr` d2) 62
    r4b1 = rot (ix inp 8 `xr` d3) 55
    r4b2 = rot (ix inp 14 `xr` d4) 39
    r4b3 = rot (ix inp 15 `xr` d0) 41
    r4b4 = rot (ix inp 21 `xr` d1) 2
    o20 = st o19 20 (r4b0 `xr` (cmpl r4b1 `nd` r4b2))
    o21 = st o20 21 (r4b1 `xr` (cmpl r4b2 `nd` r4b3))
    o22 = st o21 22 (r4b2 `xr` (cmpl r4b3 `nd` r4b4))
    o23 = st o22 23 (r4b3 `xr` (cmpl r4b4 `nd` r4b0))
    o24 = st o23 24 (r4b4 `xr` (cmpl r4b0 `nd` r4b1))
  in o24

-- | Keccak-f[1600]: 24 rounds, ping-ponging between the caller's buffer and one
-- | scratch buffer (allocated once). Each round writes every lane of its output, so
-- | the scratch needs no initialisation. 24 is even, so the result lands back in the
-- | caller's original buffer `a`, preserving its identity for the sponge.
keccakF :: State -> State
keccakF a = go 0 a (IA.unsafeNew 25)
  where
  go rnd inp out
    | rnd < 24 = go (rnd + 1) (roundInto rnd inp out) inp
    | otherwise = inp