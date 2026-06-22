module Crypto.SHA3.Keccak
  ( State
  , clearState
  , getLane
  , setLane
  , keccakF
  ) where

import Prelude

import Data.Int.Bits (shl, (.|.))
import Wasm.Array (unsafeIndex, unsafeNew, unsafeSet) as WA
import Wasm.Int64 (Int64)
import Wasm.Int64 as I

-- A 25-element MUTABLE wasm array of native i64 lanes. Lane (x,y) lives at the
-- linear index x + 5y. `setLane`/`clearState` mutate in place and return the same
-- buffer, threaded by the caller so the write stays live and ordered by the data
-- dependency (no Effect needed). Each lane is one 64-bit word: one `i64.*`
-- instruction per op, in particular `Wasm.Int64.rotl` (a single `i64.rotl`) for
-- the rho step, replacing the old (lo, hi) i32-pair emulation.
type State = Array Int64

i64zero :: Int64
i64zero = I.fromInt 0

i64one :: Int64
i64one = I.fromInt 1

-- Zero all 25 lanes of an already-allocated buffer (`unsafeNew` leaves them null;
-- reading before a write traps). Used on the sponge's working state at hash entry.
clearState :: State -> State
clearState s = go 0 s
  where
  go i acc
    | i < 25 = go (i + 1) (WA.unsafeSet acc i i64zero)
    | otherwise = acc

-- Lane access by linear index l = x + 5y (0 <= l < 25). The sponge addresses
-- lanes linearly too, so there is no (x, y) <-> index arithmetic on this path.
getLane :: State -> Int -> Int64
getLane = WA.unsafeIndex

setLane :: State -> Int -> Int64 -> State
setLane = WA.unsafeSet

-- The 24 round constants, kept as their original 32-bit halves (the exact values
-- the i32-pair version used, so already validated) and assembled into a full i64
-- on demand. `fromInt` sign-extends, so the low half is masked to 32 bits before
-- the high half is shifted in.
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
loMask = I.zshr (I.fromInt (-1)) (I.fromInt 32) -- 0x00000000FFFFFFFF

rcAt :: Int -> Int64
rcAt r =
  I.shl (I.fromInt (WA.unsafeIndex rcHi r)) (I.fromInt 32)
    `I.or` (I.fromInt (WA.unsafeIndex rcLo r) `I.and` loMask)

rhoOffsets :: Array Int
rhoOffsets =
  [ 0, 1, 62, 28, 27
  , 36, 44, 6, 55, 20
  , 3, 10, 43, 25, 39
  , 41, 45, 15, 21, 8
  , 18, 2, 61, 56, 14
  ]

-- theta: column parities into a separate 5-lane buffer (a distinct `unsafeNew`
-- size, so it never aliases the 25-lane state), fully computed from the original
-- state BEFORE any lane is mutated, which is what makes the in-place update sound.
column :: State -> Int -> Int64
column a x =
  WA.unsafeIndex a x
    `I.xor` WA.unsafeIndex a (x + 5)
    `I.xor` WA.unsafeIndex a (x + 10)
    `I.xor` WA.unsafeIndex a (x + 15)
    `I.xor` WA.unsafeIndex a (x + 20)

theta :: State -> State
theta a = applyD a (computeD a (WA.unsafeNew 5) 0) 0

computeD :: State -> State -> Int -> State
computeD a d x
  | x < 5 =
      let
        xm = (x + 4) `mod` 5
        xp = (x + 1) `mod` 5
        dx = column a xm `I.xor` I.rotl (column a xp) i64one
      in
        computeD a (WA.unsafeSet d x dx) (x + 1)
  | otherwise = d

applyD :: State -> State -> Int -> State
applyD a d l
  | l < 25 =
      let
        x = l `mod` 5
        al = WA.unsafeIndex a l `I.xor` WA.unsafeIndex d x
      in
        applyD (WA.unsafeSet a l al) d (l + 1)
  | otherwise = a

-- rho + pi: read src lane l, rotate left by rho(l), write to the permuted lane in
-- dst (a different buffer from src). rho(x, y) is indexed by x + 5y, which is l.
rhoPi :: State -> State -> State
rhoPi src dst = go 0 dst
  where
  go l acc
    | l < 25 =
        let
          x = l `mod` 5
          y = l / 5
          dl = y + 5 * ((2 * x + 3 * y) `mod` 5)
          rotated = I.rotl (WA.unsafeIndex src l) (I.fromInt (WA.unsafeIndex rhoOffsets l))
        in
          go (l + 1) (WA.unsafeSet acc dl rotated)
    | otherwise = acc

-- chi: out[l] = src[l] XOR ((NOT src[l1]) AND src[l2]); reads src, writes dst.
chi :: State -> State -> State
chi src dst = go 0 dst
  where
  go l acc
    | l < 25 =
        let
          x = l `mod` 5
          y = l / 5
          l1 = ((x + 1) `mod` 5) + 5 * y
          l2 = ((x + 2) `mod` 5) + 5 * y
          out = WA.unsafeIndex src l
                  `I.xor` (I.complement (WA.unsafeIndex src l1) `I.and` WA.unsafeIndex src l2)
        in
          go (l + 1) (WA.unsafeSet acc l out)
    | otherwise = acc

iota :: Int -> State -> State
iota r a = WA.unsafeSet a 0 (WA.unsafeIndex a 0 `I.xor` rcAt r)

keccakRound :: State -> Int -> State -> State
keccakRound scratch r a =
  let
    a1 = theta a
    b1 = rhoPi a1 scratch
    a2 = chi b1 a1
  in
    iota r a2

-- One scratch buffer, allocated once and threaded through all 24 rounds. It is a
-- DISTINCT `unsafeNew` site from the caller's state buffer, so `a` and `scratch`
-- are always different memory (the probe confirms distinct sites do not merge,
-- even at the same length).
keccakF :: State -> State
keccakF a = go 0 a (WA.unsafeNew 25)
  where
  go r st scratch
    | r < 24 = go (r + 1) (keccakRound scratch r st) scratch
    | otherwise = st