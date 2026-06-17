module Crypto.SHA3.Keccak
  ( State
  , clearState
  , getLo
  , getHi
  , setLo
  , setHi
  , keccakF
  ) where

import Prelude

import Data.Int.Bits (complement, shl, xor, zshr, (.&.), (.|.))
import Wasm.Array (unsafeIndex, unsafeNew, unsafeSet) as WA

-- A 50-element MUTABLE wasm array. Lane (x,y) at 2*(x+5y) (lo) and +1 (hi).
-- Each Int is an i32; nothing masks. `setLo`/`setHi`/`clearState` mutate in
-- place and return the same buffer, threaded by the caller.
type State = Array Int

-- Zero all 50 slots of an already-allocated buffer (unsafeNew leaves them
-- uninitialised). Used on the sponge's working state at hash entry.
clearState :: State -> State
clearState s = go 0 s
  where
  go i acc
    | i < 50 = go (i + 1) (WA.unsafeSet acc i 0)
    | otherwise = acc

loAt :: Int -> Int -> Int
loAt x y = 2 * (x + 5 * y)

hiAt :: Int -> Int -> Int
hiAt x y = 2 * (x + 5 * y) + 1

getLo :: State -> Int -> Int -> Int
getLo a x y = WA.unsafeIndex a (loAt x y)

getHi :: State -> Int -> Int -> Int
getHi a x y = WA.unsafeIndex a (hiAt x y)

setLo :: State -> Int -> Int -> Int -> State
setLo a x y v = WA.unsafeSet a (loAt x y) v

setHi :: State -> Int -> Int -> Int -> State
setHi a x y v = WA.unsafeSet a (hiAt x y) v

-- 64-bit left rotation on a (lo, hi) i32 pair, 0 <= n < 64.
rotlLo :: Int -> Int -> Int -> Int
rotlLo lo hi n
  | n == 0 = lo
  | n < 32 = shl lo n .|. zshr hi (32 - n)
  | n == 32 = hi
  | otherwise = let m = n - 32 in shl hi m .|. zshr lo (32 - m)

rotlHi :: Int -> Int -> Int -> Int
rotlHi lo hi n
  | n == 0 = hi
  | n < 32 = shl hi n .|. zshr lo (32 - n)
  | n == 32 = lo
  | otherwise = let m = n - 32 in shl lo m .|. zshr hi (32 - m)

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

rhoOffsets :: Array Int
rhoOffsets =
  [ 0, 1, 62, 28, 27
  , 36, 44, 6, 55, 20
  , 3, 10, 43, 25, 39
  , 41, 45, 15, 21, 8
  , 18, 2, 61, 56, 14
  ]

rho :: Int -> Int -> Int
rho x y = WA.unsafeIndex rhoOffsets (x + 5 * y)

-- theta: column parities, then add D to every lane. D is computed into its own
-- 10-element buffer (distinct size, so never aliases the state) BEFORE any
-- lane is mutated, which is what makes the in-place update correct.

columnLo :: State -> Int -> Int
columnLo a x = getLo a x 0 `xor` getLo a x 1 `xor` getLo a x 2 `xor` getLo a x 3 `xor` getLo a x 4

columnHi :: State -> Int -> Int
columnHi a x = getHi a x 0 `xor` getHi a x 1 `xor` getHi a x 2 `xor` getHi a x 3 `xor` getHi a x 4

theta :: State -> State
theta a = applyD a (computeD a (WA.unsafeNew 10) 0) 0

computeD :: State -> State -> Int -> State
computeD a d x
  | x < 5 =
      let
        xm = (x + 4) `mod` 5
        xp = (x + 1) `mod` 5
        cpLo = columnLo a xp
        cpHi = columnHi a xp
        dlo = columnLo a xm `xor` rotlLo cpLo cpHi 1
        dhi = columnHi a xm `xor` rotlHi cpLo cpHi 1
        d1 = WA.unsafeSet d (2 * x) dlo
        d2 = WA.unsafeSet d1 (2 * x + 1) dhi
      in
        computeD a d2 (x + 1)
  | otherwise = d

applyD :: State -> State -> Int -> State
applyD a d l
  | l < 25 =
      let
        x = l `mod` 5
        dlo = WA.unsafeIndex d (2 * x)
        dhi = WA.unsafeIndex d (2 * x + 1)
        a1 = WA.unsafeSet a (2 * l) (WA.unsafeIndex a (2 * l) `xor` dlo)
        a2 = WA.unsafeSet a1 (2 * l + 1) (WA.unsafeIndex a1 (2 * l + 1) `xor` dhi)
      in
        applyD a2 d (l + 1)
  | otherwise = a

-- rho + pi: read src lane, rotate, write to the permuted lane in dst (!= src).
rhoPi :: State -> State -> State
rhoPi src dst = go 0 dst
  where
  go l acc
    | l < 25 =
        let
          x = l `mod` 5
          y = l / 5
          n = rho x y
          lo0 = WA.unsafeIndex src (2 * l)
          hi0 = WA.unsafeIndex src (2 * l + 1)
          dl = y + 5 * ((2 * x + 3 * y) `mod` 5)
          acc1 = WA.unsafeSet acc (2 * dl) (rotlLo lo0 hi0 n)
          acc2 = WA.unsafeSet acc1 (2 * dl + 1) (rotlHi lo0 hi0 n)
        in
          go (l + 1) acc2
    | otherwise = acc

-- chi: read src (the post-rho-pi state), write dst (!= src).
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
          lo = WA.unsafeIndex src (2 * l) `xor` (complement (WA.unsafeIndex src (2 * l1)) .&. WA.unsafeIndex src (2 * l2))
          hi = WA.unsafeIndex src (2 * l + 1) `xor` (complement (WA.unsafeIndex src (2 * l1 + 1)) .&. WA.unsafeIndex src (2 * l2 + 1))
          acc1 = WA.unsafeSet acc (2 * l) lo
          acc2 = WA.unsafeSet acc1 (2 * l + 1) hi
        in
          go (l + 1) acc2
    | otherwise = acc

iota :: Int -> State -> State
iota r a =
  let
    a1 = WA.unsafeSet a 0 (WA.unsafeIndex a 0 `xor` WA.unsafeIndex rcLo r)
  in
    WA.unsafeSet a1 1 (WA.unsafeIndex a1 1 `xor` WA.unsafeIndex rcHi r)

keccakRound :: State -> Int -> State -> State
keccakRound scratch r a =
  let
    a1 = theta a
    b1 = rhoPi a1 scratch
    a2 = chi b1 a1
  in
    iota r a2

-- One scratch buffer, allocated once and threaded through all 24 rounds. It is
-- a DISTINCT unsafeNew site from the caller's state buffer (the probe confirms
-- those don't merge), so `a` and `scratch` are always different memory.
keccakF :: State -> State
keccakF a = go 0 a (WA.unsafeNew 50)
  where
  go r st scratch
    | r < 24 = go (r + 1) (keccakRound scratch r st) scratch
    | otherwise = st