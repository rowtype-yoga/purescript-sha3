module Test.SHA3.Bench where

import Prelude

import Crypto.SHA3 (SHA3(..), hash, shake128, shake256)
import Crypto.Keccak as Keccak
import Data.Array as A
import Effect (Effect)
import Effect.Console (log)

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import performanceNow :: Effect Number
foreign import defer :: forall a. (Unit -> a) -> Effect a
foreign import intToNumber :: Int -> Number

-------------------------------------------------------------------------------
-- Timing Helpers
-------------------------------------------------------------------------------

timeN :: Int -> Effect Unit -> Effect Number
timeN n action = do
  t0 <- performanceNow
  go 0
  t1 <- performanceNow
  pure (t1 - t0)
  where
  go i
    | i >= n = pure unit
    | otherwise = action *> go (i + 1)

report :: String -> Int -> Int -> Number -> Effect Unit
report label iterations inputBytes ms = do
  let
    throughputMBs =
      if ms > 0.0 then
        (intToNumber (iterations * inputBytes) / 1048576.0) / (ms / 1000.0)
      else 0.0
    opsPerSec =
      if ms > 0.0 then intToNumber iterations / (ms / 1000.0)
      else 0.0
  log $ "  " <> label
    <> "  " <> show iterations <> " iters"
    <> "  " <> show ms <> " ms"
    <> "  " <> show opsPerSec <> " ops/s"
    <> "  " <> show throughputMBs <> " MB/s"

-------------------------------------------------------------------------------
-- Benchmarks
-------------------------------------------------------------------------------

benchSuite :: Effect Unit
benchSuite = do
  log "═══════════════════════════════════════════════════════════"
  log "  SHA-3 Benchmarks (Chez Scheme / purescm)"
  log "═══════════════════════════════════════════════════════════"

  log "\n── SHA3-256 (small inputs) ─────────────────────────────"
  let iters = 500

  do
    let input = ([] :: Array Int)
    ms <- timeN iters (void $ defer \_ -> hash SHA3_256 input)
    report "empty (0 B)" iters 0 ms

  do
    let input = A.replicate 32 0
    ms <- timeN iters (void $ defer \_ -> hash SHA3_256 input)
    report "32 B       " iters 32 ms

  do
    let input = A.replicate 64 0
    ms <- timeN iters (void $ defer \_ -> hash SHA3_256 input)
    report "64 B       " iters 64 ms

  do
    let input = A.replicate 136 0
    ms <- timeN iters (void $ defer \_ -> hash SHA3_256 input)
    report "136 B (1×r)" iters 136 ms

  log "\n── SHA3-256 (multi-block) ──────────────────────────────"
  let itersM = 100

  do
    let input = A.replicate 512 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA3_256 input)
    report "512 B      " itersM 512 ms

  do
    let input = A.replicate 1024 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA3_256 input)
    report "1 KiB      " itersM 1024 ms

  do
    let input = A.replicate 4096 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA3_256 input)
    report "4 KiB      " itersM 4096 ms

  log "\n── SHA3-256 (large inputs) ─────────────────────────────"
  let itersL = 10

  do
    let input = A.replicate 65536 0
    ms <- timeN itersL (void $ defer \_ -> hash SHA3_256 input)
    report "64 KiB     " itersL 65536 ms

  do
    let input = A.replicate 1048576 0
    ms <- timeN itersL (void $ defer \_ -> hash SHA3_256 input)
    report "1 MiB      " itersL 1048576 ms

  log "\n── All SHA3 variants (256 B input) ─────────────────────"
  let itersV = 200

  do
    let input = A.replicate 256 0
    ms224 <- timeN itersV (void $ defer \_ -> hash SHA3_224 input)
    report "SHA3-224   " itersV 256 ms224
    ms256 <- timeN itersV (void $ defer \_ -> hash SHA3_256 input)
    report "SHA3-256   " itersV 256 ms256
    ms384 <- timeN itersV (void $ defer \_ -> hash SHA3_384 input)
    report "SHA3-384   " itersV 256 ms384
    ms512 <- timeN itersV (void $ defer \_ -> hash SHA3_512 input)
    report "SHA3-512   " itersV 256 ms512

  log "\n── SHAKE XOFs (256 B input) ────────────────────────────"

  do
    let input = A.replicate 256 0
    ms128 <- timeN itersV (void $ defer \_ -> shake128 32 input)
    report "SHAKE128/32" itersV 256 ms128
    ms256 <- timeN itersV (void $ defer \_ -> shake256 64 input)
    report "SHAKE256/64" itersV 256 ms256

  log "\n── Keccak-f[1600] permutation (raw) ────────────────────"
  let itersK = 1000
  do
    let emptyState = A.replicate 25 0
    ms <- timeN itersK (void $ defer \_ -> Keccak.keccakF1600 emptyState)
    report "keccakF1600" itersK 200 ms

  log "\n═══════════════════════════════════════════════════════════"
  log "  Done."
  log "═══════════════════════════════════════════════════════════"