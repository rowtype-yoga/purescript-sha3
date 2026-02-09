-- | Test suite for Crypto.SHA3 against NIST FIPS 202 test vectors.
-- |
-- | Run with: spago test
-- | (Assuming this module is wired as the test entry point)
module Test.Crypto.SHA3 where

import Prelude

import Crypto.SHA3 (sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256, toHex, fromHex, fromUtf8)
import Data.Array as A
import Data.Foldable (for_)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Console (log)

type TestCase =
  { name :: String
  , result :: String
  , expected :: String
  }

runTests :: Array TestCase -> Effect Unit
runTests tests = do
  let
    results = map
      ( \t ->
          { name: t.name
          , passed: t.result == t.expected
          , result: t.result
          , expected: t.expected
          }
      )
      tests
    passed = A.length (A.filter _.passed results)
    failed = A.length (A.filter (not <<< _.passed) results)

  for_ results \r ->
    if r.passed then log ("  ✓ " <> r.name)
    else do
      log ("  ✗ " <> r.name)
      log ("    expected: " <> r.expected)
      log ("    got:      " <> r.result)

  log ""
  log (show passed <> " passed, " <> show failed <> " failed")

main :: Effect Unit
main = do
  log "SHA-3 (FIPS 202) Test Suite\n"
  runTests
    -- SHA3-224
    [ { name: "SHA3-224(\"\")"
      , result: toHex (sha3_224 [])
      , expected: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
      }
    , { name: "SHA3-224(\"abc\")"
      , result: toHex (sha3_224 (fromUtf8 "abc"))
      , expected: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
      }
    -- SHA3-256
    , { name: "SHA3-256(\"\")"
      , result: toHex (sha3_256 [])
      , expected: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
      }
    , { name: "SHA3-256(\"abc\")"
      , result: toHex (sha3_256 (fromUtf8 "abc"))
      , expected: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
      }
    , { name: "SHA3-256(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\")"
      , result: toHex (sha3_256 (fromUtf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
      , expected: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
      }
    -- SHA3-384
    , { name: "SHA3-384(\"\")"
      , result: toHex (sha3_384 [])
      , expected: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
      }
    , { name: "SHA3-384(\"abc\")"
      , result: toHex (sha3_384 (fromUtf8 "abc"))
      , expected: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
      }
    -- SHA3-512
    , { name: "SHA3-512(\"\")"
      , result: toHex (sha3_512 [])
      , expected: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
      }
    , { name: "SHA3-512(\"abc\")"
      , result: toHex (sha3_512 (fromUtf8 "abc"))
      , expected: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
      }
    -- SHAKE128
    , { name: "SHAKE128(\"\", 32 bytes)"
      , result: toHex (shake128 32 [])
      , expected: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
      }
    , { name: "SHAKE128(\"abc\", 32 bytes)"
      , result: toHex (shake128 32 (fromUtf8 "abc"))
      , expected: "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
      }
    -- SHAKE256
    , { name: "SHAKE256(\"\", 64 bytes)"
      , result: toHex (shake256 64 [])
      , expected: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
      }
    -- Multi-block test (200 bytes > rate of 136 for SHA3-256)
    , { name: "SHA3-256(200 × 0xA3)"
      , result: toHex (sha3_256 (A.replicate 200 0xA3))
      , expected: "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"
      }
    -- Hex roundtrip
    , { name: "fromHex(toHex(sha3_256([]))) roundtrip"
      , result: show (fromHex (toHex (sha3_256 [])))
      , expected: show (Just (sha3_256 []))
      }
    ]