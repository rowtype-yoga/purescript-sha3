module Test.Main where

import Prelude

import Crypto.SHA3 (fromString, sha3_256, sha3_512, shake128, shake256, toHex)
import Effect (Effect)
import Effect.Console (log)
import Partial.Unsafe (unsafeCrashWith)

check :: String -> String -> String -> Effect Unit
check name actual expected =
  if actual == expected then log ("PASS " <> name)
  else unsafeCrashWith
    ("FAIL " <> name <> "\n  got      " <> actual <> "\n  expected " <> expected)

main :: Effect Unit
main = do
  check "sha3-256(\"\")"
    (toHex (sha3_256 (fromString "")))
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
  check "sha3-256(\"abc\")"
    (toHex (sha3_256 (fromString "abc")))
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
  check "sha3-512(\"\")"
    (toHex (sha3_512 (fromString "")))
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
  check "shake128(\"\", 32)"
    (toHex (shake128 32 (fromString "")))
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
  check "shake256(\"\", 32)"
    (toHex (shake256 32 (fromString "")))
    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
  log "all PureScript-level vectors pass"
