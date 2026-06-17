module Main where

import Prelude

import Crypto.SHA3 (Bytes(..), fromUtf8, sha3_224, sha3_256, sha3_384, sha3_512, toHex)
import Effect (Effect)
import Effect.Console (log)
import Wasm.String (unsafeNew, unsafeSetByte) as WS

main :: Effect Unit
main = do
  check "SHA3-224(\"\")" (toHex (sha3_224 (fromUtf8 "")))
    "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
  check "SHA3-224(\"abc\")" (toHex (sha3_224 (fromUtf8 "abc")))
    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
  check "SHA3-256(\"\")" (toHex (sha3_256 (fromUtf8 "")))
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
  check "SHA3-256(\"abc\")" (toHex (sha3_256 (fromUtf8 "abc")))
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
  check "SHA3-256(multi-block)"
    (toHex (sha3_256 (fromUtf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
    "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
  check "SHA3-256(200 x 0xA3)" (toHex (sha3_256 (repeatByte 200 0xA3)))
    "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"
  check "SHA3-384(\"\")" (toHex (sha3_384 (fromUtf8 "")))
    "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
  check "SHA3-384(\"abc\")" (toHex (sha3_384 (fromUtf8 "abc")))
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
  check "SHA3-512(\"\")" (toHex (sha3_512 (fromUtf8 "")))
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
  check "SHA3-512(\"abc\")" (toHex (sha3_512 (fromUtf8 "abc")))
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
  where
  check label got want =
    log (label <> ": " <> (if got == want then "OK" else "FAIL\n  got=" <> got))

-- An n-byte input, every byte = v, built directly in a wasm byte buffer.
repeatByte :: Int -> Int -> Bytes
repeatByte n v = Bytes (go 0 (WS.unsafeNew n))
  where
  go i acc
    | i < n = go (i + 1) (WS.unsafeSetByte acc i v)
    | otherwise = acc