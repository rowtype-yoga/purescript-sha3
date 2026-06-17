module Probe where

import Prelude
import Effect (Effect)
import Effect.Console (log)

foreign import nowMs :: Effect Number

main :: Effect Unit
main = do
  a <- nowMs
  b <- nowMs
  log (show (b - a))