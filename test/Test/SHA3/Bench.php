<?php

// Test.SHA3.Bench — phpurs FFI

$exports = [];

// Effect Number — monotonic clock in milliseconds.
$exports['performanceNow'] = function () {
    return \hrtime(true) / 1e6;
};

// (Unit -> a) -> Effect a — force re-evaluation on each run.
$exports['defer'] = function ($thunk) {
    return function () use ($thunk) {
        return $thunk(null);
    };
};

// Int -> Number
$exports['intToNumber'] = function ($n) {
    return (float) $n;
};

return $exports;