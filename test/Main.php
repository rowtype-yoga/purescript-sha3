<?php

// Test.Main — phpurs FFI

$exports = [];

$exports['hasBenchFlag'] = \getenv('BENCH') !== false;

return $exports;