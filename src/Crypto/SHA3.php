<?php

// Crypto.SHA3 — phpurs FFI (native PHP backend)
//
// ByteArray is a raw PHP binary string. PHP strings are byte strings, so
// hex encode/decode, equality, and length are single C-level builtins.

$exports = [];

// String -> ByteArray. phpurs Strings are native PHP (UTF-8 byte) strings.
$exports['stringToUtf8Bv'] = function ($s) {
    return $s;
};

// Array Int -> ByteArray. Chunked to keep pack()'s argument
// spread bounded on large inputs.
$exports['arrayToByteArray'] = function ($arr) {
    if ($arr === []) {
        return '';
    }
    if (\count($arr) <= 8192) {
        return \pack('C*', ...$arr);
    }
    $out = '';
    foreach (\array_chunk($arr, 8192) as $chunk) {
        $out .= \pack('C*', ...$chunk);
    }
    return $out;
};

// ByteArray -> Array Int
$exports['byteArrayToArray'] = function ($s) {
    return $s === '' ? [] : \array_values(\unpack('C*', $s));
};

// ByteArray -> String
$exports['bytesToHex'] = function ($s) {
    return \bin2hex($s);
};

// String -> ByteArray. Returns '' on invalid hex (the PureScript side
// maps a zero-length result for non-empty input to Nothing).
$exports['hexToByteArray'] = function ($hex) {
    if ($hex === '' || (\strlen($hex) & 1) !== 0 || !\ctype_xdigit($hex)) {
        return '';
    }
    return \hex2bin($hex);
};

// ByteArray -> ByteArray -> Boolean
$exports['eqByteArray'] = function ($a, $b = null) use (&$exports) {
    if (\func_num_args() < 2) {
        return function ($b) use ($a, &$exports) {
            return $exports['eqByteArray']($a, $b);
        };
    }
    return $a === $b;
};

// ByteArray -> Int
$exports['byteArrayLength'] = function ($s) {
    return \strlen($s);
};

return $exports;