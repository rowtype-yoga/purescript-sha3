<?php

// Crypto.Keccak — phpurs FFI (native PHP backend)
//
// Keccak-f[1600] permutation and sponge construction, FIPS 202.
//
// Performance notes (PHP-specific):
//   * PHP ints are native signed 64-bit with well-defined wrapping shifts,
//     so each lane is a single int (no hi/lo 32-bit splitting as on JS).
//   * PHP `>>` is arithmetic (sign-extending); every rotation masks the
//     shifted-in sign bits with a precomputed literal.
//   * The 24-round permutation is fully unrolled over 25 local variables.
//     Locals compile to fixed VM slots; array reads/writes go through the
//     hashtable machinery and are far slower, so the hot loop touches none.
//   * Lane (de)serialization uses pack/unpack with the 'P' format
//     (little-endian uint64) — C speed instead of per-byte PHP loops.
//   * Best run with OPcache + JIT:
//       php -d opcache.enable_cli=1 -d opcache.jit=tracing \
//           -d opcache.jit_buffer_size=64M ...

if (PHP_INT_SIZE !== 8) {
    throw new \RuntimeException('Crypto.Keccak requires 64-bit PHP.');
}

if (!function_exists('phpurs_sha3_keccakf')) {

    /**
     * Keccak-f[1600] on a 25-lane state (mutated in place).
     * State layout: lane (x, y) at index x + 5*y.
     */
    function phpurs_sha3_keccakf(array &$s): void
    {
        static $RC = [
            0x0000000000000001, 0x0000000000008082,
            (1 << 63) | 0x000000000000808A, (1 << 63) | 0x0000000080008000,
            0x000000000000808B, 0x0000000080000001,
            (1 << 63) | 0x0000000080008081, (1 << 63) | 0x0000000000008009,
            0x000000000000008A, 0x0000000000000088,
            0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, (1 << 63) | 0x000000000000008B,
            (1 << 63) | 0x0000000000008089, (1 << 63) | 0x0000000000008003,
            (1 << 63) | 0x0000000000008002, (1 << 63) | 0x0000000000000080,
            0x000000000000800A, (1 << 63) | 0x000000008000000A,
            (1 << 63) | 0x0000000080008081, (1 << 63) | 0x0000000000008080,
            0x0000000080000001, (1 << 63) | 0x0000000080008008,
        ];

        $a0  = $s[0];  $a1  = $s[1];  $a2  = $s[2];  $a3  = $s[3];  $a4  = $s[4];
        $a5  = $s[5];  $a6  = $s[6];  $a7  = $s[7];  $a8  = $s[8];  $a9  = $s[9];
        $a10 = $s[10]; $a11 = $s[11]; $a12 = $s[12]; $a13 = $s[13]; $a14 = $s[14];
        $a15 = $s[15]; $a16 = $s[16]; $a17 = $s[17]; $a18 = $s[18]; $a19 = $s[19];
        $a20 = $s[20]; $a21 = $s[21]; $a22 = $s[22]; $a23 = $s[23]; $a24 = $s[24];

        for ($round = 0; $round < 24; $round++) {
            $c0 = $a0 ^ $a5 ^ $a10 ^ $a15 ^ $a20;
            $c1 = $a1 ^ $a6 ^ $a11 ^ $a16 ^ $a21;
            $c2 = $a2 ^ $a7 ^ $a12 ^ $a17 ^ $a22;
            $c3 = $a3 ^ $a8 ^ $a13 ^ $a18 ^ $a23;
            $c4 = $a4 ^ $a9 ^ $a14 ^ $a19 ^ $a24;
            $d0 = $c4 ^ (($c1 << 1) | (($c1 >> 63) & 0x1));
            $d1 = $c0 ^ (($c2 << 1) | (($c2 >> 63) & 0x1));
            $d2 = $c1 ^ (($c3 << 1) | (($c3 >> 63) & 0x1));
            $d3 = $c2 ^ (($c4 << 1) | (($c4 >> 63) & 0x1));
            $d4 = $c3 ^ (($c0 << 1) | (($c0 >> 63) & 0x1));
            $a0 ^= $d0;
            $a1 ^= $d1;
            $a2 ^= $d2;
            $a3 ^= $d3;
            $a4 ^= $d4;
            $a5 ^= $d0;
            $a6 ^= $d1;
            $a7 ^= $d2;
            $a8 ^= $d3;
            $a9 ^= $d4;
            $a10 ^= $d0;
            $a11 ^= $d1;
            $a12 ^= $d2;
            $a13 ^= $d3;
            $a14 ^= $d4;
            $a15 ^= $d0;
            $a16 ^= $d1;
            $a17 ^= $d2;
            $a18 ^= $d3;
            $a19 ^= $d4;
            $a20 ^= $d0;
            $a21 ^= $d1;
            $a22 ^= $d2;
            $a23 ^= $d3;
            $a24 ^= $d4;
            $b0 = $a0;
            $b10 = (($a1 << 1) | (($a1 >> 63) & 0x1));
            $b20 = (($a2 << 62) | (($a2 >> 2) & 0x3FFFFFFFFFFFFFFF));
            $b5 = (($a3 << 28) | (($a3 >> 36) & 0xFFFFFFF));
            $b15 = (($a4 << 27) | (($a4 >> 37) & 0x7FFFFFF));
            $b16 = (($a5 << 36) | (($a5 >> 28) & 0xFFFFFFFFF));
            $b1 = (($a6 << 44) | (($a6 >> 20) & 0xFFFFFFFFFFF));
            $b11 = (($a7 << 6) | (($a7 >> 58) & 0x3F));
            $b21 = (($a8 << 55) | (($a8 >> 9) & 0x7FFFFFFFFFFFFF));
            $b6 = (($a9 << 20) | (($a9 >> 44) & 0xFFFFF));
            $b7 = (($a10 << 3) | (($a10 >> 61) & 0x7));
            $b17 = (($a11 << 10) | (($a11 >> 54) & 0x3FF));
            $b2 = (($a12 << 43) | (($a12 >> 21) & 0x7FFFFFFFFFF));
            $b12 = (($a13 << 25) | (($a13 >> 39) & 0x1FFFFFF));
            $b22 = (($a14 << 39) | (($a14 >> 25) & 0x7FFFFFFFFF));
            $b23 = (($a15 << 41) | (($a15 >> 23) & 0x1FFFFFFFFFF));
            $b8 = (($a16 << 45) | (($a16 >> 19) & 0x1FFFFFFFFFFF));
            $b18 = (($a17 << 15) | (($a17 >> 49) & 0x7FFF));
            $b3 = (($a18 << 21) | (($a18 >> 43) & 0x1FFFFF));
            $b13 = (($a19 << 8) | (($a19 >> 56) & 0xFF));
            $b14 = (($a20 << 18) | (($a20 >> 46) & 0x3FFFF));
            $b24 = (($a21 << 2) | (($a21 >> 62) & 0x3));
            $b9 = (($a22 << 61) | (($a22 >> 3) & 0x1FFFFFFFFFFFFFFF));
            $b19 = (($a23 << 56) | (($a23 >> 8) & 0xFFFFFFFFFFFFFF));
            $b4 = (($a24 << 14) | (($a24 >> 50) & 0x3FFF));
            $a0 = $b0 ^ (~$b1 & $b2);
            $a1 = $b1 ^ (~$b2 & $b3);
            $a2 = $b2 ^ (~$b3 & $b4);
            $a3 = $b3 ^ (~$b4 & $b0);
            $a4 = $b4 ^ (~$b0 & $b1);
            $a5 = $b5 ^ (~$b6 & $b7);
            $a6 = $b6 ^ (~$b7 & $b8);
            $a7 = $b7 ^ (~$b8 & $b9);
            $a8 = $b8 ^ (~$b9 & $b5);
            $a9 = $b9 ^ (~$b5 & $b6);
            $a10 = $b10 ^ (~$b11 & $b12);
            $a11 = $b11 ^ (~$b12 & $b13);
            $a12 = $b12 ^ (~$b13 & $b14);
            $a13 = $b13 ^ (~$b14 & $b10);
            $a14 = $b14 ^ (~$b10 & $b11);
            $a15 = $b15 ^ (~$b16 & $b17);
            $a16 = $b16 ^ (~$b17 & $b18);
            $a17 = $b17 ^ (~$b18 & $b19);
            $a18 = $b18 ^ (~$b19 & $b15);
            $a19 = $b19 ^ (~$b15 & $b16);
            $a20 = $b20 ^ (~$b21 & $b22);
            $a21 = $b21 ^ (~$b22 & $b23);
            $a22 = $b22 ^ (~$b23 & $b24);
            $a23 = $b23 ^ (~$b24 & $b20);
            $a24 = $b24 ^ (~$b20 & $b21);
            $a0 ^= $RC[$round];
        }

        $s[0]  = $a0;  $s[1]  = $a1;  $s[2]  = $a2;  $s[3]  = $a3;  $s[4]  = $a4;
        $s[5]  = $a5;  $s[6]  = $a6;  $s[7]  = $a7;  $s[8]  = $a8;  $s[9]  = $a9;
        $s[10] = $a10; $s[11] = $a11; $s[12] = $a12; $s[13] = $a13; $s[14] = $a14;
        $s[15] = $a15; $s[16] = $a16; $s[17] = $a17; $s[18] = $a18; $s[19] = $a19;
        $s[20] = $a20; $s[21] = $a21; $s[22] = $a22; $s[23] = $a23; $s[24] = $a24;
    }

    /**
     * Sponge construction (pad10*1 with domain-separation suffix).
     * Input and output are raw binary strings.
     */
    function phpurs_sha3_sponge(int $rateBytes, int $suffix, int $outBytes, string $input): string
    {
        $laneCount = $rateBytes >> 3;

        // ── Padding ────────────────────────────────────────────────
        $q = $rateBytes - (\strlen($input) % $rateBytes);
        if ($q === 1) {
            $input .= \chr($suffix | 0x80);
        } else {
            $input .= \chr($suffix) . \str_repeat("\0", $q - 2) . \chr(0x80);
        }

        // ── Absorb ─────────────────────────────────────────────────
        // One C-level unpack for the entire padded input (1-indexed).
        $lanes  = \unpack('P*', $input);
        $total  = \count($lanes);
        $s      = \array_fill(0, 25, 0);

        for ($base = 1; $base <= $total; $base += $laneCount) {
            for ($i = 0; $i < $laneCount; $i++) {
                $s[$i] ^= $lanes[$base + $i];
            }
            phpurs_sha3_keccakf($s);
        }

        // ── Squeeze ────────────────────────────────────────────────
        $out = '';
        $have = 0;
        while (true) {
            $take = $outBytes - $have;
            if ($take > $rateBytes) {
                $take = $rateBytes;
            }
            $full = $take >> 3;
            for ($i = 0; $i < $full; $i++) {
                $out .= \pack('P', $s[$i]);
            }
            $rem = $take & 7;
            if ($rem > 0) {
                $out .= \substr(\pack('P', $s[$full]), 0, $rem);
            }
            $have += $take;
            if ($have >= $outBytes) {
                break;
            }
            phpurs_sha3_keccakf($s);
        }
        return $out;
    }
}

// ── FFI exports ─────────────────────────────────────────────────────
// phpurs FFI closures must tolerate both saturated calls f(a,b,c,d) and
// curried chains f(a)(b)(c)(d); the func_num_args() fallback handles both.

$spongeNativeBv = function ($rate, $suffix = null, $out = null, $input = null) use (&$spongeNativeBv) {
    if (\func_num_args() < 4) {
        $__args = \func_get_args();
        return function (...$more) use ($__args, &$spongeNativeBv) {
            return $spongeNativeBv(...\array_merge($__args, $more));
        };
    }
    return phpurs_sha3_sponge($rate, $suffix, $out, $input);
};

$spongeOptimized = function ($rate, $suffix = null, $out = null, $input = null) use (&$spongeOptimized) {
    if (\func_num_args() < 4) {
        $__args = \func_get_args();
        return function (...$more) use ($__args, &$spongeOptimized) {
            return $spongeOptimized(...\array_merge($__args, $more));
        };
    }
    $bytes = $input === [] ? '' : \pack('C*', ...$input);
    $res = phpurs_sha3_sponge($rate, $suffix, $out, $bytes);
    return $res === '' ? [] : \array_values(\unpack('C*', $res));
};

$keccakF1600Optimized = function ($state) {
    $s = \array_values($state);
    phpurs_sha3_keccakf($s);
    return $s;
};

$exports['spongeNativeBv'] = $spongeNativeBv;
$exports['spongeOptimized'] = $spongeOptimized;
$exports['keccakF1600Optimized'] = $keccakF1600Optimized;
return $exports;