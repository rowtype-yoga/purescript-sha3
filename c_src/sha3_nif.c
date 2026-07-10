/* c_src/sha3_nif.c
 * Keccak-f[1600] + SHA-3/SHAKE sponge, implemented from FIPS 202.
 * Exposed to the BEAM as dirty CPU-bound NIFs.
 */
#include <erl_nif.h>
#include <stdint.h>
#include <string.h>

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* rho rotation offsets and pi lane destinations, per FIPS 202 Sec 3.2 */
static const int RHO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static void keccak_f1600(uint64_t a[25])
{
    uint64_t b[25], c[5], d;
    for (int round = 0; round < 24; round++) {
        /* theta */
        for (int x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++) {
            d = c[(x + 4) % 5] ^ ROTL64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                a[x + y] ^= d;
        }
        /* rho + pi */
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y * 5 + ((2 * x + 3 * y) % 5) * 0 + ((0*x)+0)] = 0; /* placeholder, replaced below */
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++) {
                int src = x + 5 * y;
                int dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = ROTL64(a[src], RHO[src]);
            }
        /* chi */
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
        /* iota */
        a[0] ^= RC[round];
    }
}

/* sponge: absorb `in`, pad with domain sep byte, squeeze `outlen` bytes.
 * rate_bytes: 136 for sha3_256/shake256, 104 for sha3_384, 72 for sha3_512, 168 for shake128 */
static void sponge(const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t outlen,
                   size_t rate, unsigned char ds)
{
    uint64_t st[25];
    unsigned char blk[200];
    memset(st, 0, sizeof st);

    while (inlen >= rate) {
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t lane;
            memcpy(&lane, in + 8 * i, 8);   /* little-endian hosts; fine for x86_64/aarch64 */
            st[i] ^= lane;
        }
        keccak_f1600(st);
        in += rate; inlen -= rate;
    }
    memset(blk, 0, rate);
    memcpy(blk, in, inlen);
    blk[inlen] ^= ds;
    blk[rate - 1] ^= 0x80;
    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t lane;
        memcpy(&lane, blk + 8 * i, 8);
        st[i] ^= lane;
    }
    keccak_f1600(st);

    while (outlen > 0) {
        size_t n = outlen < rate ? outlen : rate;
        memcpy(out, st, n);
        out += n; outlen -= n;
        if (outlen > 0) keccak_f1600(st);
    }
}

/* --- NIF plumbing --- */

static ERL_NIF_TERM hash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary in;
    unsigned int rate, outlen, ds;
    ERL_NIF_TERM out_term;
    unsigned char *out;

    if (argc != 4
        || !enif_inspect_binary(env, argv[0], &in)
        || !enif_get_uint(env, argv[1], &rate)
        || !enif_get_uint(env, argv[2], &outlen)
        || !enif_get_uint(env, argv[3], &ds)
        || rate == 0 || rate > 200 || rate % 8 != 0 || ds > 255)
        return enif_make_badarg(env);

    out = enif_make_new_binary(env, outlen, &out_term);
    sponge(in.data, in.size, out, outlen, rate, (unsigned char)ds);
    return out_term;
}

static ErlNifFunc funcs[] = {
    /* name, arity, fn, flags */
    {"hash", 4, hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(sha3_nif, funcs, NULL, NULL, NULL, NULL)
