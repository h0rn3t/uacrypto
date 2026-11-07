/*
 * Output of cryptonite's DSTU 4145 generator (PRNG_MODE_DSTU) with a fixed
 * clock: the Makefile replaces time(NULL) in dstu4145_prng_internal.c with
 * the variable fake_time. One line per case:
 *
 *   seed time1 out1 data time2 out2
 *
 * seed (40 bytes) is given to prng_alloc at time1, out1 is the next 48 bytes;
 * then prng_seed(data) runs at time2 and out2 is the next 32 bytes. Byte
 * strings are hex, "-" for empty data; times are decimal Unix seconds.
 * dstu4145/prng_test.go reads this table from dstu4145/testdata.
 */
#include <stdint.h>
#include <stdio.h>

#include "byte_array.h"
#include "prng.h"

uint64_t fake_time;

static void hex(const uint8_t *b, size_t n)
{
    if (n == 0) {
        printf("-");
    }
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

/* Deterministic bytes: a 32-bit LCG, so the table needs no randomness. */
static uint32_t lcg = 2463534242u;

static void fill(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        lcg = lcg * 1664525u + 1013904223u;
        b[i] = (uint8_t)(lcg >> 24);
    }
}

int main(void)
{
    static const uint64_t times[][2] = {
        {1700000000, 1700000060},
        {0, 0},
        {1, 4294967296},
        {1234567890, 1234567890},
        {2000000000, 2000000001},
        {1600000000, 1900000000},
        {4102444800, 4102444799},
        {86400, 172800},
    };
    static const size_t data_len[] = {5, 0, 1, 31, 32, 33, 64, 100};

    for (size_t c = 0; c < sizeof(times) / sizeof(times[0]); c++) {
        uint8_t seed[40], data[100], out1[48], out2[32];
        fill(seed, sizeof(seed));
        fill(data, data_len[c]);

        fake_time = times[c][0];
        ByteArray *seed_ba = ba_alloc_from_uint8(seed, sizeof(seed));
        PrngCtx *p = prng_alloc(PRNG_MODE_DSTU, seed_ba);
        ByteArray *o1 = ba_alloc_by_len(sizeof(out1));
        if (p == NULL || prng_next_bytes(p, o1) != 0) {
            fprintf(stderr, "case %zu: first read failed\n", c);
            return 1;
        }

        fake_time = times[c][1];
        ByteArray *data_ba = ba_alloc_from_uint8(data, data_len[c]);
        ByteArray *o2 = ba_alloc_by_len(sizeof(out2));
        if (data_ba == NULL || prng_seed(p, data_ba) != 0 || prng_next_bytes(p, o2) != 0) {
            fprintf(stderr, "case %zu: reseed failed\n", c);
            return 1;
        }

        hex(seed, sizeof(seed));
        printf(" %llu ", (unsigned long long)times[c][0]);
        hex(ba_get_buf(o1), ba_get_len(o1));
        printf(" ");
        hex(data, data_len[c]);
        printf(" %llu ", (unsigned long long)times[c][1]);
        hex(ba_get_buf(o2), ba_get_len(o2));
        printf("\n");

        prng_free(p);
        ba_free(seed_ba);
        ba_free(data_ba);
        ba_free(o1);
        ba_free(o2);
    }
    return 0;
}
