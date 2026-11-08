/*
 * Cross-checks the uacrypto cases against uapkic, the primitives library of
 * UAPKI (https://github.com/specinfo-ua/UAPKI), the certified fork of
 * cryptonite.
 *
 *	check cases.txt uapki_sigs.txt
 *
 * It checks GOST 34.311, Kupyna, GOST 28147 (block, CFB, MAC 32 and 64 bits),
 * Kalyna and DSTU 4145 against the case lines of parity gen, and signs the
 * same hashes with the same keys; the signature lines it writes go to
 * parity verify.
 *
 * uapkic mixes byte orders, as UAPKI's own pkix code shows: dstu4145_get_pubkey
 * takes d little-endian, ec_init_sign takes it big-endian; the compressed key
 * and the coordinates dstu4145_decompress_pubkey returns are little-endian,
 * ec_init_verify takes the coordinates big-endian (uapki-ns-verify.cpp swaps
 * them); the hash goes in as the hash function wrote it, r and s come out
 * little-endian, as IIT writes them. uacrypto writes d, Q, r and s big-endian.
 * dstu4145_sign takes only 32-, 48- and 64-byte hashes; the 1-byte cases are
 * skipped.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte-array.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "dstu7624.h"
#include "ec.h"
#include "gost28147.h"
#include "gost34311.h"
#include "uapkic-errors.h"

#define MAX_FIELDS 10

struct stat {
    const char *what;
    int ok, bad;
};

static struct stat stats[64];
static size_t nstats;

static void check(const char *what, int ok, const char *detail)
{
    size_t i;
    for (i = 0; i < nstats && strcmp(stats[i].what, what) != 0; i++) {
    }
    if (i == nstats) {
        stats[nstats++].what = what;
    }
    if (ok) {
        stats[i].ok++;
    } else {
        stats[i].bad++;
        fprintf(stderr, "MISMATCH %s %.60s\n", what, detail);
    }
}

static void must(int ret, const char *call)
{
    if (ret != RET_OK) {
        fprintf(stderr, "uapki: %s: error %d\n", call, ret);
        exit(1);
    }
}

/* hex decodes a field; "-" is the empty value. */
static ByteArray *hex(const char *s)
{
    ByteArray *ba = strcmp(s, "-") == 0 ? ba_alloc() : ba_alloc_from_hex(s);
    if (ba == NULL) {
        fprintf(stderr, "uapki: bad hex %.60s\n", s);
        exit(1);
    }
    return ba;
}

/* hex_le decodes a big-endian number into the little-endian order of
 * uapkic, left-padded to size bytes. */
static ByteArray *hex_le(const char *s, size_t size)
{
    size_t n = strlen(s);
    char *padded = calloc(2 * size + 1, 1);
    if (padded == NULL || n > 2 * size) {
        fprintf(stderr, "uapki: bad number %.60s\n", s);
        exit(1);
    }
    memset(padded, '0', 2 * size - n);
    memcpy(padded + 2 * size - n, s, n);
    ByteArray *ba = hex(padded);
    free(padded);
    must(ba_swap(ba), "ba_swap");
    return ba;
}

static int equal(const ByteArray *a, const ByteArray *b)
{
    return ba_get_len(a) == ba_get_len(b) && (ba_get_len(a) == 0 || ba_cmp(a, b) == 0);
}

/* print_be writes a little-endian number as big-endian hex without leading zeros. */
static void print_be(FILE *out, const ByteArray *le)
{
    const uint8_t *buf = ba_get_buf_const(le);
    size_t i = ba_get_len(le);
    while (i > 1 && buf[i - 1] == 0) {
        i--;
    }
    fprintf(out, " %x", buf[--i]);
    while (i > 0) {
        fprintf(out, "%02x", buf[--i]);
    }
}

static void check_hashes(char **f, const char *line)
{
    static const char *names[] = {"kupyna256", "kupyna384", "kupyna512"};
    static const size_t sizes[] = {32, 48, 64};
    ByteArray *msg = hex(f[1]), *want, *got = NULL, *sync = ba_alloc_by_len(32);

    must(ba_set(sync, 0), "ba_set");
    Gost34311Ctx *g = gost34311_alloc(GOST28147_SBOX_ID_1, sync);
    if (ba_get_len(msg) > 0) {
        must(gost34311_update(g, msg), "gost34311_update");
    }
    must(gost34311_final(g, &got), "gost34311_final");
    want = hex(f[2]);
    check("gost34311", equal(got, want), line);
    ba_free(want);
    ba_free(got);
    gost34311_free(g);
    ba_free(sync);
    for (int i = 0; i < 3; i++) {
        Dstu7564Ctx *k = dstu7564_alloc();
        must(dstu7564_init(k, sizes[i]), "dstu7564_init");
        if (ba_get_len(msg) > 0) {
            must(dstu7564_update(k, msg), "dstu7564_update");
        }
        got = NULL;
        must(dstu7564_final(k, &got), "dstu7564_final");
        want = hex(f[3 + i]);
        check(names[i], equal(got, want), line);
        ba_free(want);
        ba_free(got);
        dstu7564_free(k);
    }
    ba_free(msg);
}

static void check_gost28147(char **f, const char *line)
{
    ByteArray *key = hex(f[1]), *pt = hex(f[2]), *want = hex(f[3]), *got = NULL;
    Gost28147Ctx *ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
    must(gost28147_init_ecb(ctx, key), "gost28147_init_ecb");
    must(gost28147_encrypt(ctx, pt, &got), "gost28147_encrypt");
    check("gost28147", equal(got, want), line);
    gost28147_free(ctx);
    ba_free(key);
    ba_free(pt);
    ba_free(want);
    ba_free(got);
}

/* check_modes checks the line G <key> <iv> <msg> <cfb> <mac32> <mac64>. */
static void check_modes(char **f, const char *line)
{
    ByteArray *key = hex(f[1]), *iv = hex(f[2]), *msg = hex(f[3]), *cfb = hex(f[4]);
    ByteArray *want, *got = NULL;
    Gost28147Ctx *ctx;

    if (ba_get_len(msg) > 0) {
        ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
        must(gost28147_init_cfb(ctx, key, iv), "gost28147_init_cfb");
        must(gost28147_encrypt(ctx, msg, &got), "gost28147_encrypt");
        check("gost28147 cfb encrypt", equal(got, cfb), line);
        ba_free(got);
        gost28147_free(ctx);

        ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
        must(gost28147_init_cfb(ctx, key, iv), "gost28147_init_cfb");
        got = NULL;
        must(gost28147_decrypt(ctx, cfb, &got), "gost28147_decrypt");
        check("gost28147 cfb decrypt", equal(got, msg), line);
        ba_free(got);
        gost28147_free(ctx);
    }

    for (int bits = 32; bits <= 64; bits += 32) {
        ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
        must(gost28147_init_mac(ctx, key), "gost28147_init_mac");
        if (ba_get_len(msg) > 0) {
            must(gost28147_update_mac(ctx, msg), "gost28147_update_mac");
        }
        got = NULL;
        must(bits == 32 ? gost28147_final_mac(ctx, &got) : gost28147_final_mac8(ctx, &got), "gost28147_final_mac");
        want = hex(f[bits == 32 ? 5 : 6]);
        check(bits == 32 ? "gost28147 mac 32" : "gost28147 mac 64", equal(got, want), line);
        ba_free(want);
        ba_free(got);
        gost28147_free(ctx);
    }
    ba_free(key);
    ba_free(iv);
    ba_free(msg);
    ba_free(cfb);
}

/* check_kalyna checks K <key> <plaintext> <ciphertext>; the block size is the plaintext length. */
static void check_kalyna(char **f, const char *line)
{
    static char names[5][2][32];
    static const size_t sizes[5][2] = {{16, 16}, {16, 32}, {32, 32}, {32, 64}, {64, 64}};
    ByteArray *key = hex(f[1]), *pt = hex(f[2]), *ct = hex(f[3]), *got = NULL;
    size_t block = ba_get_len(pt), i;

    for (i = 0; i < 5 && !(sizes[i][0] == block && sizes[i][1] == ba_get_len(key)); i++) {
    }
    if (i == 5) {
        fprintf(stderr, "uapki: no Kalyna %zu/%zu\n", 8 * block, 8 * ba_get_len(key));
        exit(1);
    }
    snprintf(names[i][0], sizeof names[i][0], "kalyna %zu/%zu encrypt", 8 * sizes[i][0], 8 * sizes[i][1]);
    snprintf(names[i][1], sizeof names[i][1], "kalyna %zu/%zu decrypt", 8 * sizes[i][0], 8 * sizes[i][1]);

    Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);
    must(dstu7624_init_ecb(ctx, key, block), "dstu7624_init_ecb");
    must(dstu7624_encrypt(ctx, pt, &got), "dstu7624_encrypt");
    check(names[i][0], equal(got, ct), line);
    ba_free(got);
    got = NULL;
    must(dstu7624_decrypt(ctx, ct, &got), "dstu7624_decrypt");
    check(names[i][1], equal(got, pt), line);
    ba_free(got);
    dstu7624_free(ctx);
    ba_free(key);
    ba_free(pt);
    ba_free(ct);
}

/* check_signature checks S <curve> <index> <d> <Q> <hash> <r> <s> <r||s> and
 * writes the X line of its own signature of the same hash with the same key. */
static int check_signature(char **f, FILE *out)
{
    char at[32];
    int id = atoi(f[1]);
    ByteArray *hash = hex(f[5]);
    size_t hlen = ba_get_len(hash);

    if (hlen != 32 && hlen != 48 && hlen != 64) {
        ba_free(hash);
        return 0;
    }
    snprintf(at, sizeof at, "curve %s #%s", f[1], f[2]);
    EcCtx *ctx = ec_alloc_default((EcParamsId)(EC_PARAMS_ID_DSTU4145_M163_PB + id));
    if (ctx == NULL) {
        fprintf(stderr, "uapki: no curve %d\n", id);
        exit(1);
    }
    /* r and s of one length: dstu4145_verify rejects an odd total */
    size_t qlen = strlen(f[4]) / 2, rlen = (strlen(f[6]) + 1) / 2, slen = (strlen(f[7]) + 1) / 2;
    size_t nlen = rlen > slen ? rlen : slen;

    /* the public key from d, little-endian in and out */
    ByteArray *d = hex_le(f[3], (strlen(f[3]) + 1) / 2), *qx = NULL, *qy = NULL, *q = NULL;
    ByteArray *want_q = hex_le(f[4], qlen);
    must(dstu4145_get_pubkey(ctx, d, &qx, &qy), "dstu4145_get_pubkey");
    must(dstu4145_compress_pubkey(ctx, qx, qy, &q), "dstu4145_compress_pubkey");
    check("dstu4145 public key from d", equal(q, want_q), at);
    ba_free(qx);
    ba_free(qy);
    ba_free(q);

    /* the Go key and signature */
    qx = qy = NULL;
    must(dstu4145_decompress_pubkey(ctx, want_q, &qx, &qy), "dstu4145_decompress_pubkey");
    must(ba_swap(qx), "ba_swap");
    must(ba_swap(qy), "ba_swap");
    must(ec_init_verify(ctx, qx, qy), "ec_init_verify");
    ByteArray *r = hex_le(f[6], nlen), *s = hex_le(f[7], nlen);
    check("dstu4145 verify Go signature", dstu4145_verify(ctx, hash, r, s) == RET_OK, at);
    ba_free(r);
    ba_free(s);

    /* its own signature; ec_init_sign takes d big-endian */
    must(ba_swap(d), "ba_swap");
    must(ec_init_sign(ctx, d), "ec_init_sign");
    r = s = NULL;
    must(dstu4145_sign(ctx, hash, &r, &s), "dstu4145_sign");
    fprintf(out, "X uapki %s %s %s", f[1], f[4], f[5]);
    print_be(out, r);
    print_be(out, s);
    fputc('\n', out);

    ba_free(r);
    ba_free(s);
    ba_free(qx);
    ba_free(qy);
    ba_free(want_q);
    ba_free_private(d);
    ba_free(hash);
    ec_free(ctx);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: check <cases.txt> <uapki_sigs.txt>\n");
        return 2;
    }
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (in == NULL || out == NULL) {
        perror("uapki");
        return 1;
    }

    char *line = NULL;
    size_t cap = 0;
    int skipped = 0;
    while (getline(&line, &cap, in) > 0) {
        char *f[MAX_FIELDS], *copy = strdup(line);
        int n = 0;
        for (char *tok = strtok(copy, " \n"); tok != NULL && n < MAX_FIELDS; tok = strtok(NULL, " \n")) {
            f[n++] = tok;
        }
        if (n == 0) {
            free(copy);
            continue;
        }
        switch (f[0][0]) {
        case 'H':
            check_hashes(f, line);
            break;
        case 'C':
            check_gost28147(f, line);
            break;
        case 'G':
            check_modes(f, line);
            break;
        case 'K':
            check_kalyna(f, line);
            break;
        case 'S':
            if (!check_signature(f, out)) {
                skipped++;
            }
            break;
        }
        free(copy);
    }
    free(line);
    fclose(in);
    if (fclose(out) != 0) {
        perror("uapki");
        return 1;
    }

    int failed = 0;
    for (size_t i = 0; i < nstats; i++) {
        printf("uapki    %-32s %4d ok %d mismatch\n", stats[i].what, stats[i].ok, stats[i].bad);
        failed += stats[i].bad;
    }
    printf("uapki    skipped %d signature cases: dstu4145_sign takes 32-, 48- and 64-byte hashes only\n", skipped);
    return failed > 0 ? 1 : 0;
}
