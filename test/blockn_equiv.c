/*
 * blockn_equiv.c — bit-exactness battery for pompom_blockN (asm batched
 * keystream generator) vs the C pompom_block reference.
 *
 * Three layers, all must pass or the asm has silently forked the cipher:
 *   1. Cross-impl: C pompom_block x N  ==  asm pompom_blockN, for a big range
 *      of nblocks and many random initial states — compares BOTH the full
 *      keystream and the final (front,lane,t) state.
 *   2. Known-answer: fixed key/nonce, keystream digests at 1,2,7,8,15,16,31,32
 *      blocks, asserted equal between impls (and printed for the record).
 *   3. Property: encrypt->decrypt roundtrip at weird/partial sizes, where the
 *      blockN-driven crypt must also byte-match the C pompom_crypt.
 *
 * Build:
 *   clang -O2 -Iinclude -o /tmp/blockn_equiv test/blockn_equiv.c \
 *         build/arm/libpompom.a
 */
#include "pompom/cipher.h"
#include "pompom/proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* asm entry (no public header yet) */
extern void pompom_blockN(pompom_state_t *st, uint8_t *ks, uint32_t nblocks);

static uint64_t g_seed = 0x123456789abcdef0ull;
static uint8_t rb(void) {
    g_seed = g_seed * 6364136223846793005ull + 1442695040888963407ull;
    return (uint8_t)(g_seed >> 33);
}
static void rand_state(pompom_state_t *st) {
    uint8_t key[8], nonce[4];
    for (int i = 0; i < 8; i++) key[i] = rb();
    for (int i = 0; i < 4; i++) nonce[i] = rb();
    pompom_init(st, key, nonce);           /* realistic, fully-mixed state */
}

static int fails = 0;

/* 64-bit FNV-1a digest for compact known-answers */
static uint64_t fnv(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static int state_eq(const pompom_state_t *a, const pompom_state_t *b) {
    return a->front == b->front && a->t == b->t &&
           memcmp(a->lane, b->lane, 8) == 0;
}

/* ---- 1. cross-impl: keystream + final state ---- */
static void test_cross(void) {
    printf("[1] cross-impl (keystream + final state)\n");
    const uint32_t MAXB = 64;
    uint8_t *ref = malloc((MAXB + 8) * 16), *asmks = malloc((MAXB + 8) * 16);
    int bad = 0;

    for (int trial = 0; trial < 2000; trial++) {
        pompom_state_t base; rand_state(&base);
        uint32_t n = (uint32_t)(rb() | (rb() << 8)) % (MAXB + 1);   /* 0..MAXB */

        pompom_state_t s1 = base;
        for (uint32_t i = 0; i < n; i++) pompom_block(&s1, ref + 16 * i);

        pompom_state_t s2 = base;
        pompom_blockN(&s2, asmks, n);

        if (n && memcmp(ref, asmks, 16 * n) != 0) { bad++; }
        if (!state_eq(&s1, &s2)) { bad++; }
    }
    /* a few large counts */
    for (int trial = 0; trial < 20; trial++) {
        pompom_state_t base; rand_state(&base);
        uint32_t n = 1000 + trial;
        uint8_t *r = malloc(16 * n), *a = malloc(16 * n);
        pompom_state_t s1 = base; for (uint32_t i = 0; i < n; i++) pompom_block(&s1, r + 16 * i);
        pompom_state_t s2 = base; pompom_blockN(&s2, a, n);
        if (memcmp(r, a, 16 * n) != 0 || !state_eq(&s1, &s2)) bad++;
        free(r); free(a);
    }
    printf("    %s (%d mismatches)\n", bad ? "FAIL" : "ok", bad);
    fails += bad;
    free(ref); free(asmks);
}

/* ---- 2. known-answer at specific block counts ---- */
static void test_kat(void) {
    printf("[2] known-answer digests (fixed key/nonce)\n");
    const uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    const uint8_t nonce[4] = {0xde,0xad,0xbe,0xef};
    const uint32_t lens[] = {1,2,7,8,15,16,31,32};
    /* Locked-in known answers (FNV-1a of the keystream). Catches drift in
     * EITHER implementation, not just asm-vs-C divergence. */
    const uint64_t expect[] = {
        0x37eb8ce2a58f7d36ull, 0xbb96a5178d809f39ull,
        0x07c707104b8a65cdull, 0x8e57b4c5e16f74c3ull,
        0xcd54a6052cbfd3eeull, 0x608b384c4492a7faull,
        0x6fbfbbe967f5db3eull, 0xcf07b332471a8106ull,
    };

    for (size_t k = 0; k < sizeof lens / sizeof lens[0]; k++) {
        uint32_t n = lens[k];
        uint8_t *r = malloc(16 * n), *a = malloc(16 * n);
        pompom_state_t s1; pompom_init(&s1, key, nonce);
        for (uint32_t i = 0; i < n; i++) pompom_block(&s1, r + 16 * i);
        pompom_state_t s2; pompom_init(&s2, key, nonce);
        pompom_blockN(&s2, a, n);
        uint64_t d = fnv(a, 16 * n);
        int ok = memcmp(r, a, 16 * n) == 0 && state_eq(&s1, &s2) &&
                 d == expect[k];
        printf("    %2u blocks: ks=%016llx state(front=%02x t=%u)  %s\n",
               n, (unsigned long long)d, s2.front, s2.t, ok ? "ok" : "FAIL");
        if (!ok) fails++;
        free(r); free(a);
    }
}

/* blockN-driven crypt (mirrors pompom_crypt's ceil(len/16) block usage) */
static void crypt_blockN(pompom_state_t *st, const uint8_t *in, uint8_t *out, size_t len) {
    if (!len) return;
    uint32_t nb = (uint32_t)((len + 15) / 16);
    uint8_t *ks = malloc((size_t)nb * 16);
    pompom_blockN(st, ks, nb);
    for (size_t i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    free(ks);
}

/* ---- 3. roundtrip + crypt cross-impl at weird sizes ---- */
static void test_roundtrip(void) {
    printf("[3] encrypt->decrypt roundtrip + crypt cross-impl (partial blocks)\n");
    const size_t sizes[] = {0,1,2,7,8,15,16,17,31,32,33,63,64,65,127,128,
                            129,255,256,257,1000,4096,4097};
    int bad = 0;
    for (size_t si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t len = sizes[si];
        uint8_t key[8], nonce[4];
        for (int i = 0; i < 8; i++) key[i] = rb();
        for (int i = 0; i < 4; i++) nonce[i] = rb();
        uint8_t *pt = malloc(len ? len : 1), *ct_c = malloc(len ? len : 1);
        uint8_t *ct_n = malloc(len ? len : 1), *back = malloc(len ? len : 1);
        for (size_t i = 0; i < len; i++) pt[i] = rb();

        pompom_state_t s;
        pompom_init(&s, key, nonce); pompom_crypt(&s, pt, ct_c, len);   /* C ref */
        pompom_init(&s, key, nonce); crypt_blockN(&s, pt, ct_n, len);   /* asm  */
        pompom_init(&s, key, nonce); crypt_blockN(&s, ct_n, back, len); /* decrypt */

        int cross = (len == 0) || memcmp(ct_c, ct_n, len) == 0;  /* asm == C */
        int round = (len == 0) || memcmp(pt, back, len) == 0;    /* dec(enc)==pt */
        if (!cross || !round) { bad++;
            printf("    len=%zu  cross=%s round=%s\n", len,
                   cross ? "ok" : "FAIL", round ? "ok" : "FAIL");
        }
        free(pt); free(ct_c); free(ct_n); free(back);
    }
    printf("    %s\n", bad ? "FAIL" : "ok (all sizes match C and roundtrip)");
    fails += bad;
}

int main(void) {
    printf("=== pompom_blockN bit-exactness battery ===\n");
    test_cross();
    test_kat();
    test_roundtrip();
    printf("\n%s\n", fails ? "✗ BIT-EXACTNESS FAILED" : "✓ bit-exact with C reference");
    return fails ? 1 : 0;
}
