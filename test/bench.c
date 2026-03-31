#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#else
#include <time.h>
#endif

#include "pompom/padlock.h"
#include "pompom/cipher.h"
#include "pompom/accel.h"
#include "pompom/wal.h"
#include "pompom/profile.h"
#include "pompom/proto.h"

#define MUTATE_ITERS  1000000
#define BLOCK_ITERS   100000
#define BULK_SIZE     (1 << 20)   /* 1 MB */
#define DIAL_ITERS    1000000
#define WAL_ITERS     10000

static double now_sec(void) {
#ifdef __APPLE__
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    uint64_t t = mach_absolute_time();
    return (double)(t * tb.numer / tb.denom) * 1e-9;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}

/* ================================================================
 * Correctness
 * ================================================================ */

static int test_roundtrip(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};

    const char *plain = "pompom rolling block cipher test message!!";
    size_t len = strlen(plain);

    uint8_t *ct = malloc(len);
    uint8_t *pt = malloc(len);

    pompom_state_t enc, dec;
    pompom_init(&enc, key, nonce);
    pompom_crypt(&enc, (const uint8_t *)plain, ct, len);

    pompom_init(&dec, key, nonce);
    pompom_crypt(&dec, ct, pt, len);

    int ok = (memcmp(pt, plain, len) == 0);
    free(ct);
    free(pt);
    return ok;
}

static int test_padlock_correct(void) {
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "secret", 6);
    pompom_lock_set(&lock);
    pompom_dial(&lock, "secret", 6);
    return pompom_lock_try(&lock) == 0;
}

static int test_padlock_wrong(void) {
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "secret", 6);
    pompom_lock_set(&lock);
    pompom_dial(&lock, "wrong!", 6);
    return pompom_lock_try(&lock) != 0;
}

static int test_ct_nontrivial(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};
    uint8_t plain[16] = {0};
    uint8_t ct[16];

    pompom_state_t st;
    pompom_init(&st, key, nonce);
    pompom_crypt(&st, plain, ct, 16);

    int nonzero = 0;
    for (int i = 0; i < 16; i++)
        nonzero |= ct[i];
    return nonzero != 0;
}

static int test_different_keys_differ(void) {
    uint8_t key_a[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t key_b[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEE};
    uint8_t nonce[4] = {0x00,0x00,0x00,0x01};
    uint8_t plain[16] = {0};
    uint8_t ct_a[16], ct_b[16];

    pompom_state_t st;
    pompom_init(&st, key_a, nonce);
    pompom_crypt(&st, plain, ct_a, 16);

    pompom_init(&st, key_b, nonce);
    pompom_crypt(&st, plain, ct_b, 16);

    return memcmp(ct_a, ct_b, 16) != 0;
}

static int test_no_keystream_reuse(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0x00,0x00,0x00,0x01};
    uint8_t ks1[16], ks2[16];

    pompom_state_t st;
    pompom_init(&st, key, nonce);
    pompom_block(&st, ks1);
    pompom_block(&st, ks2);

    return memcmp(ks1, ks2, 16) != 0;
}

static int test_cascade_matches_scalar(void) {
    /* Verify SIMD cascade produces identical output to scalar mutate calls */
    static const uint8_t x_rot[]  = {1,2,3,4,5,6,7,5};
    static const uint8_t x_salt[] = {0x53,0x91,0x1F,0xA6,0x72,0xE8,0x3D,0xF4};
    static const uint8_t x_sbox[] = {0,1,0,1,0,1,0,1};

    uint8_t a[8], b[8];
    for (int i = 0; i < 8; i++)
        a[i] = b[i] = (uint8_t)(0x42 + i * 17);

    /* Scalar reference */
    for (int i = 0; i < 8; i++)
        a[i] = pompom_mutate_x(a[i], x_rot[i], x_salt[i], x_sbox[i]);

    /* Cascade (SIMD-accelerated) */
    pompom_cascade_x(b);

    return memcmp(a, b, 8) == 0;
}

static int test_profiled_same_speed(void) {
    /* Same passphrase + same speed bands → lock opens */
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);

    /* Set: slow-fast-medium-fast-slow-medium */
    uint64_t set_us[] = {0, 900000, 100000, 500000, 80000, 300000};
    pompom_dial_profiled(&lock, "secret", 6, set_us);
    pompom_lock_set(&lock);

    /* Try: different exact times but same bands */
    uint64_t try_us[] = {0, 1200000, 120000, 600000, 60000, 400000};
    pompom_dial_profiled(&lock, "secret", 6, try_us);

    return pompom_lock_try(&lock) == 0;
}

static int test_profiled_wrong_speed(void) {
    /* Right passphrase + wrong speed → lock stays shut */
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);

    /* Set: all slow */
    uint64_t set_us[] = {0, 900000, 900000, 900000, 900000, 900000};
    pompom_dial_profiled(&lock, "secret", 6, set_us);
    pompom_lock_set(&lock);

    /* Try: all burst (completely different speed profile) */
    uint64_t try_us[] = {0, 20000, 20000, 20000, 20000, 20000};
    pompom_dial_profiled(&lock, "secret", 6, try_us);

    return pompom_lock_try(&lock) != 0;
}

static int test_profile_match_tolerance(void) {
    pompom_profile_t ref, attempt;
    uint64_t ref_us[]     = {0, 900000, 100000, 500000};
    uint64_t attempt_us[] = {0, 500000, 100000, 500000}; /* band 0→1 at seg 1 */

    pompom_profile_capture(&ref,     "test", 4, ref_us);
    pompom_profile_capture(&attempt, "test", 4, attempt_us);

    /* tolerance=0: should fail (band 0 vs 1 at segment 1) */
    int exact_fail = pompom_profile_match(&ref, &attempt, 0) != 0;
    /* tolerance=1: should pass (±1 band) */
    int fuzzy_pass = pompom_profile_match(&ref, &attempt, 1) == 0;

    return exact_fail && fuzzy_pass;
}

static int test_proto_handshake_roundtrip(void) {
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t buf[64];

    /* Client session */
    pompom_session_t client;
    pompom_session_init(&client, key);

    /* Server session */
    pompom_session_t server;
    pompom_session_init(&server, key);

    /* 1. Client sends HELLO */
    int hello_len = pompom_pkt_hello(&client, buf, sizeof(buf));
    if (hello_len < 0) return 0;

    /* 2. Server receives HELLO, sends ACCEPT */
    uint8_t accept_buf[64];
    int accept_len = pompom_pkt_accept(&server, buf, (size_t)hello_len,
                                        accept_buf, sizeof(accept_buf));
    if (accept_len < 0) return 0;

    /* 3. Client receives ACCEPT, finishes handshake */
    if (pompom_pkt_finish(&client, accept_buf, (size_t)accept_len) != 0)
        return 0;

    /* Both should be established */
    if (!client.established || !server.established) return 0;

    /* 4. Client sends DATA, server decodes */
    const char *msg = "hello pompom!";
    size_t msg_len = strlen(msg);
    uint8_t pkt[128], decoded[128];
    size_t decoded_len;
    uint8_t pkt_type;

    int pkt_len = pompom_pkt_encode(&client, POMPOM_PKT_DATA,
                                     (const uint8_t *)msg, msg_len,
                                     pkt, sizeof(pkt));
    if (pkt_len < 0) return 0;

    if (pompom_pkt_decode(&server, pkt, (size_t)pkt_len,
                           &pkt_type, decoded, &decoded_len) != 0)
        return 0;

    if (pkt_type != POMPOM_PKT_DATA) return 0;
    if (decoded_len != msg_len) return 0;
    if (memcmp(decoded, msg, msg_len) != 0) return 0;

    /* 5. Server sends DATA back, client decodes */
    const char *reply = "pong!";
    size_t reply_len = strlen(reply);

    pkt_len = pompom_pkt_encode(&server, POMPOM_PKT_DATA,
                                 (const uint8_t *)reply, reply_len,
                                 pkt, sizeof(pkt));
    if (pkt_len < 0) return 0;

    if (pompom_pkt_decode(&client, pkt, (size_t)pkt_len,
                           &pkt_type, decoded, &decoded_len) != 0)
        return 0;

    return pkt_type == POMPOM_PKT_DATA &&
           decoded_len == reply_len &&
           memcmp(decoded, reply, reply_len) == 0;
}

static int test_proto_replay_rejected(void) {
    uint8_t key[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22};
    uint8_t buf[64], accept_buf[64], pkt[128], decoded[128];
    size_t decoded_len;
    uint8_t pkt_type;

    pompom_session_t client, server;
    pompom_session_init(&client, key);
    pompom_session_init(&server, key);

    int n = pompom_pkt_hello(&client, buf, sizeof(buf));
    n = pompom_pkt_accept(&server, buf, (size_t)n, accept_buf, sizeof(accept_buf));
    pompom_pkt_finish(&client, accept_buf, (size_t)n);

    /* Send a packet */
    int pkt_len = pompom_pkt_encode(&client, POMPOM_PKT_DATA,
                                     (const uint8_t *)"test", 4,
                                     pkt, sizeof(pkt));
    /* Decode it once (should succeed) */
    int rc = pompom_pkt_decode(&server, pkt, (size_t)pkt_len,
                                &pkt_type, decoded, &decoded_len);
    if (rc != 0) return 0;

    /* Replay the same packet (should be rejected — seq too low) */
    rc = pompom_pkt_decode(&server, pkt, (size_t)pkt_len,
                            &pkt_type, decoded, &decoded_len);

    return rc != 0;  /* should fail */
}

static int test_wal_checkpoint_recover(void) {
    const char *path = "/tmp/pompom_test.wal";
    uint8_t key[8]   = {1,2,3,4,5,6,7,8};
    uint8_t nonce[4] = {0xAA,0xBB,0xCC,0xDD};

    pompom_state_t orig;
    pompom_init(&orig, key, nonce);

    pompom_wal_t *wal = pompom_wal_open(path);
    if (!wal) return 0;
    pompom_wal_checkpoint(wal, &orig);
    pompom_wal_close(wal);

    wal = pompom_wal_open(path);
    if (!wal) return 0;
    pompom_state_t recv;
    memset(&recv, 0, sizeof(recv));
    int rc = pompom_wal_recover(wal, &recv);
    pompom_wal_close(wal);
    unlink(path);

    if (rc != 0) return 0;
    return recv.t == orig.t &&
           recv.front == orig.front &&
           memcmp(recv.lane, orig.lane, 8) == 0 &&
           recv.seed == orig.seed;
}

/* ================================================================
 * Benchmarks
 * ================================================================ */

static void bench_mutate(void) {
    volatile uint8_t state = 0xAA;
    double t0, t1, ns;

    t0 = now_sec();
    for (int i = 0; i < MUTATE_ITERS; i++)
        state = pompom_mutate_x((uint8_t)state, 3, 0x53, 0);
    t1 = now_sec();
    ns = (t1 - t0) / MUTATE_ITERS * 1e9;
    printf("  mutate_x scalar      %8.2f ns/byte   (1M iters)\n", ns);

    t0 = now_sec();
    for (int i = 0; i < MUTATE_ITERS; i++)
        state = pompom_mutate_y((uint8_t)state, 3, 0xCA, 1);
    t1 = now_sec();
    ns = (t1 - t0) / MUTATE_ITERS * 1e9;
    printf("  mutate_y scalar      %8.2f ns/byte   (1M iters)\n", ns);
}

static void bench_cascade(void) {
    uint8_t states[8];
    for (int i = 0; i < 8; i++) states[i] = 0xAA;

    double t0 = now_sec();
    for (int i = 0; i < MUTATE_ITERS; i++)
        pompom_cascade_x(states);
    double t1 = now_sec();
    double ns = (t1 - t0) / MUTATE_ITERS * 1e9;
    double ns_per = ns / 8.0;
    printf("  cascade_x (8 lanes)  %8.2f ns/call   %.2f ns/byte\n", ns, ns_per);

    t0 = now_sec();
    for (int i = 0; i < MUTATE_ITERS; i++)
        pompom_cascade_y(states);
    t1 = now_sec();
    ns = (t1 - t0) / MUTATE_ITERS * 1e9;
    ns_per = ns / 8.0;
    printf("  cascade_y (8 lanes)  %8.2f ns/call   %.2f ns/byte\n", ns, ns_per);
}

static void bench_block(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};
    uint8_t ks[16];

    pompom_state_t st;
    pompom_init(&st, key, nonce);

    double t0 = now_sec();
    for (int i = 0; i < BLOCK_ITERS; i++)
        pompom_block(&st, ks);
    double t1 = now_sec();

    double elapsed = t1 - t0;
    double total_bytes = (double)BLOCK_ITERS * 16;
    double ns_per_byte = elapsed / total_bytes * 1e9;
    double mb_s = (total_bytes / (1024.0 * 1024.0)) / elapsed;

    printf("  pompom_block         %8.2f ns/byte   %.2f MB/s  (100K blocks)\n",
           ns_per_byte, mb_s);
}

__attribute__((optnone))
static void bench_crypt_bulk(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};
    const size_t bulk = BULK_SIZE;

    uint8_t *in  = calloc(1, bulk);
    uint8_t *out = malloc(bulk);
    if (!in || !out) { printf("  pompom_crypt: alloc failed\n"); return; }

    pompom_state_t st;
    pompom_init(&st, key, nonce);

    /* Touch output to prevent dead-store elimination */
    volatile uint8_t sink;

    double t0 = now_sec();
    pompom_crypt(&st, in, out, bulk);
    double t1 = now_sec();

    sink = out[0] ^ out[bulk - 1];
    (void)sink;

    double elapsed = t1 - t0;
    double ns_per_byte = elapsed / (double)bulk * 1e9;
    double mb_s = ((double)bulk / (1024.0 * 1024.0)) / elapsed;

    printf("  pompom_crypt 1MB     %8.2f ns/byte   %.2f MB/s\n",
           ns_per_byte, mb_s);

    free(in);
    free(out);
}

static void bench_padlock_dial(void) {
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);

    double t0 = now_sec();
    for (int i = 0; i < DIAL_ITERS; i++)
        pompom_dial(&lock, "test", 4);
    double t1 = now_sec();

    double ns = (t1 - t0) / DIAL_ITERS * 1e9;
    double ops = DIAL_ITERS / (t1 - t0);

    printf("  padlock dial(\"test\") %8.2f ns/op    %.0f ops/s\n", ns, ops);
}

static void bench_wal(void) {
    const char *path = "/tmp/pompom_bench.wal";
    pompom_wal_t *wal = pompom_wal_open(path);
    if (!wal) { printf("  WAL: failed to open\n"); return; }

    pompom_state_t st;
    memset(&st, 0, sizeof(st));
    st.t = 1; st.front = 0xAA;

    double t0 = now_sec();
    for (int i = 0; i < WAL_ITERS; i++)
        pompom_wal_checkpoint(wal, &st);
    double t1 = now_sec();
    printf("  WAL checkpoint       %8.0f ns/op    (fsync'd, %d entries)\n",
           (t1 - t0) / WAL_ITERS * 1e9, WAL_ITERS);

    t0 = now_sec();
    for (int i = 0; i < WAL_ITERS; i++)
        pompom_wal_recover(wal, &st);
    t1 = now_sec();
    printf("  WAL recover          %8.0f ns/op\n",
           (t1 - t0) / WAL_ITERS * 1e9);

    pompom_wal_close(wal);
    unlink(path);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    int accel = pompom_accel_detect();
    printf("=== pompom test suite ===\n");
    printf("  accel: %s\n\n", pompom_accel_name(accel));

    struct { const char *name; int (*fn)(void); } tests[] = {
        { "encrypt/decrypt roundtrip",    test_roundtrip },
        { "padlock correct combo",        test_padlock_correct },
        { "padlock wrong combo rejects",  test_padlock_wrong },
        { "ciphertext non-trivial",       test_ct_nontrivial },
        { "1-bit key diff -> diff ct",    test_different_keys_differ },
        { "consecutive blocks differ",    test_no_keystream_reuse },
        { "cascade matches scalar",       test_cascade_matches_scalar },
        { "profiled: same speed opens",   test_profiled_same_speed },
        { "profiled: wrong speed blocks", test_profiled_wrong_speed },
        { "profiled: tolerance ±1 band",  test_profile_match_tolerance },
        { "proto: handshake + roundtrip",  test_proto_handshake_roundtrip },
        { "proto: replay rejected",       test_proto_replay_rejected },
        { "WAL checkpoint/recover",       test_wal_checkpoint_recover },
    };

    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    int pass = 0, fail = 0;

    for (int i = 0; i < n; i++) {
        int ok = tests[i].fn();
        printf("  [%s] %s\n", ok ? "PASS" : "FAIL", tests[i].name);
        if (ok) pass++; else fail++;
    }

    printf("\n  %d/%d passed\n", pass, n);

    printf("\n=== pompom bench (byte travel time) ===\n\n");

    bench_mutate();
    bench_cascade();
    bench_block();
    bench_crypt_bulk();
    bench_padlock_dial();
    bench_wal();

    printf("\n");
    return fail ? 1 : 0;
}
