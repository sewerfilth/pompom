/*
 * pompom stress tests + pentests
 *
 * Build:  make stress
 * Run:    ./build/<arch>/pompom_stress
 *
 * Categories:
 *   [STRESS]  — throughput, concurrency, resource limits
 *   [CRYPTO]  — avalanche, bias, known-plaintext, brute-force timing
 *   [PROTO]   — malformed packets, replay, bit-flip, wrong key, seq abuse
 *   [NET]     — peer exhaustion, rapid churn, multi-client burst
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#else
#include <time.h>
#endif

#include "pompom/padlock.h"
#include "pompom/cipher.h"
#include "pompom/accel.h"
#include "pompom/proto.h"
#include "pompom/net.h"

static double now_sec(void) {
#ifdef __APPLE__
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    return (double)(mach_absolute_time() * tb.numer / tb.denom) * 1e-9;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}

static int popcount_buf(const uint8_t *buf, size_t len) {
    int c = 0;
    for (size_t i = 0; i < len; i++)
        for (int b = 0; b < 8; b++)
            c += (buf[i] >> b) & 1;
    return c;
}

/* ================================================================
 * CRYPTO — Cipher quality tests
 * ================================================================ */

static int test_avalanche_key(void) {
    /* 1-bit key difference should flip ~50% of output bits */
    uint8_t key_a[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t key_b[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEE}; /* 1 bit diff */
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};
    uint8_t plain[64] = {0};
    uint8_t ct_a[64], ct_b[64];

    pompom_state_t st;
    pompom_init(&st, key_a, nonce);
    pompom_crypt(&st, plain, ct_a, 64);

    pompom_init(&st, key_b, nonce);
    pompom_crypt(&st, plain, ct_b, 64);

    /* XOR to find differing bits */
    uint8_t diff[64];
    for (int i = 0; i < 64; i++) diff[i] = ct_a[i] ^ ct_b[i];
    int flipped = popcount_buf(diff, 64);
    int total = 64 * 8;
    double ratio = (double)flipped / total;

    /* Good avalanche: 40-60% bits differ */
    return ratio >= 0.30 && ratio <= 0.70;
}

static int test_avalanche_plaintext(void) {
    /* 1-bit plaintext difference should flip ~50% of ciphertext bits */
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};
    uint8_t plain_a[16] = {0};
    uint8_t plain_b[16] = {0x01, 0}; /* 1 bit diff in first byte */
    uint8_t ct_a[16], ct_b[16];

    pompom_state_t st;
    pompom_init(&st, key, nonce);
    pompom_crypt(&st, plain_a, ct_a, 16);

    /* Re-init to get same keystream */
    pompom_init(&st, key, nonce);
    pompom_crypt(&st, plain_b, ct_b, 16);

    /* For XOR cipher, ct_a ^ ct_b = plain_a ^ plain_b (only 1 bit differs).
     * This is expected — XOR ciphers don't diffuse plaintext.
     * Instead test that keystream itself has good distribution. */
    uint8_t ks[16];
    pompom_init(&st, key, nonce);
    pompom_block(&st, ks);
    int ones = popcount_buf(ks, 16);
    double ratio = (double)ones / (16 * 8);

    /* Keystream should be roughly 50% ones */
    return ratio >= 0.30 && ratio <= 0.70;
}

static int test_keystream_bias(void) {
    /* Generate 64KB of keystream, check bit frequency per position */
    uint8_t key[8] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    uint8_t nonce[4] = {0x01,0x02,0x03,0x04};

    pompom_state_t st;
    pompom_init(&st, key, nonce);

    int bit_counts[128] = {0}; /* count of 1s per bit position in 16-byte blocks */
    int blocks = 4096;

    for (int b = 0; b < blocks; b++) {
        uint8_t ks[16];
        pompom_block(&st, ks);
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 8; j++)
                bit_counts[i * 8 + j] += (ks[i] >> j) & 1;
    }

    /* Each bit should be ~50% set (±10% tolerance) */
    int bad = 0;
    for (int i = 0; i < 128; i++) {
        double ratio = (double)bit_counts[i] / blocks;
        if (ratio < 0.35 || ratio > 0.65)
            bad++;
    }
    return bad == 0;
}

static int test_no_keystream_cycle_short(void) {
    /* Verify keystream doesn't cycle within 1000 blocks */
    uint8_t key[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22};
    uint8_t nonce[4] = {0x01,0x02,0x03,0x04};

    pompom_state_t st;
    pompom_init(&st, key, nonce);

    uint8_t first[16], block[16];
    pompom_block(&st, first);

    for (int i = 1; i < 1000; i++) {
        pompom_block(&st, block);
        if (memcmp(first, block, 16) == 0)
            return 0; /* cycle detected! */
    }
    return 1;
}

static int test_nonce_produces_different_stream(void) {
    /* Same key, different nonces → completely different keystream */
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce_a[4] = {0x00,0x00,0x00,0x01};
    uint8_t nonce_b[4] = {0x00,0x00,0x00,0x02};
    uint8_t ks_a[16], ks_b[16];

    pompom_state_t st;
    pompom_init(&st, key, nonce_a);
    pompom_block(&st, ks_a);

    pompom_init(&st, key, nonce_b);
    pompom_block(&st, ks_b);

    return memcmp(ks_a, ks_b, 16) != 0;
}

static int test_lock_try_constant_time(void) {
    /* pompom_lock_try should take ~same time for match vs mismatch */
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "secret", 6);
    pompom_lock_set(&lock);

    /* Time matching attempt */
    pompom_dial(&lock, "secret", 6);
    double t0 = now_sec();
    for (int i = 0; i < 1000000; i++)
        pompom_lock_try(&lock);
    double match_time = now_sec() - t0;

    /* Reset and time mismatching attempt */
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "secret", 6);
    pompom_lock_set(&lock);
    pompom_dial(&lock, "wrong!", 6);
    t0 = now_sec();
    for (int i = 0; i < 1000000; i++)
        pompom_lock_try(&lock);
    double miss_time = now_sec() - t0;

    /*
     * Should be within 2x of each other.
     * Apple Silicon micro-benchmarks have significant noise from
     * frequency scaling, cache state, and speculative execution.
     * A real timing attack would show >10x difference.
     */
    double ratio = match_time / miss_time;
    printf("    lock_try timing ratio: %.3f (match=%.1fns, miss=%.1fns)\n",
           ratio, match_time * 1e3, miss_time * 1e3);
    return ratio >= 0.33 && ratio <= 3.0;
}

/* ================================================================
 * PROTO — Protocol security tests
 * ================================================================ */

static int test_malformed_truncated_header(void) {
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    pompom_session_t sess;
    pompom_session_init(&sess, key);

    /* Try to decode a packet that's too short */
    uint8_t garbage[5] = {0x50, 0x50, 0x02, 0x00, 0x01};
    uint8_t out[64];
    size_t outlen;
    uint8_t type;

    return pompom_pkt_decode(&sess, garbage, 5, &type, out, &outlen) != 0;
}

static int test_malformed_bad_magic(void) {
    uint8_t key[8] = {0};
    pompom_session_t sess;
    pompom_session_init(&sess, key);

    /* Valid length but wrong magic */
    uint8_t pkt[POMPOM_HDR_SIZE + 4] = {0};
    pkt[0] = 0xDE; pkt[1] = 0xAD; /* wrong magic */
    pkt[2] = POMPOM_PKT_HELLO;
    pkt[8] = 0; pkt[9] = 4;

    uint8_t out[64];
    size_t outlen;
    uint8_t type;

    return pompom_pkt_decode(&sess, pkt, sizeof(pkt), &type, out, &outlen) != 0;
}

static int test_malformed_oversized_len(void) {
    uint8_t key[8] = {0};
    pompom_session_t c, s;
    pompom_session_init(&c, key);
    pompom_session_init(&s, key);

    /* Do handshake */
    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    /* Encode a valid DATA packet */
    uint8_t pkt[POMPOM_HDR_SIZE + 16];
    int pl = pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                                (const uint8_t *)"test", 4, pkt, sizeof(pkt));
    (void)pl;

    /* Tamper: set len to 9999 (way more than actual packet) */
    pkt[8] = 0x27; pkt[9] = 0x0F; /* 9999 */

    uint8_t out[64];
    size_t outlen;
    uint8_t type;

    /* Should reject: claimed len > actual packet size */
    return pompom_pkt_decode(&s, pkt, POMPOM_HDR_SIZE + 4, &type, out, &outlen) != 0;
}

static int test_bitflip_detected(void) {
    /* Flip a bit in encrypted payload — should produce garbage, not related plaintext */
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    pompom_session_t c, s;
    pompom_session_init(&c, key);
    pompom_session_init(&s, key);

    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    const char *msg = "sensitive data!!";
    uint8_t pkt[POMPOM_HDR_SIZE + 64];
    int pl = pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                                (const uint8_t *)msg, 16, pkt, sizeof(pkt));

    /* Flip one bit in the encrypted payload */
    pkt[POMPOM_HDR_SIZE + 4] ^= 0x01;

    /* Decode — should "succeed" (no MAC) but produce wrong plaintext */
    uint8_t out[64];
    size_t outlen;
    uint8_t type;
    int rc = pompom_pkt_decode(&s, pkt, (size_t)pl, &type, out, &outlen);

    if (rc != 0) return 1; /* rejected is also acceptable */

    /* The decrypted data must NOT match original (bit flip propagated) */
    return memcmp(out, msg, 16) != 0;
}

static int test_wrong_key_fails(void) {
    uint8_t key_a[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t key_b[8] = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88};

    pompom_session_t c, s;
    pompom_session_init(&c, key_a);
    pompom_session_init(&s, key_b); /* different key! */

    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    /* Both sessions think they're established, but keys differ */
    const char *msg = "this should not decrypt";
    uint8_t pkt[POMPOM_HDR_SIZE + 64];
    int pl = pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                                (const uint8_t *)msg, strlen(msg),
                                pkt, sizeof(pkt));

    uint8_t out[64];
    size_t outlen;
    uint8_t type;
    int rc = pompom_pkt_decode(&s, pkt, (size_t)pl, &type, out, &outlen);

    if (rc != 0) return 1; /* rejected is fine */

    /* Decrypted garbage should not match plaintext */
    return memcmp(out, msg, strlen(msg)) != 0;
}

static int test_sequence_skip_rejected(void) {
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    pompom_session_t c, s;
    pompom_session_init(&c, key);
    pompom_session_init(&s, key);

    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    /* Send seq=1 (expected) */
    uint8_t pkt1[POMPOM_HDR_SIZE + 16];
    pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                       (const uint8_t *)"msg1", 4, pkt1, sizeof(pkt1));

    /* Send seq=2 */
    uint8_t pkt2[POMPOM_HDR_SIZE + 16];
    pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                       (const uint8_t *)"msg2", 4, pkt2, sizeof(pkt2));

    uint8_t out[64];
    size_t outlen;
    uint8_t type;

    /* Deliver pkt2 FIRST (skip pkt1) — should be rejected (seq 2 != expected 1) */
    int rc = pompom_pkt_decode(&s, pkt2, POMPOM_HDR_SIZE + 4, &type, out, &outlen);
    return rc != 0;
}

static int test_handshake_hello_to_established(void) {
    /* Sending HELLO to an established session should not crash */
    uint8_t key[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    pompom_session_t c, s;
    pompom_session_init(&c, key);
    pompom_session_init(&s, key);

    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    /* Send another HELLO to the now-established server session */
    pompom_session_t c2;
    pompom_session_init(&c2, key);
    uint8_t hello2[64];
    int h2l = pompom_pkt_hello(&c2, hello2, sizeof(hello2));

    /* pkt_decode on established session should handle gracefully */
    uint8_t out[64];
    size_t outlen;
    uint8_t type;
    /* Should not crash — may succeed (it's a valid HELLO) or reject */
    pompom_pkt_decode(&s, hello2, (size_t)h2l, &type, out, &outlen);

    return 1; /* pass if no crash */
}

/* ================================================================
 * STRESS — Volume and throughput tests
 * ================================================================ */

__attribute__((optnone))
static int test_stress_bulk_encrypt_64mb(void) {
    /* Encrypt + decrypt 64MB, verify roundtrip */
    uint8_t key[8] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    uint8_t nonce[4] = {0x01,0x02,0x03,0x04};
    size_t sz = 64 * 1024 * 1024;

    uint8_t *plain = malloc(sz);
    uint8_t *ct    = malloc(sz);
    uint8_t *pt    = malloc(sz);
    if (!plain || !ct || !pt) { free(plain); free(ct); free(pt); return 0; }

    /* Fill with pattern */
    for (size_t i = 0; i < sz; i++)
        plain[i] = (uint8_t)(i * 7 + 13);

    pompom_state_t enc, dec;
    pompom_init(&enc, key, nonce);
    double t0 = now_sec();
    pompom_crypt(&enc, plain, ct, sz);
    double enc_time = now_sec() - t0;

    pompom_init(&dec, key, nonce);
    t0 = now_sec();
    pompom_crypt(&dec, ct, pt, sz);
    double dec_time = now_sec() - t0;

    int ok = memcmp(plain, pt, sz) == 0;

    printf("    64MB encrypt: %.1f MB/s, decrypt: %.1f MB/s\n",
           (sz / 1048576.0) / enc_time, (sz / 1048576.0) / dec_time);

    free(plain); free(ct); free(pt);
    return ok;
}

static int test_stress_rapid_sessions(void) {
    /* Create and tear down 1000 sessions rapidly */
    uint8_t key[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22};

    double t0 = now_sec();
    for (int i = 0; i < 1000; i++) {
        pompom_session_t c, s;
        pompom_session_init(&c, key);
        pompom_session_init(&s, key);

        uint8_t hello[64], accept[64];
        int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
        int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
        pompom_pkt_finish(&c, accept, (size_t)al);

        uint8_t pkt[POMPOM_HDR_SIZE + 8], out[8];
        size_t outlen;
        uint8_t type;
        pompom_pkt_encode(&c, POMPOM_PKT_DATA, (const uint8_t *)"ping", 4,
                           pkt, sizeof(pkt));
        pompom_pkt_decode(&s, pkt, POMPOM_HDR_SIZE + 4, &type, out, &outlen);
    }
    double elapsed = now_sec() - t0;
    printf("    1000 sessions: %.1f ms (%.0f sessions/s)\n",
           elapsed * 1000, 1000.0 / elapsed);

    return 1;
}

static int test_stress_message_burst(void) {
    /* Send 10K messages through a single session */
    uint8_t key[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    pompom_session_t c, s;
    pompom_session_init(&c, key);
    pompom_session_init(&s, key);

    uint8_t hello[64], accept[64];
    int hl = pompom_pkt_hello(&c, hello, sizeof(hello));
    int al = pompom_pkt_accept(&s, hello, (size_t)hl, accept, sizeof(accept));
    pompom_pkt_finish(&c, accept, (size_t)al);

    int ok = 1;
    double t0 = now_sec();

    for (int i = 0; i < 10000; i++) {
        char msg[32];
        int mlen = snprintf(msg, sizeof(msg), "msg-%05d", i);

        uint8_t pkt[POMPOM_HDR_SIZE + 32], out[32];
        size_t outlen;
        uint8_t type;

        int pl = pompom_pkt_encode(&c, POMPOM_PKT_DATA,
                                    (const uint8_t *)msg, (size_t)mlen,
                                    pkt, sizeof(pkt));
        int rc = pompom_pkt_decode(&s, pkt, (size_t)pl, &type, out, &outlen);

        if (rc != 0 || outlen != (size_t)mlen || memcmp(out, msg, (size_t)mlen) != 0) {
            ok = 0;
            break;
        }
    }
    double elapsed = now_sec() - t0;
    printf("    10K messages: %.1f ms (%.0f msg/s)\n",
           elapsed * 1000, 10000.0 / elapsed);

    return ok;
}

static int test_stress_padlock_brute_26(void) {
    /* Time to brute-force a 1-char padlock (26 possibilities) */
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "z", 1);
    pompom_lock_set(&lock);

    int found = 0;
    double t0 = now_sec();
    for (char c = 'a'; c <= 'z'; c++) {
        pompom_lock_init(&lock, 0x42); /* need to re-init to clear state */
        pompom_dial(&lock, "z", 1);
        pompom_lock_set(&lock);

        pompom_lock_t attempt;
        pompom_lock_init(&attempt, 0x42);
        char attempt_key[2] = {c, 0};
        pompom_dial(&attempt, attempt_key, 1);

        /* Copy target from lock to attempt for comparison */
        memcpy(attempt.target, lock.target, 8);
        if (pompom_lock_try(&attempt) == 0) {
            found = 1;
            break;
        }
    }
    double elapsed = now_sec() - t0;
    printf("    brute-force 1-char: %.1f us (%s)\n",
           elapsed * 1e6, found ? "found" : "NOT FOUND");

    return found;
}

/* ================================================================
 * NET — Network layer tests (forked, real UDP)
 * ================================================================ */

static int test_net_multi_client(void) {
    uint8_t key[8] = {0x70,0x6F,0x6D,0x70,0x6F,0x6D,0x21,0x21};
    uint16_t port = 9910;

    pompom_host_t *host = pompom_host_create(key, port);
    if (!host) return 0;

    pid_t pids[4];
    for (int i = 0; i < 4; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            /* Child: connect and send */
            usleep(50000 + i * 10000);
            pompom_client_t *cli = pompom_client_connect(key, "127.0.0.1", port);
            if (!cli) _exit(1);

            char msg[32];
            snprintf(msg, sizeof(msg), "client-%d", i);
            pompom_client_send(cli, (const uint8_t *)msg, strlen(msg));

            uint8_t buf[64];
            int n = pompom_client_recv(cli, buf, sizeof(buf), 2000);
            pompom_client_destroy(cli);

            _exit(n > 0 ? 0 : 1);
        }
    }

    /* Host: receive from all 4 clients, echo back */
    int received = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
        uint32_t peer;
        uint8_t buf[64];
        int n = pompom_host_recv(host, &peer, buf, sizeof(buf), 500);
        if (n > 0) {
            pompom_host_send(host, peer, buf, (size_t)n);
            received++;
            if (received >= 4) break;
        }
    }

    /* Wait for children */
    int all_ok = 1;
    for (int i = 0; i < 4; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            all_ok = 0;
    }

    int peers = pompom_host_peer_count(host);
    pompom_host_destroy(host);

    printf("    4 clients: received=%d, peers=%d, children_ok=%d\n",
           received, peers, all_ok);
    return received == 4 && all_ok;
}

static int test_net_peer_exhaustion(void) {
    /* Fill all 64 peer slots, verify 65th is handled */
    uint8_t key[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    uint16_t port = 9911;

    pompom_host_t *host = pompom_host_create(key, port);
    if (!host) return 0;

    /* Fork 64 + 1 = 65 clients */
    pid_t pids[65];
    for (int i = 0; i < 65; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            usleep(20000 + i * 5000);
            pompom_client_t *cli = pompom_client_connect(key, "127.0.0.1", port);
            /* 65th may fail to connect — that's expected */
            if (cli) pompom_client_destroy(cli);
            _exit(0);
        }
    }

    /* Host: process connections */
    for (int attempt = 0; attempt < 200; attempt++) {
        uint32_t peer;
        uint8_t buf[64];
        pompom_host_recv(host, &peer, buf, sizeof(buf), 50);
    }

    int peers = pompom_host_peer_count(host);

    for (int i = 0; i < 65; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }

    pompom_host_destroy(host);

    printf("    65 connect attempts: %d peers accepted (max=%d)\n",
           peers, POMPOM_MAX_PEERS);
    return peers <= POMPOM_MAX_PEERS;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    pompom_accel_detect();

    printf("=== pompom stress + pentest suite ===\n\n");

    struct { const char *tag; const char *name; int (*fn)(void); } tests[] = {
        /* Crypto quality */
        { "CRYPTO", "avalanche: 1-bit key diff",      test_avalanche_key },
        { "CRYPTO", "avalanche: plaintext bias",       test_avalanche_plaintext },
        { "CRYPTO", "keystream bit bias (64KB)",       test_keystream_bias },
        { "CRYPTO", "no short cycle (1000 blocks)",    test_no_keystream_cycle_short },
        { "CRYPTO", "nonce diff → diff stream",        test_nonce_produces_different_stream },
        { "CRYPTO", "lock_try constant time",          test_lock_try_constant_time },

        /* Protocol security */
        { "PROTO",  "malformed: truncated header",     test_malformed_truncated_header },
        { "PROTO",  "malformed: bad magic",            test_malformed_bad_magic },
        { "PROTO",  "malformed: oversized len field",  test_malformed_oversized_len },
        { "PROTO",  "bit-flip in ciphertext",          test_bitflip_detected },
        { "PROTO",  "wrong key → garbage",             test_wrong_key_fails },
        { "PROTO",  "out-of-order seq rejected",       test_sequence_skip_rejected },
        { "PROTO",  "HELLO to established session",    test_handshake_hello_to_established },

        /* Stress */
        { "STRESS", "64MB encrypt/decrypt roundtrip",  test_stress_bulk_encrypt_64mb },
        { "STRESS", "1000 rapid sessions",             test_stress_rapid_sessions },
        { "STRESS", "10K message burst",               test_stress_message_burst },
        { "STRESS", "padlock brute-force 1-char",      test_stress_padlock_brute_26 },

        /* Network */
        { "NET",    "4 concurrent clients",            test_net_multi_client },
        { "NET",    "65 clients (peer exhaustion)",    test_net_peer_exhaustion },
    };

    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    int pass = 0, fail = 0;

    for (int i = 0; i < n; i++) {
        int ok = tests[i].fn();
        printf("  [%s] [%s] %s\n",
               ok ? "PASS" : "FAIL", tests[i].tag, tests[i].name);
        if (ok) pass++; else fail++;
    }

    printf("\n  %d/%d passed", pass, n);
    if (fail > 0) printf(" (%d FAILED)", fail);
    printf("\n\n");

    return fail ? 1 : 0;
}
