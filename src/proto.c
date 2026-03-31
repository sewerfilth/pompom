#include "pompom/proto.h"
#include "pompom/accel.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ---- Endian helpers ---- */

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint16_t get16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

/* ---- Nonce generation ---- */

static void fill_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, len);
        close(fd);
    }
}

/* ---- Key derivation from PSK + nonces ---- */

static void derive_session(pompom_session_t *sess, int is_server) {
    /*
     * Derive directional nonces.  Both sides must agree on which
     * nonce is "client" and which is "server" — the is_server flag
     * only controls which direction becomes tx vs rx.
     */
    const uint8_t *client_n = is_server ? sess->remote_nonce : sess->local_nonce;
    const uint8_t *server_n = is_server ? sess->local_nonce  : sess->remote_nonce;

    uint8_t c2s_nonce[4], s2c_nonce[4];
    for (int i = 0; i < 4; i++) {
        uint8_t combined = client_n[i] ^ server_n[i];
        c2s_nonce[i] = combined;
        s2c_nonce[i] = ~combined;
    }

    if (is_server) {
        pompom_init(&sess->tx, sess->key, s2c_nonce);
        pompom_init(&sess->rx, sess->key, c2s_nonce);
    } else {
        pompom_init(&sess->tx, sess->key, c2s_nonce);
        pompom_init(&sess->rx, sess->key, s2c_nonce);
    }

    sess->tx_seq = 1;
    sess->rx_seq = 1;
    sess->established = 1;
}

/* ---- Header encode/decode ---- */

static void write_hdr(uint8_t *out, uint8_t type, uint8_t flags,
                       uint32_t seq, uint16_t len) {
    put16(out + 0, POMPOM_PROTO_MAGIC);
    out[2] = type;
    out[3] = flags;
    put32(out + 4, seq);
    put16(out + 8, len);
}

/* ---- Public API ---- */

void pompom_session_init(pompom_session_t *sess, const uint8_t key[8]) {
    memset(sess, 0, sizeof(*sess));
    memcpy(sess->key, key, 8);
}

void pompom_session_reset(pompom_session_t *sess) {
    uint8_t key[8];
    memcpy(key, sess->key, 8);
    memset(sess, 0, sizeof(*sess));
    memcpy(sess->key, key, 8);
}

int pompom_pkt_hello(pompom_session_t *sess,
                     uint8_t *out, size_t outsize) {
    if (outsize < POMPOM_HDR_SIZE + 4)
        return -1;

    fill_random(sess->local_nonce, 4);

    write_hdr(out, POMPOM_PKT_HELLO, 0, 0, 4);
    memcpy(out + POMPOM_HDR_SIZE, sess->local_nonce, 4);

    return POMPOM_HDR_SIZE + 4;
}

int pompom_pkt_accept(pompom_session_t *sess,
                      const uint8_t *hello_pkt, size_t hello_len,
                      uint8_t *out, size_t outsize) {
    if (hello_len < POMPOM_HDR_SIZE + 4 || outsize < POMPOM_HDR_SIZE + 4)
        return -1;
    if (get16(hello_pkt) != POMPOM_PROTO_MAGIC || hello_pkt[2] != POMPOM_PKT_HELLO)
        return -1;

    /* Extract client nonce */
    memcpy(sess->remote_nonce, hello_pkt + POMPOM_HDR_SIZE, 4);

    /* Generate server nonce */
    fill_random(sess->local_nonce, 4);

    /* Derive session keys (we are server) */
    derive_session(sess, 1);

    /* Write ACCEPT */
    write_hdr(out, POMPOM_PKT_ACCEPT, 0, 0, 4);
    memcpy(out + POMPOM_HDR_SIZE, sess->local_nonce, 4);

    return POMPOM_HDR_SIZE + 4;
}

int pompom_pkt_finish(pompom_session_t *sess,
                      const uint8_t *accept_pkt, size_t accept_len) {
    if (accept_len < POMPOM_HDR_SIZE + 4)
        return -1;
    if (get16(accept_pkt) != POMPOM_PROTO_MAGIC || accept_pkt[2] != POMPOM_PKT_ACCEPT)
        return -1;

    /* Extract server nonce */
    memcpy(sess->remote_nonce, accept_pkt + POMPOM_HDR_SIZE, 4);

    /* Derive session keys (we are client) */
    derive_session(sess, 0);

    return 0;
}

int pompom_pkt_encode(pompom_session_t *sess,
                      uint8_t type,
                      const uint8_t *data, size_t len,
                      uint8_t *out, size_t outsize) {
    if (!sess->established)
        return -1;
    if (len > POMPOM_MAX_PAYLOAD)
        return -1;
    if (outsize < POMPOM_HDR_SIZE + len)
        return -1;

    /* Write header */
    write_hdr(out, type, 0, sess->tx_seq, (uint16_t)len);

    /* Encrypt payload */
    if (len > 0)
        pompom_crypt(&sess->tx, data, out + POMPOM_HDR_SIZE, len);

    sess->tx_seq++;
    return (int)(POMPOM_HDR_SIZE + len);
}

int pompom_pkt_decode(pompom_session_t *sess,
                      const uint8_t *pkt, size_t pktlen,
                      uint8_t *type,
                      uint8_t *out, size_t *outlen) {
    if (pktlen < POMPOM_HDR_SIZE)
        return -1;

    /* Validate magic */
    if (get16(pkt) != POMPOM_PROTO_MAGIC)
        return -1;

    uint8_t  pkt_type = pkt[2];
    uint32_t seq      = get32(pkt + 4);
    uint16_t len      = get16(pkt + 8);

    if (pktlen < POMPOM_HDR_SIZE + len)
        return -1;

    /* Handshake packets are unencrypted */
    if (pkt_type == POMPOM_PKT_HELLO || pkt_type == POMPOM_PKT_ACCEPT) {
        *type = pkt_type;
        if (len > 0 && out)
            memcpy(out, pkt + POMPOM_HDR_SIZE, len);
        *outlen = len;
        return 0;
    }

    /* Encrypted packets require established session */
    if (!sess->established)
        return -1;

    /* Reject out-of-order / replay: rolling cipher requires sequential processing */
    if (seq != sess->rx_seq)
        return -1;

    /* Decrypt payload */
    if (len > 0)
        pompom_crypt(&sess->rx, pkt + POMPOM_HDR_SIZE, out, len);

    *type = pkt_type;
    *outlen = len;
    sess->rx_seq++;

    return 0;
}
