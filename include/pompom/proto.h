#ifndef POMPOM_PROTO_H
#define POMPOM_PROTO_H

#include <stdint.h>
#include <stddef.h>
#include "pompom/cipher.h"

/* ---- Wire format ---- */

#define POMPOM_PROTO_MAGIC  0x5050   /* "PP" on the wire (big-endian) */
#define POMPOM_HDR_SIZE     10
#define POMPOM_MAX_PAYLOAD  1460     /* fits in standard MTU (1500-20-8-12) */

#define POMPOM_PKT_HELLO    0x00     /* handshake init  (cleartext) */
#define POMPOM_PKT_ACCEPT   0x01     /* handshake reply (cleartext) */
#define POMPOM_PKT_DATA     0x02     /* encrypted payload */
#define POMPOM_PKT_PING     0x03     /* encrypted keepalive (empty body) */
#define POMPOM_PKT_CLOSE    0x04     /* encrypted session close */

/*
 * Packet layout (all multi-byte fields big-endian):
 *
 *  0      2    3    4        8      10
 *  ┌──────┬────┬────┬────────┬──────┐
 *  │magic │type│flag│  seq   │ len  │  <- header (10 bytes)
 *  ├──────┴────┴────┴────────┴──────┤
 *  │         payload (len bytes)    │  <- encrypted for DATA/PING/CLOSE
 *  └────────────────────────────────┘
 */

/* ---- Session ---- */

typedef struct {
    pompom_state_t tx;           /* outbound cipher state */
    pompom_state_t rx;           /* inbound cipher state */
    uint32_t       tx_seq;       /* next outbound sequence number */
    uint32_t       rx_seq;       /* next expected inbound sequence */
    uint8_t        key[8];       /* pre-shared key */
    uint8_t        established;  /* 1 after handshake complete */

    /* Handshake state */
    uint8_t  local_nonce[4];
    uint8_t  remote_nonce[4];
} pompom_session_t;

/* ---- Packet codec (transport-agnostic) ---- */

/*
 * Encode a HELLO packet (client → server).
 * Writes to `out`, returns bytes written or -1 on error.
 * Generates a random local nonce and stores it in sess.
 */
int pompom_pkt_hello(pompom_session_t *sess,
                     uint8_t *out, size_t outsize);

/*
 * Encode an ACCEPT packet (server → client).
 * Call after receiving a HELLO.
 * Generates server nonce, derives session keys, marks established.
 */
int pompom_pkt_accept(pompom_session_t *sess,
                      const uint8_t *hello_pkt, size_t hello_len,
                      uint8_t *out, size_t outsize);

/*
 * Finalize handshake on the client side after receiving ACCEPT.
 * Derives session keys and marks established.
 */
int pompom_pkt_finish(pompom_session_t *sess,
                      const uint8_t *accept_pkt, size_t accept_len);

/*
 * Encode a DATA packet: header + encrypt payload.
 * Returns total packet size or -1 on error.
 */
int pompom_pkt_encode(pompom_session_t *sess,
                      uint8_t type,
                      const uint8_t *data, size_t len,
                      uint8_t *out, size_t outsize);

/*
 * Decode any received packet.
 * On success: writes decrypted payload to `out`, sets `*outlen`,
 *             sets `*type` to the packet type, returns 0.
 * On failure: returns -1 (bad magic, replay, too short, etc.).
 */
int pompom_pkt_decode(pompom_session_t *sess,
                      const uint8_t *pkt, size_t pktlen,
                      uint8_t *type,
                      uint8_t *out, size_t *outlen);

/* ---- Session lifecycle ---- */

/* Initialize session with a pre-shared key. */
void pompom_session_init(pompom_session_t *sess, const uint8_t key[8]);

/* Reset session (clear cipher state, keep key). */
void pompom_session_reset(pompom_session_t *sess);

#endif
