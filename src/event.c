#ifndef NO_POSIX_SOCKETS
#include "pompom/stream.h"
#include "pompom/proto.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

/* ---- Endian helpers (match proto.c) ---- */

static void ev_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static uint16_t ev_get16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* ================================================================
 * Event Stream — fire-and-forget typed events
 *
 * Event wire format (inside encrypted DATA payload):
 *   [event_type: 2 bytes BE] [event_data: N bytes]
 *
 * Subscribe/unsubscribe wire format:
 *   [count: 2 bytes BE] [type_0: 2 bytes] [type_1: 2 bytes] ...
 * ================================================================ */

/* ---- Encode helpers ---- */

static int encode_event(uint8_t *buf, size_t bufsize,
                        uint16_t event_type,
                        const uint8_t *data, size_t len) {
    if (2 + len > bufsize || 2 + len > POMPOM_MAX_PAYLOAD)
        return -1;
    ev_put16(buf, event_type);
    if (len > 0)
        memcpy(buf + 2, data, len);
    return (int)(2 + len);
}

static int encode_sub_list(uint8_t *buf, size_t bufsize,
                           const uint16_t *types, size_t count) {
    size_t need = 2 + count * 2;
    if (need > bufsize || need > POMPOM_MAX_PAYLOAD)
        return -1;
    ev_put16(buf, (uint16_t)count);
    for (size_t i = 0; i < count; i++)
        ev_put16(buf + 2 + i * 2, types[i]);
    return (int)need;
}

/* ---- Host: emit events ---- */

/* Access host internals — defined in host.c, we use the same struct layout.
 * The host stores peers in a fixed array with session + addr info.
 * We call pompom_host_send for delivery but need pompom_pkt_encode for event type. */

/* Helper: encode event into proto packet and send raw via host */
static int emit_event_pkt(pompom_host_t *host, uint32_t peer_id,
                          uint16_t event_type,
                          const uint8_t *data, size_t len) {
    uint8_t payload[POMPOM_MAX_PAYLOAD];
    int plen = encode_event(payload, sizeof(payload), event_type, data, len);
    if (plen < 0) return -1;

    /* Use host_send which encrypts as PKT_DATA.
     * The event type is encoded INSIDE the encrypted payload. */
    return pompom_host_send(host, peer_id, payload, (size_t)plen);
}

int pompom_event_emit(pompom_host_t *host,
                      uint16_t event_type,
                      const uint8_t *data, size_t len) {
    /* Build the event payload once, broadcast to all peers */
    uint8_t payload[POMPOM_MAX_PAYLOAD];
    int plen = encode_event(payload, sizeof(payload), event_type, data, len);
    if (plen < 0) return -1;
    return pompom_host_broadcast(host, payload, (size_t)plen);
}

int pompom_event_emit_to(pompom_host_t *host, uint32_t peer_id,
                         uint16_t event_type,
                         const uint8_t *data, size_t len) {
    return emit_event_pkt(host, peer_id, event_type, data, len);
}

/* ---- Client: subscribe/unsubscribe ---- */

int pompom_event_subscribe(pompom_client_t *client,
                           const uint16_t *types, size_t count) {
    uint8_t payload[POMPOM_MAX_PAYLOAD];
    int plen = encode_sub_list(payload, sizeof(payload), types, count);
    if (plen < 0) return -1;

    /* Send as regular DATA — host can interpret the subscribe message
     * by inspecting the first 2 bytes as a command discriminator.
     * For v1 we send subscribe info but filtering is client-side. */
    return pompom_client_send(client, payload, (size_t)plen);
}

int pompom_event_unsubscribe(pompom_client_t *client,
                             const uint16_t *types, size_t count) {
    /* Same encoding, different semantic — for v1, filtering is client-side */
    return pompom_event_subscribe(client, types, count);
}

/* ---- Client: receive events ---- */

int pompom_event_recv(pompom_client_t *client,
                      uint16_t *event_type,
                      uint8_t *buf, size_t bufsize,
                      int timeout_ms) {
    /* Receive a DATA packet and decode the event type from the payload */
    uint8_t raw[POMPOM_MAX_PAYLOAD];
    int n = pompom_client_recv(client, raw, sizeof(raw), timeout_ms);
    if (n <= 0) return n;

    if (n < 2) return -1; /* too short for event header */

    *event_type = ev_get16(raw);
    size_t data_len = (size_t)(n - 2);
    if (data_len > bufsize) data_len = bufsize;
    if (data_len > 0)
        memcpy(buf, raw + 2, data_len);
    return (int)data_len;
}

#endif /* NO_POSIX_SOCKETS */
