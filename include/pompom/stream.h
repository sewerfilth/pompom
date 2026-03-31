#ifndef POMPOM_STREAM_H
#define POMPOM_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include "pompom/net.h"

/* ================================================================
 * Event Stream — fire-and-forget typed events (WSS/SSE-like)
 *
 * Host emits events, clients receive them. Clients can subscribe
 * to specific event types to filter traffic. No ACKs, no ordering
 * guarantees beyond what UDP provides — designed for real-time
 * updates where latest-value-wins.
 *
 * Usage (host):
 *   pompom_event_emit(host, EVT_PRICE_UPDATE, data, len);
 *   pompom_event_emit_to(host, peer, EVT_CHAT_MSG, data, len);
 *
 * Usage (client):
 *   uint16_t subs[] = { EVT_PRICE_UPDATE, EVT_CHAT_MSG };
 *   pompom_event_subscribe(client, subs, 2);
 *   uint16_t type;
 *   int n = pompom_event_recv(client, &type, buf, sizeof(buf), 1000);
 * ================================================================ */

/* Wire: [event_type: u16 BE] [payload: N bytes] */
#define POMPOM_PKT_EVENT       0x10
#define POMPOM_PKT_SUBSCRIBE   0x11
#define POMPOM_PKT_UNSUBSCRIBE 0x12

/* User-defined event types start here */
#define POMPOM_EVT_USER 0x0100

/* Maximum subscriptions per client */
#define POMPOM_MAX_SUBS 64

/* Host: broadcast event to all connected peers */
int pompom_event_emit(pompom_host_t *host,
                      uint16_t event_type,
                      const uint8_t *data, size_t len);

/* Host: send event to specific peer */
int pompom_event_emit_to(pompom_host_t *host, uint32_t peer_id,
                         uint16_t event_type,
                         const uint8_t *data, size_t len);

/* Client: subscribe to event types (additive) */
int pompom_event_subscribe(pompom_client_t *client,
                           const uint16_t *types, size_t count);

/* Client: unsubscribe from event types */
int pompom_event_unsubscribe(pompom_client_t *client,
                             const uint16_t *types, size_t count);

/* Client: receive next event. Returns payload bytes, 0 on timeout, -1 on error.
 * Sets *event_type to the event type code. */
int pompom_event_recv(pompom_client_t *client,
                      uint16_t *event_type,
                      uint8_t *buf, size_t bufsize,
                      int timeout_ms);

/* ================================================================
 * Reliable Pipe — chunked byte stream with ACKs (TCP-like)
 *
 * Multiplexed streams over a single pompom session. Each stream
 * has its own chunk sequencing, sliding window, and retransmit.
 * Designed for file transfer, large payloads, and proxy tunnels.
 *
 * Usage (sender):
 *   pompom_pipe_t *p = pompom_pipe_open(client, "photo.jpg", filesize);
 *   while (remaining > 0)
 *     pompom_pipe_write(p, chunk, len);
 *   pompom_pipe_finish(p);
 *
 * Usage (receiver):
 *   pompom_pipe_t *p = pompom_pipe_accept(host, &peer, name, ...);
 *   while ((n = pompom_pipe_read(p, buf, sizeof(buf), 1000)) > 0)
 *     write(fd, buf, n);
 *   pompom_pipe_close(p);
 * ================================================================ */

#define POMPOM_PKT_PIPE_OPEN   0x20
#define POMPOM_PKT_PIPE_CHUNK  0x21
#define POMPOM_PKT_PIPE_ACK    0x22
#define POMPOM_PKT_PIPE_FIN    0x23
#define POMPOM_PKT_PIPE_RST    0x24

/*
 * Wire formats:
 *   PIPE_OPEN:  [stream_id:4] [flags:1] [total_size:8] [name_len:2] [name:N]
 *   PIPE_CHUNK: [stream_id:4] [chunk_seq:4] [data:N]
 *   PIPE_ACK:   [stream_id:4] [ack_seq:4] [window:2]
 *   PIPE_FIN:   [stream_id:4] [sha256:32]
 *   PIPE_RST:   [stream_id:4] [reason:1]
 */

#define POMPOM_PIPE_CHUNK_SIZE  1400  /* max data per chunk (fits in one packet) */
#define POMPOM_PIPE_WINDOW      16    /* chunks in flight before backpressure */
#define POMPOM_PIPE_MAX_STREAMS 16    /* concurrent streams per session */
#define POMPOM_PIPE_RETRANSMIT_MS 500 /* retransmit timeout */
#define POMPOM_PIPE_NAME_MAX    255

/* Pipe flags (PIPE_OPEN) */
#define POMPOM_PIPE_FLAG_FILE   0x01  /* this is a file transfer */
#define POMPOM_PIPE_FLAG_PROXY  0x02  /* this is a proxy tunnel */

typedef struct pompom_pipe pompom_pipe_t;

/* Open a reliable pipe to the host (client side) */
pompom_pipe_t *pompom_pipe_open(pompom_client_t *client,
                                const char *name,
                                uint64_t total_size,
                                uint8_t flags);

/* Open a reliable pipe to a specific peer (host side) */
pompom_pipe_t *pompom_pipe_open_to(pompom_host_t *host, uint32_t peer_id,
                                   const char *name,
                                   uint64_t total_size,
                                   uint8_t flags);

/* Accept an incoming pipe. Returns NULL on timeout.
 * Caller provides buffers for name and total_size. */
pompom_pipe_t *pompom_pipe_accept(pompom_host_t *host,
                                  uint32_t *peer_id,
                                  char *name, size_t namesize,
                                  uint64_t *total_size,
                                  uint8_t *flags,
                                  int timeout_ms);

/* Write data into the pipe (may block for window space). */
int pompom_pipe_write(pompom_pipe_t *pipe,
                      const uint8_t *data, size_t len);

/* Read data from the pipe (reassembled, in order). */
int pompom_pipe_read(pompom_pipe_t *pipe,
                     uint8_t *buf, size_t bufsize,
                     int timeout_ms);

/* Signal end of stream. Sends FIN with SHA-256 integrity hash. */
int pompom_pipe_finish(pompom_pipe_t *pipe);

/* Close and free pipe resources. */
void pompom_pipe_close(pompom_pipe_t *pipe);

/* Progress queries */
uint64_t pompom_pipe_bytes_sent(const pompom_pipe_t *pipe);
uint64_t pompom_pipe_bytes_acked(const pompom_pipe_t *pipe);
uint64_t pompom_pipe_total(const pompom_pipe_t *pipe);

/* ================================================================
 * Incoming Proxy — tunnel external TCP through pompom
 *
 * Host listens for PIPE_OPEN with FLAG_PROXY, connects to the
 * target TCP service, and relays data bidirectionally through
 * the encrypted pompom pipe.
 *
 *   Internet → pompom client → [encrypted UDP] → pompom host
 *              → [plaintext TCP] → internal service
 *
 * Usage (host — expose internal service):
 *   pompom_proxy_rule_t rule = { .name = "ssh", .target_host = "127.0.0.1", .target_port = 22 };
 *   pompom_proxy_add_rule(host, &rule);
 *
 * Usage (client — connect to proxied service):
 *   pompom_pipe_t *p = pompom_proxy_connect(client, "ssh");
 *   pompom_pipe_write(p, ssh_data, len);
 *   int n = pompom_pipe_read(p, buf, sizeof(buf), 1000);
 * ================================================================ */

#define POMPOM_MAX_PROXY_RULES 16

typedef struct {
    char     name[POMPOM_PIPE_NAME_MAX + 1];
    char     target_host[256];
    uint16_t target_port;
} pompom_proxy_rule_t;

/* Host: register a proxy rule (name → target host:port) */
int pompom_proxy_add_rule(pompom_host_t *host, const pompom_proxy_rule_t *rule);

/* Host: remove a proxy rule by name */
int pompom_proxy_remove_rule(pompom_host_t *host, const char *name);

/* Client: open a proxy pipe to a named service on the host */
pompom_pipe_t *pompom_proxy_connect(pompom_client_t *client, const char *service_name);

#endif
