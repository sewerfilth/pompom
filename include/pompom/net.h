#ifndef POMPOM_NET_H
#define POMPOM_NET_H

#include <stdint.h>
#include <stddef.h>

#define POMPOM_MAX_PEERS 64

/* ================================================================
 * Host (server)
 *
 * Usage:
 *   pompom_host_t *h = pompom_host_create(key, 9900);
 *   while (running) {
 *       uint32_t peer;
 *       int n = pompom_host_recv(h, &peer, buf, sizeof(buf), 1000);
 *       if (n > 0) pompom_host_send(h, peer, buf, n);  // echo
 *   }
 *   pompom_host_destroy(h);
 *
 * Handshakes are handled transparently — recv only returns
 * decrypted DATA payloads.
 * ================================================================ */

typedef struct pompom_host pompom_host_t;

/* Bind a UDP host on the given port with a pre-shared key. */
pompom_host_t *pompom_host_create(const uint8_t key[8], uint16_t port);

/* Destroy host, close socket, free all peers. */
void pompom_host_destroy(pompom_host_t *host);

/*
 * Receive the next DATA payload from any peer.
 * Handshakes (HELLO/ACCEPT) and keepalives are consumed internally.
 * Returns payload bytes written to buf, 0 on timeout, -1 on error.
 * Sets *peer_id to the sending peer's ID.
 * timeout_ms: -1 = block forever, 0 = non-blocking.
 */
int pompom_host_recv(pompom_host_t *host, uint32_t *peer_id,
                     uint8_t *buf, size_t bufsize, int timeout_ms);

/* Send encrypted DATA to a specific peer. Returns 0 or -1. */
int pompom_host_send(pompom_host_t *host, uint32_t peer_id,
                     const uint8_t *data, size_t len);

/* Send encrypted DATA to all connected peers. Returns 0 or -1. */
int pompom_host_broadcast(pompom_host_t *host,
                          const uint8_t *data, size_t len);

/* Disconnect a peer (sends CLOSE, removes session). */
void pompom_host_kick(pompom_host_t *host, uint32_t peer_id);

/* Number of currently connected peers. */
int pompom_host_peer_count(const pompom_host_t *host);

/* ================================================================
 * Client
 *
 * Usage:
 *   pompom_client_t *c = pompom_client_connect(key, "127.0.0.1", 9900);
 *   pompom_client_send(c, data, len);
 *   int n = pompom_client_recv(c, buf, sizeof(buf), 5000);
 *   pompom_client_destroy(c);
 *
 * The handshake (HELLO → ACCEPT) is performed inside connect().
 * ================================================================ */

typedef struct pompom_client pompom_client_t;

/*
 * Connect to a pompom host. Performs the full handshake.
 * Returns NULL on failure (timeout, wrong key, network error).
 */
pompom_client_t *pompom_client_connect(const uint8_t key[8],
                                       const char *host, uint16_t port);

/* Destroy client, close socket. */
void pompom_client_destroy(pompom_client_t *client);

/* Send encrypted DATA to the host. Returns 0 or -1. */
int pompom_client_send(pompom_client_t *client,
                       const uint8_t *data, size_t len);

/*
 * Receive the next DATA payload from the host.
 * Returns payload bytes, 0 on timeout, -1 on error/disconnect.
 */
int pompom_client_recv(pompom_client_t *client,
                       uint8_t *buf, size_t bufsize, int timeout_ms);

#endif
