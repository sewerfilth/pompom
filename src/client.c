#ifndef NO_POSIX_SOCKETS
#include "pompom/net.h"
#include "pompom/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

struct pompom_client {
    int              fd;
    pompom_session_t session;
};

pompom_client_t *pompom_client_connect(const uint8_t key[8],
                                       const char *host, uint16_t port) {
    /* Resolve host */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }

    /* "Connect" the UDP socket so we can use send/recv */
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);

    pompom_client_t *c = calloc(1, sizeof(*c));
    if (!c) { close(fd); return NULL; }
    c->fd = fd;
    pompom_session_init(&c->session, key);

    /* ---- Handshake ---- */

    /* Send HELLO */
    uint8_t hello[POMPOM_HDR_SIZE + 4];
    int hlen = pompom_pkt_hello(&c->session, hello, sizeof(hello));
    if (hlen < 0 || send(fd, hello, (size_t)hlen, 0) != hlen)
        goto fail;

    /* Wait for ACCEPT (3 second timeout) */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, 3000) <= 0)
        goto fail;

    uint8_t accept_buf[POMPOM_HDR_SIZE + 4];
    ssize_t n = recv(fd, accept_buf, sizeof(accept_buf), 0);
    if (n < (ssize_t)(POMPOM_HDR_SIZE + 4))
        goto fail;

    if (pompom_pkt_finish(&c->session, accept_buf, (size_t)n) != 0)
        goto fail;

    return c;

fail:
    close(fd);
    free(c);
    return NULL;
}

void pompom_client_destroy(pompom_client_t *c) {
    if (!c) return;

    /* Best-effort CLOSE */
    if (c->session.established) {
        uint8_t pkt[POMPOM_HDR_SIZE];
        int pkt_len = pompom_pkt_encode(&c->session, POMPOM_PKT_CLOSE,
                                         NULL, 0, pkt, sizeof(pkt));
        if (pkt_len > 0)
            send(c->fd, pkt, (size_t)pkt_len, 0);
    }

    close(c->fd);
    free(c);
}

int pompom_client_send(pompom_client_t *c,
                       const uint8_t *data, size_t len) {
    uint8_t pkt[POMPOM_HDR_SIZE + POMPOM_MAX_PAYLOAD];
    int pkt_len = pompom_pkt_encode(&c->session, POMPOM_PKT_DATA,
                                     data, len, pkt, sizeof(pkt));
    if (pkt_len < 0) return -1;

    ssize_t sent = send(c->fd, pkt, (size_t)pkt_len, 0);
    return sent > 0 ? 0 : -1;
}

int pompom_client_recv(pompom_client_t *c,
                       uint8_t *buf, size_t bufsize,
                       int timeout_ms) {
    (void)bufsize;
    uint8_t raw[POMPOM_HDR_SIZE + POMPOM_MAX_PAYLOAD];

    for (;;) {
        struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0) return -1;
        if (ready == 0) return 0;

        ssize_t n = recv(c->fd, raw, sizeof(raw), 0);
        if (n < (ssize_t)POMPOM_HDR_SIZE) continue;

        uint8_t pkt_type;
        size_t  outlen = 0;
        if (pompom_pkt_decode(&c->session, raw, (size_t)n,
                               &pkt_type, buf, &outlen) != 0)
            continue;

        if (pkt_type == POMPOM_PKT_CLOSE)
            return -1;

        if (pkt_type == POMPOM_PKT_PING)
            continue;

        if (pkt_type == POMPOM_PKT_DATA)
            return (int)outlen;
    }
}

#endif /* NO_POSIX_SOCKETS */
