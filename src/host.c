#ifndef NO_POSIX_SOCKETS
#include "pompom/net.h"
#include "pompom/proto.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    pompom_session_t        session;
    uint32_t                id;
    uint8_t                 active;
} peer_t;

struct pompom_host {
    int       fd;
    uint8_t   key[8];
    peer_t    peers[POMPOM_MAX_PEERS];
    uint32_t  next_id;
    int       peer_count;
};

/* ---- Peer management ---- */

static peer_t *find_peer_by_addr(pompom_host_t *h,
                                  const struct sockaddr_storage *addr,
                                  socklen_t addr_len) {
    for (int i = 0; i < POMPOM_MAX_PEERS; i++) {
        peer_t *p = &h->peers[i];
        if (!p->active) continue;
        if (p->addr_len != addr_len) continue;
        if (p->addr.ss_family != addr->ss_family) continue;
        if (addr->ss_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
            const struct sockaddr_in *b = (const struct sockaddr_in *)&p->addr;
            if (a->sin_port == b->sin_port &&
                a->sin_addr.s_addr == b->sin_addr.s_addr)
                return p;
        }
        if (addr->ss_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
            const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)&p->addr;
            if (a->sin6_port == b->sin6_port &&
                memcmp(&a->sin6_addr, &b->sin6_addr, 16) == 0)
                return p;
        }
    }
    return NULL;
}

static peer_t *find_peer_by_id(pompom_host_t *h, uint32_t id) {
    for (int i = 0; i < POMPOM_MAX_PEERS; i++) {
        if (h->peers[i].active && h->peers[i].id == id)
            return &h->peers[i];
    }
    return NULL;
}

static peer_t *alloc_peer(pompom_host_t *h,
                           const struct sockaddr_storage *addr,
                           socklen_t addr_len) {
    for (int i = 0; i < POMPOM_MAX_PEERS; i++) {
        peer_t *p = &h->peers[i];
        if (p->active) continue;

        memcpy(&p->addr, addr, addr_len);
        p->addr_len = addr_len;
        pompom_session_init(&p->session, h->key);
        p->id = ++h->next_id;
        p->active = 1;
        h->peer_count++;
        return p;
    }
    return NULL; /* full */
}

static void remove_peer(pompom_host_t *h, peer_t *p) {
    p->active = 0;
    h->peer_count--;
}

/* ---- Public API ---- */

pompom_host_t *pompom_host_create(const uint8_t key[8], uint16_t port) {
    pompom_host_t *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    memcpy(h->key, key, 8);

    h->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (h->fd < 0) {
        h->fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (h->fd < 0) { free(h); return NULL; }

        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr.s_addr = INADDR_ANY;
        if (bind(h->fd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
            close(h->fd); free(h); return NULL;
        }
    } else {
        int off = 0;
        setsockopt(h->fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr6.sin6_addr = in6addr_any;
        if (bind(h->fd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
            close(h->fd); free(h); return NULL;
        }
    }

    return h;
}

void pompom_host_destroy(pompom_host_t *h) {
    if (!h) return;
    close(h->fd);
    free(h);
}

int pompom_host_recv(pompom_host_t *h, uint32_t *peer_id,
                     uint8_t *buf, size_t bufsize,
                     int timeout_ms) {
    (void)bufsize;
    uint8_t raw[POMPOM_HDR_SIZE + POMPOM_MAX_PAYLOAD];

    for (;;) {
        struct pollfd pfd = { .fd = h->fd, .events = POLLIN };
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0) return -1;
        if (ready == 0) return 0;

        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(h->fd, raw, sizeof(raw), 0,
                              (struct sockaddr *)&from, &fromlen);
        if (n < (ssize_t)POMPOM_HDR_SIZE) continue;

        /* Look up peer */
        peer_t *p = find_peer_by_addr(h, &from, fromlen);

        /* Handshake: new peer sending HELLO */
        if (!p && raw[2] == POMPOM_PKT_HELLO) {
            p = alloc_peer(h, &from, fromlen);
            if (!p) continue;   /* full, ignore */

            uint8_t accept_buf[POMPOM_HDR_SIZE + 4];
            int alen = pompom_pkt_accept(&p->session, raw, (size_t)n,
                                          accept_buf, sizeof(accept_buf));
            if (alen > 0)
                sendto(h->fd, accept_buf, (size_t)alen, 0,
                       (struct sockaddr *)&from, fromlen);
            continue;   /* handshake consumed, wait for DATA */
        }

        if (!p) continue;   /* unknown peer, not HELLO — drop */

        /* Decode packet */
        uint8_t pkt_type;
        size_t  outlen = 0;
        if (pompom_pkt_decode(&p->session, raw, (size_t)n,
                               &pkt_type, buf, &outlen) != 0)
            continue;   /* bad packet, drop */

        if (pkt_type == POMPOM_PKT_CLOSE) {
            remove_peer(h, p);
            continue;
        }

        if (pkt_type == POMPOM_PKT_PING)
            continue;

        if (pkt_type == POMPOM_PKT_DATA) {
            *peer_id = p->id;
            return (int)outlen;
        }
    }
}

int pompom_host_send(pompom_host_t *h, uint32_t peer_id,
                     const uint8_t *data, size_t len) {
    peer_t *p = find_peer_by_id(h, peer_id);
    if (!p) return -1;

    uint8_t pkt[POMPOM_HDR_SIZE + POMPOM_MAX_PAYLOAD];
    int pkt_len = pompom_pkt_encode(&p->session, POMPOM_PKT_DATA,
                                     data, len, pkt, sizeof(pkt));
    if (pkt_len < 0) return -1;

    ssize_t sent = sendto(h->fd, pkt, (size_t)pkt_len, 0,
                           (struct sockaddr *)&p->addr, p->addr_len);
    return sent > 0 ? 0 : -1;
}

int pompom_host_broadcast(pompom_host_t *h,
                          const uint8_t *data, size_t len) {
    int err = 0;
    for (int i = 0; i < POMPOM_MAX_PEERS; i++) {
        if (!h->peers[i].active) continue;
        if (pompom_host_send(h, h->peers[i].id, data, len) < 0)
            err = -1;
    }
    return err;
}

void pompom_host_kick(pompom_host_t *h, uint32_t peer_id) {
    peer_t *p = find_peer_by_id(h, peer_id);
    if (!p) return;

    uint8_t pkt[POMPOM_HDR_SIZE];
    int pkt_len = pompom_pkt_encode(&p->session, POMPOM_PKT_CLOSE,
                                     NULL, 0, pkt, sizeof(pkt));
    if (pkt_len > 0)
        sendto(h->fd, pkt, (size_t)pkt_len, 0,
               (struct sockaddr *)&p->addr, p->addr_len);
    remove_peer(h, p);
}

int pompom_host_peer_count(const pompom_host_t *h) {
    return h->peer_count;
}

#endif /* NO_POSIX_SOCKETS */
