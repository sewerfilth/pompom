/*
 * pompom host — echo server example
 *
 * Build:  make examples
 * Run:    ./build/<arch>/pompom_host
 *
 * Listens on UDP :9900, echoes all messages back to sender.
 * Handles multiple clients. Ctrl+C to stop.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "pompom/net.h"

static volatile int running = 1;

static void on_signal(int sig) { (void)sig; running = 0; }

int main(int argc, char **argv) {
    uint16_t port = 9900;
    if (argc > 1) port = (uint16_t)atoi(argv[1]);

    /* Pre-shared key — in a real app this comes from config/env */
    uint8_t key[8] = { 0x70,0x6F,0x6D,0x70,0x6F,0x6D,0x21,0x21 }; /* "pompom!!" */

    pompom_host_t *host = pompom_host_create(key, port);
    if (!host) {
        fprintf(stderr, "failed to bind port %u\n", port);
        return 1;
    }

    signal(SIGINT, on_signal);
    printf("pompom host listening on :%u (ctrl+c to stop)\n", port);

    uint8_t buf[1500];
    uint32_t peer;

    while (running) {
        int n = pompom_host_recv(host, &peer, buf, sizeof(buf), 1000);
        if (n < 0) break;
        if (n == 0) continue;   /* timeout, loop */

        printf("[peer %u] (%d bytes) %.*s\n", peer, n, n, (char *)buf);

        /* Echo back */
        pompom_host_send(host, peer, buf, (size_t)n);
    }

    printf("\nshutting down (%d peers connected)\n",
           pompom_host_peer_count(host));
    pompom_host_destroy(host);
    return 0;
}
