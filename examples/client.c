/*
 * pompom client — interactive chat example
 *
 * Build:  make examples
 * Run:    ./build/<arch>/pompom_client [host] [port]
 *
 * Connects to a pompom host, sends lines from stdin,
 * prints encrypted replies from the host.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include "pompom/net.h"

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t port = 9900;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = (uint16_t)atoi(argv[2]);

    /* Same PSK as the host */
    uint8_t key[8] = { 0x70,0x6F,0x6D,0x70,0x6F,0x6D,0x21,0x21 };

    printf("connecting to %s:%u...\n", host, port);
    pompom_client_t *cli = pompom_client_connect(key, host, port);
    if (!cli) {
        fprintf(stderr, "connection failed\n");
        return 1;
    }
    printf("connected! type messages (ctrl+d to quit)\n\n");

    char line[1024];
    uint8_t buf[1500];

    for (;;) {
        /* Poll both stdin and the socket */
        struct pollfd fds[2];
        fds[0].fd = 0;          /* stdin */
        fds[0].events = POLLIN;
        fds[1].fd = -1;         /* placeholder — we'll check client manually */
        fds[1].events = 0;

        /* Check for user input */
        int ready = poll(fds, 1, 100);

        if (ready > 0 && (fds[0].revents & POLLIN)) {
            if (!fgets(line, sizeof(line), stdin))
                break;  /* EOF */

            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n')
                line[--len] = '\0';
            if (len == 0) continue;

            if (pompom_client_send(cli, (const uint8_t *)line, len) < 0) {
                fprintf(stderr, "send failed\n");
                break;
            }
        }

        /* Check for incoming data (non-blocking) */
        int n = pompom_client_recv(cli, buf, sizeof(buf) - 1, 0);
        if (n < 0) {
            printf("disconnected\n");
            break;
        }
        if (n > 0) {
            buf[n] = '\0';
            printf("  <- %s\n", (char *)buf);
        }
    }

    pompom_client_destroy(cli);
    return 0;
}
