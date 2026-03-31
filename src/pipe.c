#include "pompom/stream.h"
#include "pompom/proto.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

/* ---- Endian helpers ---- */

static void pp_put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void pp_put32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static void pp_put64(uint8_t *p, uint64_t v) { pp_put32(p,(uint32_t)(v>>32)); pp_put32(p+4,(uint32_t)v); }
static uint16_t pp_get16(const uint8_t *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t pp_get32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint64_t pp_get64(const uint8_t *p) { return ((uint64_t)pp_get32(p)<<32)|pp_get32(p+4); }

/* ---- Simple SHA-256 (lightweight, no dependency) ---- */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define SIG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define SIG1(x) (RR(x,17)^RR(x,19)^((x)>>10))

typedef struct { uint32_t h[8]; uint8_t buf[64]; uint64_t len; int buflen; } sha256_ctx;

static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len=0; c->buflen=0;
}

static void sha256_block(sha256_ctx *c) {
    uint32_t w[64], t1, t2;
    for(int i=0;i<16;i++) w[i]=(uint32_t)c->buf[i*4]<<24|(uint32_t)c->buf[i*4+1]<<16|(uint32_t)c->buf[i*4+2]<<8|c->buf[i*4+3];
    for(int i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    uint32_t s[8]={c->h[0],c->h[1],c->h[2],c->h[3],c->h[4],c->h[5],c->h[6],c->h[7]};
    for(int i=0;i<64;i++){
        t1=s[7]+EP1(s[4])+CH(s[4],s[5],s[6])+K[i]+w[i];
        t2=EP0(s[0])+MAJ(s[0],s[1],s[2]);
        s[7]=s[6];s[6]=s[5];s[5]=s[4];s[4]=s[3]+t1;s[3]=s[2];s[2]=s[1];s[1]=s[0];s[0]=t1+t2;
    }
    for(int i=0;i<8;i++) c->h[i]+=s[i];
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    for(size_t i=0;i<len;i++){
        c->buf[c->buflen++]= data[i]; c->len++;
        if(c->buflen==64){sha256_block(c);c->buflen=0;}
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    c->buf[c->buflen++]=0x80;
    if(c->buflen>56){while(c->buflen<64)c->buf[c->buflen++]=0;sha256_block(c);c->buflen=0;}
    while(c->buflen<56)c->buf[c->buflen++]=0;
    uint64_t bits=c->len*8;
    for(int i=7;i>=0;i--) c->buf[56+(7-i)]=(uint8_t)(bits>>(i*8));
    sha256_block(c);
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(c->h[i]>>24);out[i*4+1]=(uint8_t)(c->h[i]>>16);out[i*4+2]=(uint8_t)(c->h[i]>>8);out[i*4+3]=(uint8_t)c->h[i];}
}

/* ================================================================
 * Pipe internals
 * ================================================================ */

/* Chunk in the reassembly/retransmit buffer */
typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  data[POMPOM_PIPE_CHUNK_SIZE];
    uint8_t  acked;
    uint64_t sent_at_ms;
} chunk_t;

struct pompom_pipe {
    /* Identity */
    uint32_t stream_id;
    char     name[POMPOM_PIPE_NAME_MAX + 1];
    uint64_t total_size;
    uint8_t  flags;

    /* Transport (one of these is non-NULL) */
    pompom_client_t *client;
    pompom_host_t   *host;
    uint32_t         peer_id;

    /* Send state */
    uint32_t  next_chunk_seq;
    uint32_t  window_base;      /* oldest unacked chunk seq */
    chunk_t   send_buf[POMPOM_PIPE_WINDOW];
    int       send_count;       /* chunks in send_buf */
    uint64_t  bytes_written;

    /* Receive state */
    chunk_t   recv_buf[POMPOM_PIPE_WINDOW * 2];
    int       recv_count;
    uint32_t  recv_next_seq;    /* next expected chunk seq */
    uint64_t  bytes_read;

    /* Integrity */
    sha256_ctx sha_send;
    sha256_ctx sha_recv;
    uint8_t    finished;
};

static uint32_t next_stream_id(void) {
    static uint32_t counter = 1;
    return counter++;
}

static uint64_t now_ms(void) {
#ifdef __APPLE__
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom / 1000000;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* ---- Send/recv raw via client or host ---- */

static int pipe_send_raw(pompom_pipe_t *p, const uint8_t *data, size_t len) {
    if (p->client)
        return pompom_client_send(p->client, data, len);
    if (p->host)
        return pompom_host_send(p->host, p->peer_id, data, len);
    return -1;
}

static int pipe_recv_raw(pompom_pipe_t *p, uint8_t *buf, size_t bufsize, int timeout_ms) {
    if (p->client)
        return pompom_client_recv(p->client, buf, bufsize, timeout_ms);
    if (p->host)
        return pompom_host_recv(p->host, &p->peer_id, buf, bufsize, timeout_ms);
    return -1;
}

/* ---- Wire encode helpers ---- */

static int encode_pipe_open(uint8_t *buf, size_t bufsize,
                            uint32_t sid, uint8_t flags, uint64_t total,
                            const char *name) {
    size_t nlen = strlen(name);
    size_t need = 1 + 4 + 1 + 8 + 2 + nlen; /* type discriminator + fields */
    if (need > bufsize) return -1;
    buf[0] = POMPOM_PKT_PIPE_OPEN;
    pp_put32(buf + 1, sid);
    buf[5] = flags;
    pp_put64(buf + 6, total);
    pp_put16(buf + 14, (uint16_t)nlen);
    memcpy(buf + 16, name, nlen);
    return (int)need;
}

static int encode_pipe_chunk(uint8_t *buf, size_t bufsize,
                             uint32_t sid, uint32_t seq,
                             const uint8_t *data, size_t len) {
    size_t need = 1 + 4 + 4 + len;
    if (need > bufsize) return -1;
    buf[0] = POMPOM_PKT_PIPE_CHUNK;
    pp_put32(buf + 1, sid);
    pp_put32(buf + 5, seq);
    memcpy(buf + 9, data, len);
    return (int)need;
}

static int encode_pipe_ack(uint8_t *buf, size_t bufsize,
                           uint32_t sid, uint32_t ack_seq, uint16_t window) {
    if (bufsize < 11) return -1;
    buf[0] = POMPOM_PKT_PIPE_ACK;
    pp_put32(buf + 1, sid);
    pp_put32(buf + 5, ack_seq);
    pp_put16(buf + 9, window);
    return 11;
}

static int encode_pipe_fin(uint8_t *buf, size_t bufsize,
                           uint32_t sid, const uint8_t hash[32]) {
    if (bufsize < 37) return -1;
    buf[0] = POMPOM_PKT_PIPE_FIN;
    pp_put32(buf + 1, sid);
    memcpy(buf + 5, hash, 32);
    return 37;
}

/* ---- Send a chunk and record it in send buffer ---- */

static int send_chunk(pompom_pipe_t *p, uint32_t seq,
                      const uint8_t *data, size_t len) {
    uint8_t pkt[POMPOM_MAX_PAYLOAD];
    int plen = encode_pipe_chunk(pkt, sizeof(pkt), p->stream_id, seq, data, len);
    if (plen < 0) return -1;

    /* Record in send buffer for retransmit */
    int slot = (int)(seq % POMPOM_PIPE_WINDOW);
    chunk_t *c = &p->send_buf[slot];
    c->seq = seq;
    c->len = (uint16_t)len;
    memcpy(c->data, data, len);
    c->acked = 0;
    c->sent_at_ms = now_ms();

    return pipe_send_raw(p, pkt, (size_t)plen);
}

/* ---- Send ACK back to sender ---- */

static int send_ack(pompom_pipe_t *p, uint32_t ack_seq) {
    uint8_t pkt[16];
    uint16_t window = POMPOM_PIPE_WINDOW;
    int plen = encode_pipe_ack(pkt, sizeof(pkt), p->stream_id, ack_seq, window);
    if (plen < 0) return -1;
    return pipe_send_raw(p, pkt, (size_t)plen);
}

/* ---- Retransmit timed-out chunks ---- */

static void retransmit_expired(pompom_pipe_t *p) {
    uint64_t now = now_ms();
    for (int i = 0; i < POMPOM_PIPE_WINDOW; i++) {
        chunk_t *c = &p->send_buf[i];
        if (c->len > 0 && !c->acked && c->seq >= p->window_base) {
            if (now - c->sent_at_ms >= POMPOM_PIPE_RETRANSMIT_MS) {
                uint8_t pkt[POMPOM_MAX_PAYLOAD];
                int plen = encode_pipe_chunk(pkt, sizeof(pkt),
                                              p->stream_id, c->seq, c->data, c->len);
                if (plen > 0) {
                    pipe_send_raw(p, pkt, (size_t)plen);
                    c->sent_at_ms = now;
                }
            }
        }
    }
}

/* ---- Process incoming messages (dispatch by type byte) ---- */

static void process_incoming(pompom_pipe_t *p, const uint8_t *data, size_t len) {
    if (len < 1) return;
    uint8_t type = data[0];

    if (type == POMPOM_PKT_PIPE_ACK && len >= 11) {
        uint32_t ack_seq = pp_get32(data + 5);
        /* Mark all chunks up to ack_seq as acknowledged */
        for (int i = 0; i < POMPOM_PIPE_WINDOW; i++) {
            if (p->send_buf[i].seq <= ack_seq && !p->send_buf[i].acked) {
                p->send_buf[i].acked = 1;
            }
        }
        /* Advance window base */
        while (p->window_base <= ack_seq)
            p->window_base++;
    }

    if (type == POMPOM_PKT_PIPE_CHUNK && len >= 9) {
        uint32_t seq = pp_get32(data + 5);
        size_t chunk_len = len - 9;

        /* Store in receive buffer */
        int slot = (int)(seq % (POMPOM_PIPE_WINDOW * 2));
        chunk_t *c = &p->recv_buf[slot];
        c->seq = seq;
        c->len = (uint16_t)chunk_len;
        memcpy(c->data, data + 9, chunk_len);
        c->acked = 1; /* mark as received */
        if (seq >= p->recv_next_seq && p->recv_count < POMPOM_PIPE_WINDOW * 2)
            p->recv_count++;

        /* ACK immediately */
        send_ack(p, seq);
    }

    if (type == POMPOM_PKT_PIPE_FIN && len >= 37) {
        p->finished = 1;
    }
}

/* ================================================================
 * Public API
 * ================================================================ */

pompom_pipe_t *pompom_pipe_open(pompom_client_t *client,
                                const char *name,
                                uint64_t total_size,
                                uint8_t flags) {
    pompom_pipe_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->client = client;
    p->stream_id = next_stream_id();
    p->total_size = total_size;
    p->flags = flags;
    strncpy(p->name, name, POMPOM_PIPE_NAME_MAX);
    sha256_init(&p->sha_send);

    /* Send PIPE_OPEN */
    uint8_t pkt[POMPOM_MAX_PAYLOAD];
    int plen = encode_pipe_open(pkt, sizeof(pkt), p->stream_id, flags, total_size, name);
    if (plen < 0 || pipe_send_raw(p, pkt, (size_t)plen) < 0) {
        free(p);
        return NULL;
    }

    return p;
}

pompom_pipe_t *pompom_pipe_open_to(pompom_host_t *host, uint32_t peer_id,
                                   const char *name,
                                   uint64_t total_size,
                                   uint8_t flags) {
    pompom_pipe_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->host = host;
    p->peer_id = peer_id;
    p->stream_id = next_stream_id();
    p->total_size = total_size;
    p->flags = flags;
    strncpy(p->name, name, POMPOM_PIPE_NAME_MAX);
    sha256_init(&p->sha_send);

    uint8_t pkt[POMPOM_MAX_PAYLOAD];
    int plen = encode_pipe_open(pkt, sizeof(pkt), p->stream_id, flags, total_size, name);
    if (plen < 0 || pipe_send_raw(p, pkt, (size_t)plen) < 0) {
        free(p);
        return NULL;
    }

    return p;
}

pompom_pipe_t *pompom_pipe_accept(pompom_host_t *host,
                                  uint32_t *peer_id,
                                  char *name, size_t namesize,
                                  uint64_t *total_size,
                                  uint8_t *flags,
                                  int timeout_ms) {
    uint8_t buf[POMPOM_MAX_PAYLOAD];
    uint32_t from;
    int n = pompom_host_recv(host, &from, buf, sizeof(buf), timeout_ms);
    if (n <= 0) return NULL;

    /* Expect PIPE_OPEN discriminator */
    if (n < 16 || buf[0] != POMPOM_PKT_PIPE_OPEN) return NULL;

    uint32_t sid = pp_get32(buf + 1);
    uint8_t f = buf[5];
    uint64_t total = pp_get64(buf + 6);
    uint16_t nlen = pp_get16(buf + 14);
    if (16 + nlen > (size_t)n) return NULL;

    pompom_pipe_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->host = host;
    p->peer_id = from;
    p->stream_id = sid;
    p->total_size = total;
    p->flags = f;
    sha256_init(&p->sha_recv);

    size_t copy = nlen < namesize - 1 ? nlen : namesize - 1;
    memcpy(p->name, buf + 16, copy);
    p->name[copy] = '\0';
    if (name) { memcpy(name, p->name, copy); name[copy] = '\0'; }
    if (total_size) *total_size = total;
    if (flags) *flags = f;
    if (peer_id) *peer_id = from;

    return p;
}

int pompom_pipe_write(pompom_pipe_t *p,
                      const uint8_t *data, size_t len) {
    size_t off = 0;

    while (off < len) {
        /* Wait for window space */
        int in_flight = (int)(p->next_chunk_seq - p->window_base);
        while (in_flight >= POMPOM_PIPE_WINDOW) {
            /* Drain ACKs */
            uint8_t buf[POMPOM_MAX_PAYLOAD];
            int n = pipe_recv_raw(p, buf, sizeof(buf), POMPOM_PIPE_RETRANSMIT_MS);
            if (n > 0) process_incoming(p, buf, (size_t)n);
            retransmit_expired(p);
            in_flight = (int)(p->next_chunk_seq - p->window_base);
        }

        /* Send next chunk */
        size_t chunk_len = len - off;
        if (chunk_len > POMPOM_PIPE_CHUNK_SIZE) chunk_len = POMPOM_PIPE_CHUNK_SIZE;

        sha256_update(&p->sha_send, data + off, chunk_len);

        if (send_chunk(p, p->next_chunk_seq, data + off, chunk_len) < 0)
            return -1;

        p->next_chunk_seq++;
        p->bytes_written += chunk_len;
        off += chunk_len;
    }

    return 0;
}

int pompom_pipe_read(pompom_pipe_t *p,
                     uint8_t *buf, size_t bufsize,
                     int timeout_ms) {
    /* Try to deliver next in-order chunk from recv buffer */
    int slot = (int)(p->recv_next_seq % (POMPOM_PIPE_WINDOW * 2));
    chunk_t *c = &p->recv_buf[slot];

    if (c->acked && c->seq == p->recv_next_seq) {
        size_t copy = c->len < bufsize ? c->len : bufsize;
        memcpy(buf, c->data, copy);
        sha256_update(&p->sha_recv, c->data, c->len);
        c->acked = 0;
        p->recv_next_seq++;
        p->bytes_read += c->len;
        return (int)copy;
    }

    /* No data ready — poll for more */
    uint8_t raw[POMPOM_MAX_PAYLOAD];
    int n = pipe_recv_raw(p, raw, sizeof(raw), timeout_ms);
    if (n <= 0) {
        if (p->finished) return -1; /* stream ended */
        return 0; /* timeout */
    }

    process_incoming(p, raw, (size_t)n);

    /* Try again after processing */
    c = &p->recv_buf[(int)(p->recv_next_seq % (POMPOM_PIPE_WINDOW * 2))];
    if (c->acked && c->seq == p->recv_next_seq) {
        size_t copy = c->len < bufsize ? c->len : bufsize;
        memcpy(buf, c->data, copy);
        sha256_update(&p->sha_recv, c->data, c->len);
        c->acked = 0;
        p->recv_next_seq++;
        p->bytes_read += c->len;
        return (int)copy;
    }

    return 0;
}

int pompom_pipe_finish(pompom_pipe_t *p) {
    /* Drain remaining ACKs */
    while (p->window_base < p->next_chunk_seq) {
        uint8_t buf[POMPOM_MAX_PAYLOAD];
        int n = pipe_recv_raw(p, buf, sizeof(buf), POMPOM_PIPE_RETRANSMIT_MS);
        if (n > 0) process_incoming(p, buf, (size_t)n);
        retransmit_expired(p);
    }

    /* Compute final hash */
    uint8_t hash[32];
    sha256_final(&p->sha_send, hash);

    /* Send FIN with hash */
    uint8_t pkt[64];
    int plen = encode_pipe_fin(pkt, sizeof(pkt), p->stream_id, hash);
    if (plen < 0) return -1;
    return pipe_send_raw(p, pkt, (size_t)plen);
}

void pompom_pipe_close(pompom_pipe_t *p) {
    if (!p) return;
    free(p);
}

uint64_t pompom_pipe_bytes_sent(const pompom_pipe_t *p) { return p->bytes_written; }
uint64_t pompom_pipe_bytes_acked(const pompom_pipe_t *p) {
    return (uint64_t)p->window_base * POMPOM_PIPE_CHUNK_SIZE;
}
uint64_t pompom_pipe_total(const pompom_pipe_t *p) { return p->total_size; }

/* ================================================================
 * Proxy
 * ================================================================ */

/* Proxy rules stored on the host (simple linear array) */
static pompom_proxy_rule_t proxy_rules[POMPOM_MAX_PROXY_RULES];
static int proxy_rule_count = 0;

int pompom_proxy_add_rule(pompom_host_t *host, const pompom_proxy_rule_t *rule) {
    (void)host;
    if (proxy_rule_count >= POMPOM_MAX_PROXY_RULES) return -1;
    proxy_rules[proxy_rule_count++] = *rule;
    return 0;
}

int pompom_proxy_remove_rule(pompom_host_t *host, const char *name) {
    (void)host;
    for (int i = 0; i < proxy_rule_count; i++) {
        if (strcmp(proxy_rules[i].name, name) == 0) {
            proxy_rules[i] = proxy_rules[--proxy_rule_count];
            return 0;
        }
    }
    return -1;
}

pompom_pipe_t *pompom_proxy_connect(pompom_client_t *client, const char *service_name) {
    return pompom_pipe_open(client, service_name, 0, POMPOM_PIPE_FLAG_PROXY);
}
