/*
 * blockn_bench.c — throughput of the asm pompom_blockN batched keystream
 * generator vs the per-block C loop, at tiny/medium/large message sizes.
 *
 * Build (binary goes in the gitignored build dir, not /tmp):
 *   cc -c -DPP_UNROLL=2 -o build/arm/blockn.o asm/arm/blockn.S   # if sweeping
 *   clang -O2 -Iinclude -o build/blockn_bench test/blockn_bench.c build/arm/libpompom.a
 *   ./build/blockn_bench
 *
 * Unroll sweep: rebuild blockn.o with -DPP_UNROLL=1|2|4|8 and relink.
 */
#include "pompom/cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static uint64_t now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000ull + t.tv_nsec;
}

static double mbps_blockN(uint32_t nb, uint64_t target_bytes) {
    uint8_t key[8] = {1,2,3,4,5,6,7,8}, nonce[4] = {9,9,9,9};
    pompom_state_t st; uint8_t *ks = malloc((size_t)nb * 16);
    uint64_t reps = target_bytes / ((uint64_t)nb * 16); if (reps < 1) reps = 1;
    for (uint64_t i = 0; i < reps/10 + 1; i++) { pompom_init(&st,key,nonce); pompom_blockN(&st,ks,nb); }
    uint64_t t0 = now();
    for (uint64_t i = 0; i < reps; i++) { pompom_init(&st,key,nonce); pompom_blockN(&st,ks,nb); }
    uint64_t t1 = now();
    double bytes = (double)reps * nb * 16; free(ks);
    return bytes / ((t1 - t0) / 1e9) / 1e6;
}

static double mbps_cref(uint32_t nb, uint64_t target_bytes) {
    uint8_t key[8] = {1,2,3,4,5,6,7,8}, nonce[4] = {9,9,9,9};
    pompom_state_t st; uint8_t ks[16];
    uint64_t reps = target_bytes / ((uint64_t)nb * 16); if (reps < 1) reps = 1;
    for (uint64_t i = 0; i < reps/10 + 1; i++) { pompom_init(&st,key,nonce); for (uint32_t b=0;b<nb;b++) pompom_block(&st,ks); }
    uint64_t t0 = now();
    for (uint64_t i = 0; i < reps; i++) { pompom_init(&st,key,nonce); for (uint32_t b=0;b<nb;b++) pompom_block(&st,ks); }
    uint64_t t1 = now();
    double bytes = (double)reps * nb * 16;
    return bytes / ((t1 - t0) / 1e9) / 1e6;
}

int main(void) {
    struct { const char *name; uint32_t nb; } S[] = {
        {"tiny  (64B/4blk)", 4}, {"medium(4KB/256blk)", 256}, {"large (256KB/16384blk)", 16384}
    };
    uint64_t TARGET = 200ull * 1024 * 1024;
    printf("  %-24s %12s %12s %8s\n", "size", "blockN MB/s", "C-loop MB/s", "speedup");
    for (int i = 0; i < 3; i++) {
        double a = mbps_blockN(S[i].nb, TARGET);
        double c = mbps_cref(S[i].nb, TARGET);
        printf("  %-24s %12.1f %12.1f %7.2fx\n", S[i].name, a, c, a / c);
    }
    return 0;
}
