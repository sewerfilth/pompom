#include "pompom/cipher.h"
#include "pompom/padlock.h"
#include "pompom/accel.h"

typedef struct {
    uint8_t x_rot;
    uint8_t x_salt;
    uint8_t x_sbox;
    uint8_t y_rot;
    uint8_t y_salt;
    uint8_t y_sbox;
} lane_cfg_t;

static const lane_cfg_t LANES[POMPOM_CIPHER_LANES] = {
    {  1, 0x53, 0,   1, 0xCA, 1 },
    {  2, 0x91, 1,   3, 0x3E, 0 },
    {  3, 0x1F, 0,   5, 0x87, 1 },
    {  4, 0xA6, 1,   2, 0xD1, 0 },
    {  5, 0x72, 0,   7, 0x4E, 1 },
    {  6, 0xE8, 1,   4, 0x59, 0 },
    {  7, 0x3D, 0,   6, 0xB5, 1 },
    {  5, 0xF4, 1,   1, 0x26, 0 },
};

static inline uint8_t rol8(uint8_t v, uint8_t n) {
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

void pompom_init(pompom_state_t *st,
                 const uint8_t key[POMPOM_CIPHER_LANES],
                 const uint8_t nonce[4]) {
    st->seed = nonce[0] ^ nonce[1] ^ nonce[2] ^ nonce[3];
    st->front = st->seed;
    st->t = ((uint32_t)nonce[0] << 24) |
            ((uint32_t)nonce[1] << 16) |
            ((uint32_t)nonce[2] << 8)  |
            ((uint32_t)nonce[3]);

    for (int i = 0; i < POMPOM_CIPHER_LANES; i++)
        st->lane[i] = key[i];

    uint8_t discard[POMPOM_BLOCK_SIZE];
    for (int i = 0; i < 4; i++)
        pompom_block(st, discard);
}

void pompom_block(pompom_state_t *st, uint8_t ks[POMPOM_BLOCK_SIZE]) {
    /* X cascade: all 8 lanes (SIMD-accelerated when available) */
    pompom_cascade_x(st->lane);

    /*
     * Pre-XOR time into lanes for Y cascade.
     * cascade_y uses fixed salts; ROL8(t_mix, y_rot) compensates so
     * the result matches mutate_y(state, y_rot, y_salt ^ t_mix, y_sbox).
     *
     * Proof: ROR(s ^ ROL(tm, r), r) ^ salt
     *      = (ROR(s, r) ^ tm) ^ salt
     *      = ROR(s, r) ^ (salt ^ tm)
     */
    for (int i = 0; i < POMPOM_CIPHER_LANES; i++) {
        uint8_t tm = (uint8_t)(st->t >> (i & 3));
        st->lane[i] ^= rol8(tm, LANES[i].y_rot);
    }

    /* Y cascade: all 8 lanes */
    pompom_cascade_y(st->lane);

    /* Front evolves by folding lane[0] through X-mutation */
    st->front = pompom_mutate_x(
        st->front ^ st->lane[0],
        3, 0xB7, 0
    );

    /*
     * Cross-lane diffusion: fold all lanes + front into a single
     * byte, then XOR it back into every lane.
     *
     * This ensures a 1-bit change in ANY lane propagates to ALL
     * lanes within a single block step. Without this, the 8 lanes
     * evolve independently and key avalanche is ~10%. With it,
     * avalanche reaches ~50% within 4 warmup blocks.
     *
     * mix = front ^ lane[0] ^ lane[1] ^ ... ^ lane[7]
     * lane[i] ^= mix  →  lane[i] now contains information from
     *                     every other lane.
     */
    uint8_t mix = st->front;
    for (int i = 0; i < POMPOM_CIPHER_LANES; i++)
        mix ^= st->lane[i];
    for (int i = 0; i < POMPOM_CIPHER_LANES; i++)
        st->lane[i] ^= mix;

    st->t++;

    /* Extract 16-byte keystream */
    ks[0]  = st->front;
    ks[1]  = st->lane[0];
    ks[2]  = st->lane[1];
    ks[3]  = st->lane[2];
    ks[4]  = st->lane[3];
    ks[5]  = st->lane[4];
    ks[6]  = st->lane[5];
    ks[7]  = st->lane[6];
    ks[8]  = st->lane[7];

    /* Derived bytes: cross-lane mixing + time injection */
    ks[9]  = st->lane[0] ^ st->lane[3] ^ (uint8_t)st->t;
    ks[10] = st->lane[1] ^ st->front   ^ (uint8_t)(st->t >> 8);
    ks[11] = st->lane[2] ^ st->lane[6];
    ks[12] = st->lane[4] ^ st->lane[7];
    ks[13] = st->lane[5] ^ st->front;
    ks[14] = st->lane[0] ^ st->lane[7] ^ (uint8_t)(st->t * 13);
    ks[15] = st->lane[2] ^ st->lane[5] ^ (uint8_t)(st->t * 7);
}

void pompom_crypt(pompom_state_t *st,
                  const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ks[POMPOM_BLOCK_SIZE];
    size_t off = 0;

    while (off + POMPOM_BLOCK_SIZE <= len) {
        pompom_block(st, ks);
        for (int i = 0; i < POMPOM_BLOCK_SIZE; i++)
            out[off + i] = in[off + i] ^ ks[i];
        off += POMPOM_BLOCK_SIZE;
    }

    if (off < len) {
        pompom_block(st, ks);
        for (size_t i = 0; off + i < len; i++)
            out[off + i] = in[off + i] ^ ks[i];
    }
}
