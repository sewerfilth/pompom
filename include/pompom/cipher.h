#ifndef POMPOM_CIPHER_H
#define POMPOM_CIPHER_H

#include <stdint.h>
#include <stddef.h>

#define POMPOM_CIPHER_LANES 8
#define POMPOM_BLOCK_SIZE   16

typedef struct {
    uint8_t  front;
    uint8_t  lane[POMPOM_CIPHER_LANES];
    uint32_t t;
    uint8_t  seed;
} pompom_state_t;

/*
 * Initialize cipher state from a key and nonce.
 * key:   POMPOM_CIPHER_LANES bytes  (seeds the 8 lanes)
 * nonce: 4 bytes                    (seeds front + initial time offset)
 */
void pompom_init(pompom_state_t *st,
                 const uint8_t key[POMPOM_CIPHER_LANES],
                 const uint8_t nonce[4]);

/*
 * Encrypt or decrypt `len` bytes in place.
 * Processes full 16-byte blocks, then handles any trailing partial block.
 * Same function for both directions (XOR is its own inverse).
 */
void pompom_crypt(pompom_state_t *st,
                  const uint8_t *in, uint8_t *out, size_t len);

/*
 * Advance state by one block step and extract a 16-byte keystream block.
 * Used internally by pompom_crypt; exposed for testing / diagnostics.
 */
void pompom_block(pompom_state_t *st, uint8_t ks[POMPOM_BLOCK_SIZE]);

#endif
