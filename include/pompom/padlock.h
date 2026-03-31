#ifndef POMPOM_PADLOCK_H
#define POMPOM_PADLOCK_H

#include <stdint.h>
#include <stddef.h>

#define POMPOM_LANES 8

typedef struct {
    uint8_t state[POMPOM_LANES];
    uint8_t target[POMPOM_LANES];
    uint8_t seed;
} pompom_lock_t;

void pompom_lock_init(pompom_lock_t *lock, uint8_t seed);
void pompom_rotate_x(pompom_lock_t *lock, uint8_t steps);
void pompom_rotate_y(pompom_lock_t *lock, uint8_t steps);
void pompom_dial(pompom_lock_t *lock, const char *key, size_t len);
void pompom_lock_set(pompom_lock_t *lock);
int  pompom_lock_try(const pompom_lock_t *lock);

/* Arch-specific ASM primitives (internal) */
uint8_t pompom_mutate_x(uint8_t state, uint8_t rot, uint8_t salt, uint8_t sbox_id);
uint8_t pompom_mutate_y(uint8_t state, uint8_t rot, uint8_t salt, uint8_t sbox_id);

#endif
