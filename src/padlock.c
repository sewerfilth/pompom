#include "pompom/padlock.h"
#include "pompom/accel.h"

void pompom_lock_init(pompom_lock_t *lock, uint8_t seed) {
    lock->seed = seed;
    for (int i = 0; i < POMPOM_LANES; i++) {
        lock->state[i] = seed;
        lock->target[i] = 0;
    }
}

void pompom_rotate_x(pompom_lock_t *lock, uint8_t steps) {
    for (uint8_t s = 0; s < steps; s++)
        pompom_cascade_x(lock->state);
}

void pompom_rotate_y(pompom_lock_t *lock, uint8_t steps) {
    for (uint8_t s = 0; s < steps; s++)
        pompom_cascade_y(lock->state);
}

void pompom_dial(pompom_lock_t *lock, const char *key, size_t len) {
    size_t dir = 0;
    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        uint8_t pos;
        if (c >= 'a' && c <= 'z')
            pos = (uint8_t)(c - 'a' + 1);
        else if (c >= 'A' && c <= 'Z')
            pos = (uint8_t)(c - 'A' + 1);
        else
            continue;

        if (dir & 1)
            pompom_rotate_y(lock, pos);
        else
            pompom_rotate_x(lock, pos);
        dir++;
    }
}

void pompom_lock_set(pompom_lock_t *lock) {
    for (int i = 0; i < POMPOM_LANES; i++) {
        lock->target[i] = lock->state[i];
        lock->state[i] = lock->seed;
    }
}

int pompom_lock_try(const pompom_lock_t *lock) {
    volatile uint8_t diff = 0;
    for (int i = 0; i < POMPOM_LANES; i++)
        diff |= lock->state[i] ^ lock->target[i];
    return (int)diff;
}
