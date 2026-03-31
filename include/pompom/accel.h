#ifndef POMPOM_ACCEL_H
#define POMPOM_ACCEL_H

#include <stdint.h>

#define POMPOM_ACCEL_NONE  0
#define POMPOM_ACCEL_NEON  1
#define POMPOM_ACCEL_AES   2
#define POMPOM_ACCEL_XMM   3
#define POMPOM_ACCEL_AESNI 4

int         pompom_accel_detect(void);
const char *pompom_accel_name(int accel);

/* Dispatched cascade: auto-selects best available path.
 * Processes all 8 lanes in one call (SIMD when hardware supports it). */
void pompom_cascade_x(uint8_t states[8]);
void pompom_cascade_y(uint8_t states[8]);

/* ARM: NEON rotate/XOR + Crypto Extensions S-box */
void pompom_cascade_x_aes(uint8_t states[8]);
void pompom_cascade_y_aes(uint8_t states[8]);

/* x86: SSSE3 scatter/gather + AES-NI S-box */
void pompom_cascade_x_aesni(uint8_t states[8]);
void pompom_cascade_y_aesni(uint8_t states[8]);

#endif
