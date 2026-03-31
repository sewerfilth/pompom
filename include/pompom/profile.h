#ifndef POMPOM_PROFILE_H
#define POMPOM_PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include "pompom/padlock.h"

/*
 * Speed band quantization (2 bits, 4 bands).
 *
 * Band boundaries are logarithmic to match human perception:
 *   SLOW   >= 800 ms     (deliberate)
 *   MEDIUM  200–800 ms   (comfortable)
 *   FAST     50–200 ms   (quick)
 *   BURST    < 50 ms     (mashing)
 *
 * The wide band windows give natural tolerance — you don't need
 * exact timing, just the same general feel.
 */
#define POMPOM_BAND_SLOW   0
#define POMPOM_BAND_MEDIUM 1
#define POMPOM_BAND_FAST   2
#define POMPOM_BAND_BURST  3

#define POMPOM_MAX_SEGMENTS 32

/* Quantize a microsecond interval to a speed band. */
uint8_t pompom_quantize_band(uint64_t interval_us);

/*
 * Profiled dial: like pompom_dial, but each character's speed band
 * gets XOR-mixed into all 8 lanes BEFORE the rotation cascade.
 *
 * Same passphrase + same speed bands → same final state.
 * Same passphrase + different speed   → different state entirely.
 *
 * intervals_us[i]: microseconds since previous keypress for key[i].
 *                  intervals_us[0] is ignored (no prior key).
 *                  Pass NULL for unprofiled (all bands default to 0).
 */
void pompom_dial_profiled(pompom_lock_t *lock,
                          const char *key, size_t len,
                          const uint64_t *intervals_us);

/*
 * Optional: explicit profile capture / matching for applications
 * that want fine-grained tolerance control beyond the band widths.
 */
typedef struct {
    uint8_t bands[POMPOM_MAX_SEGMENTS];
    uint8_t len;
} pompom_profile_t;

/* Capture band sequence from timing data. */
void pompom_profile_capture(pompom_profile_t *prof,
                            const char *key, size_t len,
                            const uint64_t *intervals_us);

/*
 * Compare two profiles with tolerance (±N bands).
 * Returns 0 if within tolerance, nonzero if not.
 * tolerance=0: exact band match required.
 * tolerance=1: ±1 band allowed (e.g., SLOW matches MEDIUM).
 */
int pompom_profile_match(const pompom_profile_t *ref,
                         const pompom_profile_t *attempt,
                         uint8_t tolerance);

#endif
