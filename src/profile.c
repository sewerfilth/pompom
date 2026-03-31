#include "pompom/profile.h"
#include "pompom/accel.h"

/*
 * Band spread table: 4 bands × 8 lanes.
 *
 * Each row has high pairwise Hamming distance from the others,
 * ensuring different bands produce maximally divergent state
 * evolution after the S-box nonlinearity.
 */
static const uint8_t BAND_SPREAD[4][8] = {
    { 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F }, /* slow   */
    { 0x3C, 0x78, 0xF0, 0xE1, 0xC3, 0x87, 0x0F, 0x1E }, /* medium */
    { 0x5A, 0xB4, 0x69, 0xD2, 0xA5, 0x4B, 0x96, 0x2D }, /* fast   */
    { 0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8 }, /* burst  */
};

uint8_t pompom_quantize_band(uint64_t interval_us) {
    if (interval_us >= 800000) return POMPOM_BAND_SLOW;
    if (interval_us >= 200000) return POMPOM_BAND_MEDIUM;
    if (interval_us >=  50000) return POMPOM_BAND_FAST;
    return POMPOM_BAND_BURST;
}

void pompom_dial_profiled(pompom_lock_t *lock,
                          const char *key, size_t len,
                          const uint64_t *intervals_us) {
    size_t dir = 0;
    size_t seg = 0;

    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        uint8_t pos;
        if (c >= 'a' && c <= 'z')
            pos = (uint8_t)(c - 'a' + 1);
        else if (c >= 'A' && c <= 'Z')
            pos = (uint8_t)(c - 'A' + 1);
        else
            continue;

        /* Quantize speed for this segment */
        uint8_t band = (seg > 0 && intervals_us)
            ? pompom_quantize_band(intervals_us[seg])
            : POMPOM_BAND_SLOW;

        /* Mix band spread into all lanes before rotation.
         * This cryptographically binds the speed to the state:
         * different band → different XOR → different cascade input
         * → completely different output after S-box. */
        const uint8_t *spread = BAND_SPREAD[band];
        for (int j = 0; j < POMPOM_LANES; j++)
            lock->state[j] ^= spread[j];

        /* Rotate (uses SIMD cascade internally) */
        for (uint8_t s = 0; s < pos; s++) {
            if (dir & 1)
                pompom_cascade_y(lock->state);
            else
                pompom_cascade_x(lock->state);
        }

        dir++;
        seg++;
    }
}

void pompom_profile_capture(pompom_profile_t *prof,
                            const char *key, size_t len,
                            const uint64_t *intervals_us) {
    prof->len = 0;
    size_t seg = 0;
    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            continue;

        uint8_t band = (seg > 0 && intervals_us)
            ? pompom_quantize_band(intervals_us[seg])
            : POMPOM_BAND_SLOW;

        if (prof->len < POMPOM_MAX_SEGMENTS)
            prof->bands[prof->len++] = band;
        seg++;
    }
}

int pompom_profile_match(const pompom_profile_t *ref,
                         const pompom_profile_t *attempt,
                         uint8_t tolerance) {
    if (ref->len != attempt->len)
        return 1;

    /* Constant-time: always check all segments */
    uint8_t fail = 0;
    for (uint8_t i = 0; i < ref->len; i++) {
        int diff = (int)ref->bands[i] - (int)attempt->bands[i];
        if (diff < 0) diff = -diff;
        if ((uint8_t)diff > tolerance)
            fail = 1;
    }
    return (int)fail;
}
