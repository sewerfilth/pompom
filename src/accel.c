#include "pompom/accel.h"
#include "pompom/padlock.h"

/* ---- Scalar fallback (used when no SIMD available) ---- */

#if !defined(__aarch64__) && !defined(_M_ARM64)

typedef struct {
    uint8_t x_rot, x_salt, x_sbox;
    uint8_t y_rot, y_salt, y_sbox;
} lane_cfg_t;

static const lane_cfg_t LANES[8] = {
    { 1, 0x53, 0,  1, 0xCA, 1 },
    { 2, 0x91, 1,  3, 0x3E, 0 },
    { 3, 0x1F, 0,  5, 0x87, 1 },
    { 4, 0xA6, 1,  2, 0xD1, 0 },
    { 5, 0x72, 0,  7, 0x4E, 1 },
    { 6, 0xE8, 1,  4, 0x59, 0 },
    { 7, 0x3D, 0,  6, 0xB5, 1 },
    { 5, 0xF4, 1,  1, 0x26, 0 },
};
static void cascade_x_scalar(uint8_t states[8]) {
    for (int i = 0; i < 8; i++)
        states[i] = pompom_mutate_x(states[i],
            LANES[i].x_rot, LANES[i].x_salt, LANES[i].x_sbox);
}

static void cascade_y_scalar(uint8_t states[8]) {
    for (int i = 0; i < 8; i++)
        states[i] = pompom_mutate_y(states[i],
            LANES[i].y_rot, LANES[i].y_salt, LANES[i].y_sbox);
}
#endif

/* ---- Dispatch ---- */

static void (*fn_x)(uint8_t[8]) = 0;
static void (*fn_y)(uint8_t[8]) = 0;
static int detected = -1;

int pompom_accel_detect(void) {
    if (detected >= 0) return detected;

#if defined(__aarch64__) || defined(_M_ARM64)
    /* ARM64: Apple Silicon always has crypto; assume available elsewhere too */
    fn_x = pompom_cascade_x_aes;
    fn_y = pompom_cascade_y_aes;
    detected = POMPOM_ACCEL_AES;

#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    {
        unsigned int a, b, c, d;
        __asm__ __volatile__("cpuid"
            : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1));
        if (c & (1u << 25)) {       /* AES-NI */
            fn_x = pompom_cascade_x_aesni;
            fn_y = pompom_cascade_y_aesni;
            detected = POMPOM_ACCEL_AESNI;
        } else {
            fn_x = cascade_x_scalar;
            fn_y = cascade_y_scalar;
            detected = POMPOM_ACCEL_NONE;
        }
    }
#else
    fn_x = cascade_x_scalar;
    fn_y = cascade_y_scalar;
    detected = POMPOM_ACCEL_NONE;
#endif
    return detected;
}

const char *pompom_accel_name(int accel) {
    switch (accel) {
    case POMPOM_ACCEL_AES:   return "ARM NEON + Crypto (AESE/AESD)";
    case POMPOM_ACCEL_NEON:  return "ARM NEON";
    case POMPOM_ACCEL_AESNI: return "x86 AES-NI + SSSE3";
    case POMPOM_ACCEL_XMM:   return "x86 SSE2";
    default:                 return "scalar";
    }
}

void pompom_cascade_x(uint8_t states[8]) {
    if (!fn_x) pompom_accel_detect();
    fn_x(states);
}

void pompom_cascade_y(uint8_t states[8]) {
    if (!fn_y) pompom_accel_detect();
    fn_y(states);
}
