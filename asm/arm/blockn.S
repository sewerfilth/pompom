/*
 * pompom batched keystream generator — ARM64 (aarch64)
 *
 * void pompom_blockN(pompom_state_t *st, uint8_t *ks, uint32_t nblocks)
 *
 * Generates nblocks * 16 bytes of keystream into ks, bit-exact with calling
 * the C pompom_block() nblocks times. The whole cipher state (front, lane[8],
 * t) is kept in registers across all blocks, and every constant (cascade
 * params, TBL masks, time-mix rotates, S-box base) is loaded ONCE before the
 * loop. No callee-saved registers are touched, so there is no prologue/
 * epilogue spill.
 *
 * pompom_state_t layout (verified): front@0, lane@1 (8 bytes), t@12 (u32).
 *
 * Register map (resident across the loop):
 *   x0 = st          x1 = ks (advances +16/block)   w2 = remaining blocks
 *   w3 = front       w4 = t                          x5 = sbox_x base
 *   v0 = lane (8b)
 *   v16 = AES zero key           v17..v20 = TBL masks (even,odd,aese,aesd)
 *   v21..v23 = x params (lsh,rsh,salt)   v24..v26 = y params (rsh,lsh,salt)
 *   v27 = time-mix left rotates  v28 = time-mix right rotates
 * Temps: x6..x15, v1..v7.
 *
 * Build-time knob: PP_UNROLL (default 4) — blocks emitted per main-loop body.
 */

#if defined(__APPLE__)
#  define SYM(n) _##n
#else
#  define SYM(n) n
#endif

/* Unroll factor. The cipher is a serial per-block state-dependency chain
 * (latency-bound), so unrolling buys ~nothing and >=4 regresses (register
 * pressure / I-cache). A sweep over 1/2/4/8 put the sweet spot at 1-2. */
#ifndef PP_UNROLL
#define PP_UNROLL 2
#endif

/* ---- read-only constants ---- */
#ifdef __APPLE__
    .section __TEXT,__const
#else
    .section .rodata
#endif
    .p2align 4
ppN_tbl_masks:
    /* even_scatter */ .byte 0,2,4,6, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* odd_scatter  */ .byte 1,3,5,7, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* aese_gather  */ .byte 0,13,10,7, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* aesd_gather  */ .byte 0,5,10,15, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF

    .p2align 3
ppN_x_params:
    .byte  1,  2,  3,  4,  5,  6,  7,  5            /* lshifts */
    .byte  0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0xFD  /* rshifts */
    .byte  0x53,0x91,0x1F,0xA6,0x72,0xE8,0x3D,0xF4  /* salts   */
ppN_y_params:
    .byte  0xFF,0xFD,0xFB,0xFE,0xF9,0xFC,0xFA,0xFF  /* rshifts */
    .byte  7,  5,  3,  6,  1,  4,  2,  7            /* lshifts */
    .byte  0xCA,0x3E,0x87,0xD1,0x4E,0x59,0xB5,0x26  /* salts   */
ppN_yrot:
    .byte  1, 3, 5, 2, 7, 4, 6, 1                   /* y_rot per lane (left) */
    .byte  0xF9,0xFB,0xFD,0xFA,0xFF,0xFC,0xFE,0xF9  /* (y_rot-8) per lane (right) */

    .p2align 4
ppN_sbox_x:
    .byte 0x63,0x7c,0x77,0x7b, 0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b, 0xfe,0xd7,0xab,0x76
    .byte 0xca,0x82,0xc9,0x7d, 0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf, 0x9c,0xa4,0x72,0xc0
    .byte 0xb7,0xfd,0x93,0x26, 0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1, 0x71,0xd8,0x31,0x15
    .byte 0x04,0xc7,0x23,0xc3, 0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2, 0xeb,0x27,0xb2,0x75
    .byte 0x09,0x83,0x2c,0x1a, 0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3, 0x29,0xe3,0x2f,0x84
    .byte 0x53,0xd1,0x00,0xed, 0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39, 0x4a,0x4c,0x58,0xcf
    .byte 0xd0,0xef,0xaa,0xfb, 0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f, 0x50,0x3c,0x9f,0xa8
    .byte 0x51,0xa3,0x40,0x8f, 0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21, 0x10,0xff,0xf3,0xd2
    .byte 0xcd,0x0c,0x13,0xec, 0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d, 0x64,0x5d,0x19,0x73
    .byte 0x60,0x81,0x4f,0xdc, 0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14, 0xde,0x5e,0x0b,0xdb
    .byte 0xe0,0x32,0x3a,0x0a, 0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62, 0x91,0x95,0xe4,0x79
    .byte 0xe7,0xc8,0x37,0x6d, 0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea, 0x65,0x7a,0xae,0x08
    .byte 0xba,0x78,0x25,0x2e, 0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f, 0x4b,0xbd,0x8b,0x8a
    .byte 0x70,0x3e,0xb5,0x66, 0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9, 0x86,0xc1,0x1d,0x9e
    .byte 0xe1,0xf8,0x98,0x11, 0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9, 0xce,0x55,0x28,0xdf
    .byte 0x8c,0xa1,0x89,0x0d, 0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f, 0xb0,0x54,0xbb,0x16

    .text
    .p2align 2

/* ── one block: consumes v0=lane, w3=front, w4=t; writes 16B at [x1]; x1+=16 ── */
.macro PP_BLK
    /* cascade_x */
    ushl    v4.8b, v0.8b, v21.8b
    ushl    v5.8b, v0.8b, v22.8b
    orr     v0.8b, v4.8b, v5.8b
    eor     v0.8b, v0.8b, v23.8b
    tbl     v6.16b, {v0.16b}, v17.16b
    tbl     v7.16b, {v0.16b}, v18.16b
    aese    v6.16b, v16.16b
    aesd    v7.16b, v16.16b
    tbl     v6.16b, {v6.16b}, v19.16b
    tbl     v7.16b, {v7.16b}, v20.16b
    zip1    v0.8b, v6.8b, v7.8b

    /* time-mix: lane[i] ^= rol8((t >> (i&3)) & 0xFF, y_rot[i]) */
    and     w6, w4, #0xFF
    ubfx    w7, w4, #1, #8
    ubfx    w8, w4, #2, #8
    ubfx    w9, w4, #3, #8
    orr     w10, w6, w7, lsl #8
    orr     w10, w10, w8, lsl #16
    orr     w10, w10, w9, lsl #24
    orr     x10, x10, x10, lsl #32
    fmov    d1, x10
    ushl    v2.8b, v1.8b, v27.8b
    ushl    v3.8b, v1.8b, v28.8b
    orr     v2.8b, v2.8b, v3.8b
    eor     v0.8b, v0.8b, v2.8b

    /* cascade_y (S-boxes swapped, gather masks swapped) */
    ushl    v4.8b, v0.8b, v24.8b
    ushl    v5.8b, v0.8b, v25.8b
    orr     v0.8b, v4.8b, v5.8b
    eor     v0.8b, v0.8b, v26.8b
    tbl     v6.16b, {v0.16b}, v17.16b
    tbl     v7.16b, {v0.16b}, v18.16b
    aesd    v6.16b, v16.16b
    aese    v7.16b, v16.16b
    tbl     v6.16b, {v6.16b}, v20.16b
    tbl     v7.16b, {v7.16b}, v19.16b
    zip1    v0.8b, v6.8b, v7.8b

    /* lanes → GP (post-cascade_y) */
    fmov    x11, d0

    /* front = sbox_x[ ROL8(front ^ lane[0], 3) ^ 0xB7 ] */
    and     w12, w11, #0xFF
    eor     w12, w12, w3
    lsl     w13, w12, #3
    orr     w13, w13, w12, lsr #5
    and     w13, w13, #0xFF
    mov     w12, #0xB7              /* 0xB7 is not a valid logical immediate */
    eor     w13, w13, w12
    and     w13, w13, #0xFF
    ldrb    w3, [x5, w13, uxtw]

    /* mix = front ^ XOR(lane[0..7]); lane[i] ^= mix */
    eor     x14, x11, x11, lsr #32
    eor     w14, w14, w14, lsr #16
    eor     w14, w14, w14, lsr #8
    eor     w14, w14, w3
    dup     v3.8b, w14
    eor     v0.8b, v0.8b, v3.8b
    fmov    x11, d0                 /* post-mix lanes */

    add     w4, w4, #1              /* t++ */

    /* extract post-mix lanes m0..m7 */
    and     w6,  w11, #0xFF
    ubfx    w7,  w11, #8,  #8
    ubfx    w8,  w11, #16, #8
    ubfx    w9,  w11, #24, #8
    ubfx    x10, x11, #32, #8       /* bits >= 32 require an X destination */
    ubfx    x12, x11, #40, #8
    ubfx    x13, x11, #48, #8
    ubfx    x15, x11, #56, #8

    /* ks[0]=front, ks[1..8]=m0..m7 */
    strb    w3,  [x1, #0]
    strb    w6,  [x1, #1]
    strb    w7,  [x1, #2]
    strb    w8,  [x1, #3]
    strb    w9,  [x1, #4]
    strb    w10, [x1, #5]
    strb    w12, [x1, #6]
    strb    w13, [x1, #7]
    strb    w15, [x1, #8]
    /* ks[9]  = m0 ^ m3 ^ (t & 0xFF) */
    and     w11, w4, #0xFF
    eor     w14, w6, w9
    eor     w14, w14, w11
    strb    w14, [x1, #9]
    /* ks[10] = m1 ^ front ^ (t>>8) */
    ubfx    w11, w4, #8, #8
    eor     w14, w7, w3
    eor     w14, w14, w11
    strb    w14, [x1, #10]
    /* ks[11] = m2 ^ m6 */
    eor     w14, w8, w13
    strb    w14, [x1, #11]
    /* ks[12] = m4 ^ m7 */
    eor     w14, w10, w15
    strb    w14, [x1, #12]
    /* ks[13] = m5 ^ front */
    eor     w14, w12, w3
    strb    w14, [x1, #13]
    /* ks[14] = m0 ^ m7 ^ (t*13) */
    mov     w11, #13
    mul     w11, w4, w11
    eor     w14, w6, w15
    eor     w14, w14, w11
    strb    w14, [x1, #14]
    /* ks[15] = m2 ^ m5 ^ (t*7) */
    lsl     w11, w4, #3
    sub     w11, w11, w4
    eor     w14, w8, w12
    eor     w14, w14, w11
    strb    w14, [x1, #15]

    add     x1, x1, #16
.endm

    .globl SYM(pompom_blockN)
    .globl pompom_blockN
SYM(pompom_blockN):
pompom_blockN:
    cbz     w2, .LppN_ret

    /* ---- load constants once ---- */
    movi    v16.16b, #0
#ifdef __APPLE__
    adrp    x6, ppN_tbl_masks@PAGE
    add     x6, x6, ppN_tbl_masks@PAGEOFF
#else
    adrp    x6, ppN_tbl_masks
    add     x6, x6, :lo12:ppN_tbl_masks
#endif
    ld1     {v17.16b, v18.16b, v19.16b, v20.16b}, [x6]
#ifdef __APPLE__
    adrp    x6, ppN_x_params@PAGE
    add     x6, x6, ppN_x_params@PAGEOFF
#else
    adrp    x6, ppN_x_params
    add     x6, x6, :lo12:ppN_x_params
#endif
    ld1     {v21.8b, v22.8b, v23.8b}, [x6]
#ifdef __APPLE__
    adrp    x6, ppN_y_params@PAGE
    add     x6, x6, ppN_y_params@PAGEOFF
#else
    adrp    x6, ppN_y_params
    add     x6, x6, :lo12:ppN_y_params
#endif
    ld1     {v24.8b, v25.8b, v26.8b}, [x6]
#ifdef __APPLE__
    adrp    x6, ppN_yrot@PAGE
    add     x6, x6, ppN_yrot@PAGEOFF
#else
    adrp    x6, ppN_yrot
    add     x6, x6, :lo12:ppN_yrot
#endif
    ld1     {v27.8b, v28.8b}, [x6]
#ifdef __APPLE__
    adrp    x5, ppN_sbox_x@PAGE
    add     x5, x5, ppN_sbox_x@PAGEOFF
#else
    adrp    x5, ppN_sbox_x
    add     x5, x5, :lo12:ppN_sbox_x
#endif

    /* ---- load state once ---- */
    ldrb    w3, [x0]              /* front */
    ldur    d0, [x0, #1]          /* lane[0..7] */
    ldr     w4, [x0, #12]         /* t */

.LppN_main:
    cmp     w2, #PP_UNROLL
    b.lo    .LppN_tail
    .rept PP_UNROLL
    PP_BLK
    .endr
    sub     w2, w2, #PP_UNROLL
    b       .LppN_main

.LppN_tail:
    cbz     w2, .LppN_store
.LppN_t1:
    PP_BLK
    subs    w2, w2, #1
    b.ne    .LppN_t1

.LppN_store:
    /* ---- store state back ---- */
    strb    w3, [x0]
    stur    d0, [x0, #1]
    str     w4, [x0, #12]

.LppN_ret:
    ret
