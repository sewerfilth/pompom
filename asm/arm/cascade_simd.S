/*
 * pompom cascade — ARM64 NEON + Crypto Extensions
 *
 * void pompom_cascade_x_aes(uint8_t states[8])
 * void pompom_cascade_y_aes(uint8_t states[8])
 *
 * Processes all 8 lanes in one call:
 *   1. NEON ushl for per-lane variable bit rotation
 *   2. NEON eor  for per-lane XOR salts
 *   3. AESE/AESD for hardware S-box (SubBytes / InvSubBytes)
 *   4. TBL scatter/gather to handle ShiftRows permutation
 */

/* ---- Constant data ---- */

#ifdef __APPLE__
    .section __TEXT,__const
#else
    .section .rodata
#endif

    .p2align 4

/* X cascade: ROL per lane */
x_params:
    /*  +0 lshifts */ .byte  1,  2,  3,  4,  5,  6,  7,  5
    /*  +8 rshifts */ .byte  0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0xFD
    /* +16 salts   */ .byte  0x53,0x91,0x1F,0xA6,0x72,0xE8,0x3D,0xF4
    /* +24 pad     */ .byte  0,0,0,0,0,0,0,0

/* Y cascade: ROR per lane */
y_params:
    /*  +0 rshifts */ .byte  0xFF,0xFD,0xFB,0xFE,0xF9,0xFC,0xFA,0xFF
    /*  +8 lshifts */ .byte  7,  5,  3,  6,  1,  4,  2,  7
    /* +16 salts   */ .byte  0xCA,0x3E,0x87,0xD1,0x4E,0x59,0xB5,0x26
    /* +24 pad     */ .byte  0,0,0,0,0,0,0,0

/*
 * TBL shuffle masks (16 bytes each, loaded as 4 consecutive Q regs).
 *
 * even_scatter: lanes {0,2,4,6} → positions {0,1,2,3}
 * odd_scatter:  lanes {1,3,5,7} → positions {0,1,2,3}
 * aese_gather:  after AESE (ShiftRows), SubBytes results for
 *               input positions {0,1,2,3} land at output {0,13,10,7}
 * aesd_gather:  after AESD (InvShiftRows), InvSubBytes results for
 *               input positions {0,1,2,3} land at output {0,5,10,15}
 */
    .p2align 4
tbl_masks:
    /* even_scatter (+0)  */ .byte 0,2,4,6, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* odd_scatter  (+16) */ .byte 1,3,5,7, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* aese_gather  (+32) */ .byte 0,13,10,7, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    /* aesd_gather  (+48) */ .byte 0,5,10,15, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF

/* ---- Text ---- */

    .text
    .p2align 2

/*
 * void pompom_cascade_x_aes(uint8_t states[8])
 *
 * X cascade: ROL8 + XOR salt + S-box per lane.
 * Even lanes (0,2,4,6) → AESE (forward SubBytes).
 * Odd  lanes (1,3,5,7) → AESD (inverse SubBytes).
 */
    .global _pompom_cascade_x_aes
    .global pompom_cascade_x_aes
_pompom_cascade_x_aes:
pompom_cascade_x_aes:
    /* Load 8 lane bytes */
    ld1     {v0.8b}, [x0]

    /* Load X rotation vectors + salts */
#ifdef __APPLE__
    adrp    x1, x_params@PAGE
    add     x1, x1, x_params@PAGEOFF
#else
    adrp    x1, x_params
    add     x1, x1, :lo12:x_params
#endif
    ld1     {v1.8b}, [x1], #8          /* lshifts */
    ld1     {v2.8b}, [x1], #8          /* rshifts (negative = right) */
    ld1     {v3.8b}, [x1]              /* salts */

    /* Vector ROL8 per lane: (state << n) | (state >> (8-n)) */
    ushl    v4.8b, v0.8b, v1.8b        /* left part */
    ushl    v5.8b, v0.8b, v2.8b        /* right part */
    orr     v0.8b, v4.8b, v5.8b

    /* XOR per-lane salts */
    eor     v0.8b, v0.8b, v3.8b

    /* Load TBL masks (4 × 16B = 64B, one LD1 multi-reg) */
#ifdef __APPLE__
    adrp    x2, tbl_masks@PAGE
    add     x2, x2, tbl_masks@PAGEOFF
#else
    adrp    x2, tbl_masks
    add     x2, x2, :lo12:tbl_masks
#endif
    ld1     {v10.16b, v11.16b, v12.16b, v13.16b}, [x2]

    /* Zero upper half of v0 for 16B TBL */
    mov     v0.d[1], xzr

    /* Scatter even/odd lanes into separate registers */
    tbl     v6.16b, {v0.16b}, v10.16b  /* even → pos {0,1,2,3} */
    tbl     v7.16b, {v0.16b}, v11.16b  /* odd  → pos {0,1,2,3} */

    /* Hardware S-box */
    movi    v8.16b, #0
    aese    v6.16b, v8.16b             /* even: SubBytes + ShiftRows */
    aesd    v7.16b, v8.16b             /* odd:  InvSubBytes + InvShiftRows */

    /* Gather results from shuffled positions */
    tbl     v6.16b, {v6.16b}, v12.16b  /* AESE output: {0,13,10,7} */
    tbl     v7.16b, {v7.16b}, v13.16b  /* AESD output: {0,5,10,15} */

    /* Interleave even/odd back to lane order */
    zip1    v0.8b, v6.8b, v7.8b

    /* Store */
    st1     {v0.8b}, [x0]
    ret

/*
 * void pompom_cascade_y_aes(uint8_t states[8])
 *
 * Y cascade: ROR8 + XOR salt + S-box per lane.
 * Even lanes (0,2,4,6) → AESD (inverse SubBytes).
 * Odd  lanes (1,3,5,7) → AESE (forward SubBytes).
 * (Opposite of X cascade.)
 */
    .global _pompom_cascade_y_aes
    .global pompom_cascade_y_aes
_pompom_cascade_y_aes:
pompom_cascade_y_aes:
    ld1     {v0.8b}, [x0]

    /* Load Y rotation vectors + salts */
#ifdef __APPLE__
    adrp    x1, y_params@PAGE
    add     x1, x1, y_params@PAGEOFF
#else
    adrp    x1, y_params
    add     x1, x1, :lo12:y_params
#endif
    ld1     {v1.8b}, [x1], #8          /* rshifts (negative) */
    ld1     {v2.8b}, [x1], #8          /* lshifts (positive) */
    ld1     {v3.8b}, [x1]              /* salts */

    /* Vector ROR8 per lane: (state >> n) | (state << (8-n)) */
    ushl    v4.8b, v0.8b, v1.8b        /* right part */
    ushl    v5.8b, v0.8b, v2.8b        /* left part */
    orr     v0.8b, v4.8b, v5.8b

    eor     v0.8b, v0.8b, v3.8b

#ifdef __APPLE__
    adrp    x2, tbl_masks@PAGE
    add     x2, x2, tbl_masks@PAGEOFF
#else
    adrp    x2, tbl_masks
    add     x2, x2, :lo12:tbl_masks
#endif
    ld1     {v10.16b, v11.16b, v12.16b, v13.16b}, [x2]

    mov     v0.d[1], xzr

    tbl     v6.16b, {v0.16b}, v10.16b  /* even */
    tbl     v7.16b, {v0.16b}, v11.16b  /* odd */

    /* Y: S-boxes SWAPPED vs X */
    movi    v8.16b, #0
    aesd    v6.16b, v8.16b             /* even: InvSubBytes */
    aese    v7.16b, v8.16b             /* odd:  SubBytes */

    /* Gather (note swapped gather masks vs X) */
    tbl     v6.16b, {v6.16b}, v13.16b  /* AESD: {0,5,10,15} */
    tbl     v7.16b, {v7.16b}, v12.16b  /* AESE: {0,13,10,7} */

    zip1    v0.8b, v6.8b, v7.8b

    st1     {v0.8b}, [x0]
    ret
