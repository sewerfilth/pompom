;
; pompom cascade — x86_64 SSSE3 + AES-NI
;
; void pompom_cascade_x_aesni(uint8_t states[8])
; void pompom_cascade_y_aesni(uint8_t states[8])
;
; System V AMD64: rdi = states pointer
;
; Per-byte rotation is scalar (x86 has no per-byte variable shift).
; Scatter/gather via SSSE3 PSHUFB.
; S-box via AES-NI AESENCLAST / AESDECLAST.
;

%ifdef MACOS
  %define DECL(x) _ %+ x
%else
  %define DECL(x) x
%endif

default rel

; ---- Constant data (16-byte aligned for SSE) ----

section .data

align 16
x_salts_128:
    db 0x53,0x91,0x1F,0xA6, 0x72,0xE8,0x3D,0xF4, 0,0,0,0, 0,0,0,0

align 16
y_salts_128:
    db 0xCA,0x3E,0x87,0xD1, 0x4E,0x59,0xB5,0x26, 0,0,0,0, 0,0,0,0

align 16
even_scatter_128:
    db 0,2,4,6, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

align 16
odd_scatter_128:
    db 1,3,5,7, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

; After AESENCLAST (SubBytes + ShiftRows): inputs at {0,1,2,3} land at {0,13,10,7}
align 16
aese_gather_128:
    db 0,13,10,7, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

; After AESDECLAST (InvSubBytes + InvShiftRows): inputs at {0,1,2,3} land at {0,5,10,15}
align 16
aesd_gather_128:
    db 0,5,10,15, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

; ---- Text ----

section .text

; void pompom_cascade_x_aesni(uint8_t states[8])
; X: ROL per lane, then AESENCLAST (even) / AESDECLAST (odd)
global DECL(pompom_cascade_x_aesni)
DECL(pompom_cascade_x_aesni):
    movq    xmm0, [rdi]

    ; Scalar byte rotations — X amounts: {1,2,3,4,5,6,7,5}
    pxor    xmm1, xmm1

    pextrb  eax, xmm0, 0
    rol     al, 1
    pinsrb  xmm1, eax, 0

    pextrb  eax, xmm0, 1
    rol     al, 2
    pinsrb  xmm1, eax, 1

    pextrb  eax, xmm0, 2
    rol     al, 3
    pinsrb  xmm1, eax, 2

    pextrb  eax, xmm0, 3
    rol     al, 4
    pinsrb  xmm1, eax, 3

    pextrb  eax, xmm0, 4
    rol     al, 5
    pinsrb  xmm1, eax, 4

    pextrb  eax, xmm0, 5
    rol     al, 6
    pinsrb  xmm1, eax, 5

    pextrb  eax, xmm0, 6
    rol     al, 7
    pinsrb  xmm1, eax, 6

    pextrb  eax, xmm0, 7
    rol     al, 5
    pinsrb  xmm1, eax, 7

    ; XOR salts
    pxor    xmm1, [x_salts_128]

    ; Scatter even lanes → xmm2, odd → xmm3
    movdqa  xmm2, xmm1
    pshufb  xmm2, [even_scatter_128]
    movdqa  xmm3, xmm1
    pshufb  xmm3, [odd_scatter_128]

    ; AES-NI S-box
    pxor    xmm4, xmm4
    aesenclast xmm2, xmm4          ; even: forward SubBytes
    aesdeclast xmm3, xmm4          ; odd:  inverse SubBytes

    ; Gather from shuffled positions
    pshufb  xmm2, [aese_gather_128]
    pshufb  xmm3, [aesd_gather_128]

    ; Interleave even/odd
    punpcklbw xmm2, xmm3

    ; Store low 8 bytes
    movq    [rdi], xmm2
    ret

; void pompom_cascade_y_aesni(uint8_t states[8])
; Y: ROR per lane, then AESDECLAST (even) / AESENCLAST (odd)
global DECL(pompom_cascade_y_aesni)
DECL(pompom_cascade_y_aesni):
    movq    xmm0, [rdi]

    ; Scalar byte rotations — Y amounts: {1,3,5,2,7,4,6,1}
    pxor    xmm1, xmm1

    pextrb  eax, xmm0, 0
    ror     al, 1
    pinsrb  xmm1, eax, 0

    pextrb  eax, xmm0, 1
    ror     al, 3
    pinsrb  xmm1, eax, 1

    pextrb  eax, xmm0, 2
    ror     al, 5
    pinsrb  xmm1, eax, 2

    pextrb  eax, xmm0, 3
    ror     al, 2
    pinsrb  xmm1, eax, 3

    pextrb  eax, xmm0, 4
    ror     al, 7
    pinsrb  xmm1, eax, 4

    pextrb  eax, xmm0, 5
    ror     al, 4
    pinsrb  xmm1, eax, 5

    pextrb  eax, xmm0, 6
    ror     al, 6
    pinsrb  xmm1, eax, 6

    pextrb  eax, xmm0, 7
    ror     al, 1
    pinsrb  xmm1, eax, 7

    pxor    xmm1, [y_salts_128]

    movdqa  xmm2, xmm1
    pshufb  xmm2, [even_scatter_128]
    movdqa  xmm3, xmm1
    pshufb  xmm3, [odd_scatter_128]

    ; Y: S-boxes SWAPPED vs X
    pxor    xmm4, xmm4
    aesdeclast xmm2, xmm4          ; even: inverse SubBytes
    aesenclast xmm3, xmm4          ; odd:  forward SubBytes

    ; Gather (swapped masks vs X)
    pshufb  xmm2, [aesd_gather_128]
    pshufb  xmm3, [aese_gather_128]

    punpcklbw xmm2, xmm3
    movq    [rdi], xmm2
    ret
