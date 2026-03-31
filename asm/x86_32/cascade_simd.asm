;
; pompom cascade — x86_32 (i686) SSSE3 + AES-NI
;
; void pompom_cascade_x_aesni(uint8_t states[8])
; void pompom_cascade_y_aesni(uint8_t states[8])
;
; cdecl: [esp+4] = states pointer
;

%ifdef MACOS
  %define DECL(x) _ %+ x
%else
  %define DECL(x) x
%endif

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

align 16
aese_gather_128:
    db 0,13,10,7, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

align 16
aesd_gather_128:
    db 0,5,10,15, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80, 0x80,0x80,0x80,0x80

section .text

global DECL(pompom_cascade_x_aesni)
DECL(pompom_cascade_x_aesni):
    mov     edx, [esp+4]
    movq    xmm0, [edx]

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

    pxor    xmm1, [x_salts_128]

    movdqa  xmm2, xmm1
    pshufb  xmm2, [even_scatter_128]
    movdqa  xmm3, xmm1
    pshufb  xmm3, [odd_scatter_128]

    pxor    xmm4, xmm4
    aesenclast xmm2, xmm4
    aesdeclast xmm3, xmm4

    pshufb  xmm2, [aese_gather_128]
    pshufb  xmm3, [aesd_gather_128]

    punpcklbw xmm2, xmm3
    movq    [edx], xmm2
    ret

global DECL(pompom_cascade_y_aesni)
DECL(pompom_cascade_y_aesni):
    mov     edx, [esp+4]
    movq    xmm0, [edx]

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

    pxor    xmm4, xmm4
    aesdeclast xmm2, xmm4
    aesenclast xmm3, xmm4

    pshufb  xmm2, [aesd_gather_128]
    pshufb  xmm3, [aese_gather_128]

    punpcklbw xmm2, xmm3
    movq    [edx], xmm2
    ret
