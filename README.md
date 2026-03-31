# pompom

A web messaging protocol implemented in assembly with C wrappers.

## Target architectures

- ARM (aarch64)
- x86_64
- x86_32 (i686)

## Project layout

```
asm/          Architecture-specific assembly sources
  arm/        ARM / aarch64
  x86_64/     x86-64
  x86_32/     x86-32 (i686)
src/          C wrapper sources
include/      Public C headers
  pompom/
build/        Build output (gitignored)
```

## Building

Requires: a C compiler (gcc/clang), an assembler (as/nasm), and Make.

```
make ARCH=arm      # aarch64
make ARCH=x86_64   # x86-64
make ARCH=x86_32   # i686
```
