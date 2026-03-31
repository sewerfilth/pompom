# pompom

An 8-lane rolling block cipher and encrypted messaging protocol, implemented in assembly with C wrappers. Ships as a static library (`libpompom.a`) for apps to link against.

## Quick start

```c
#include "pompom/net.h"

// Host (server)
uint8_t key[8] = { /* pre-shared key */ };
pompom_host_t *host = pompom_host_create(key, 9900);
uint32_t peer;
uint8_t buf[1500];
int n = pompom_host_recv(host, &peer, buf, sizeof(buf), -1);
pompom_host_send(host, peer, buf, n);   // echo

// Client
pompom_client_t *cli = pompom_client_connect(key, "127.0.0.1", 9900);
pompom_client_send(cli, data, len);     // encrypted
int n = pompom_client_recv(cli, buf, sizeof(buf), 5000);
```

## Building

Requires: C compiler (gcc/clang), assembler (as/nasm), Make.

```
make                # build libpompom.a
make test           # unit tests (13 tests)
make stress         # stress + pentests (19 tests)
make examples       # host + client binaries
make ARCH=x86_64    # cross-compile
```

## Architecture

```
include/pompom/
  padlock.h     Digital padlock: 8-lane lock/unlock with ABC key derivation
  cipher.h      Rolling block cipher: 16-byte keystream, XOR encrypt/decrypt
  accel.h       SIMD acceleration: NEON, AES-NI, SSSE3 runtime dispatch
  profile.h     Speed profiling: timing-based biometric authentication
  proto.h       Wire protocol: 10-byte header, handshake, replay protection
  wal.h         Write-ahead log: cipher state checkpoint/recovery
  net.h         Host/client API: UDP sockets, peer management

src/            C implementation
asm/arm/        ARM64 NEON + Crypto Extensions
asm/x86_64/     x86-64 SSSE3 + AES-NI
asm/x86_32/     i686 SSSE3 + AES-NI
test/           Unit tests + stress/pentests
examples/       Host + client example programs
```

## Cipher design

8 independent lanes mutate in parallel on every step. Each lane has unique rotation width, XOR salt, and S-box assignment. A cross-lane diffusion step after each block ensures full avalanche (~50% bit flip from 1-bit key change).

```
Per step:  ROL/ROR(state, lane_rot) ^ lane_salt -> S-box[lane_sbox_id]
Per block: cascade_x -> time_mix -> cascade_y -> front_evolve -> cross_lane_mix
```

Two 256-byte S-boxes (AES forward + inverse) provide the nonlinear layer. Hardware AES instructions (`AESE`/`AESD` on ARM, `AESENCLAST`/`AESDECLAST` on x86) accelerate the S-box lookups.

## Wire protocol

```
 0      2    3    4        8      10
 +------+----+----+--------+------+
 | "PP" |type|flag|  seq   | len  |  10-byte header
 +------+----+----+--------+------+
 |         payload (encrypted)    |  up to 1460 bytes
 +--------------------------------+
```

Handshake: `HELLO(nonce) -> ACCEPT(nonce) -> established`. Replay protection via monotonic sequence numbers. Bidirectional cipher states (separate keystreams for each direction).

## Test results (ARM, Apple Silicon)

```
Unit tests:     13/13 passed
Stress/pentest: 19/19 passed

Throughput:     188 MB/s bulk encrypt (NEON + AES crypto)
Cascade:        1.1 ns/byte (8 lanes, SIMD)
Sessions:       57K handshakes/s
Messages:       4.7M msg/s (codec only)
```

## Target architectures

- ARM aarch64 (NEON + Crypto Extensions)
- x86_64 (SSSE3 + AES-NI)
- x86_32 / i686 (SSSE3 + AES-NI)
- Scalar fallback for all platforms
