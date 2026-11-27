# C Architecture Plan

Back to [[00-Index]] · Mapping: [[Porting-Map]] · Tests: [[Test-Vector-Strategy]] · Primitive: [[KCI-Primitive-Design]]

Status: **scaffold built** (Session 02, 2026-11-27): core block, deck, raw stream, wipe and tests exist. The API sketch below is superseded by `include/kci/kci.h`.

## Principles (D-010)
- Portable **C11**, core uses only `uint32_t`/`uint64_t`, no `__int128`, **no heap**, no globals, caller-owned buffers.
- Optional fast paths (SSE2/AVX2/NEON, multi-block) behind compile-time feature checks, always tested against the
  portable path.
- Constant-time core (no secret-dependent branches or table indexes).

## Layout (proposed)
```
include/kci/kci.h          public API
src/core/kci_round.c       the KCI round function (portable; rotations/constants loaded from the expanded deck)
src/core/kci_deck.c        key setup: shuffle the deck, constant-time expansion (spec §4.2)
src/core/kci_stream.c      counter-mode keystream + XOR
src/core/kci_kdf.c         password → key (v1 heritage), salted, cost parameter
src/core/kci_mac.c         optional auth tag (D-013)
src/simd/                  optional SSE2/AVX2/NEON multi-block paths
src/util/                  hex, secure zeroing, CPU feature detect
cli/kci.c                  `kci enc|dec|keygen|bench|selftest`
gui/                       later (toolkit TBD, D-008)
tests/                     unit tests, KATs (known-answer tests), statistical harness
bench/                     cycles/byte
legacy/python/             original 2023 sources (Q8 default) + loop-table check
CMakeLists.txt + Makefile  (Q7 default)
```

## API sketch (follows the KCI-20 spec draft in [[KCI-Primitive-Design]]; AEAD calls to add)
```c
#define KCI_KEY_BYTES   32
#define KCI_NONCE_BYTES 12   /* D-012 */
typedef struct { uint32_t s[16]; uint32_t ctr;
                 uint8_t rot[20][4]; uint32_t rc[20];   /* expanded deck (spec §4.2); SIMD paths add masks/count vectors */
               } kci_ctx;

void kci_init(kci_ctx *c, const uint8_t key[KCI_KEY_BYTES], const uint8_t nonce[KCI_NONCE_BYTES]);
void kci_xor(kci_ctx *c, uint8_t *out, const uint8_t *in, size_t len);     /* enc == dec */
int  kci_kdf(uint8_t key[KCI_KEY_BYTES], const char *pw, size_t pwlen,
             const uint8_t *salt, size_t saltlen, uint32_t cost);
void kci_wipe(kci_ctx *c);
```

## Toolchain present
gcc 13.3, GNU make. Missing: clang, cmake, ARM/32-bit cross compilers, qemu-user, all to install when needed.
