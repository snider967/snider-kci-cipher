# C Architecture Plan

Back to [[00-Index]] · Mapping: [[Porting-Map]] · Tests: [[Test-Vector-Strategy]] · Primitive: [[KCI-Primitive-Design]]

Status: **library + CLI built** (Session 02, 2026-11-27): core block, deck, raw/AEAD streams, Poly1305, SHA-256/PBKDF2, the AVX2 path
(`src/simd/kci_avx2.c`, picked at run time), the CLI and the tests. The API sketch below is superseded by `include/kci/kci.h`.

## Principles (D-010)
- Portable **C11**, core uses only `uint32_t`/`uint64_t` (Poly1305 uses `unsigned __int128` where the compiler has it, with a 32-bit fallback), **no heap**, no globals, caller-owned buffers.
- Optional fast paths (SSE2/AVX2/NEON, multi-block) behind compile-time feature checks, always tested against the
  portable path.
- Constant-time core (no secret-dependent branches or table indexes).

## Layout (original proposal; actual files in [[Repository-Map]]: KDF and MAC live in `kci_sha256.c`, `kci_poly1305.c`, `kci_aead.c`)
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
Dev machine: gcc 13.3, GNU make. CI (free, D-025) adds clang, CMake, Linux ARM64, macOS ARM64 and gcc -m32. Windows/MSVC and MCU targets are not built anywhere yet.
