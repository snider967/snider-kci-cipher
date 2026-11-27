# Performance Notes

Back to [[00-Index]]

## Where time goes in Python
- The loop "iterations" are **not iterated**: `perform_n_iterations` multiplies, so each loop costs about 30 dict operations, whatever n is.
- Per 16-byte v2 block: dict updates, about 6 big-int multiplies with ~120–250-bit operands, a modulo, `to_bytes`/`from_bytes`, and
  `bytes +=` concatenation, which is **O(n²)** over the keystream for long messages.
- v1: `bytes +=` in `encrypt_ecb` is also quadratic; per-byte Python list comprehension XOR.

## Expected C wins (old 1:1-port estimate; the redesign is ARX on 32-bit words, see [[KCI-Primitive-Design]])
- vec table constant; per block ≈ a handful of 64×64→128 and 128×128→256 multiplies + Mersenne fold → tens of ns.
- XOR: memory bandwidth (SIMD via auto-vectorisation).
- No allocation per block; output written straight into the caller's buffer.

## Structural limits
- The v2 chain `Bᵢ₊₁ = KG(Bᵢ)` is serial. The redesign uses **counter mode** (R1), so blocks are independent and SIMD/multi-core is possible.
- v1 keystream is a single block repeated, so it is effectively free after derivation; cost is XOR + one or two SHA-256 calls.

## Plan
1. Baseline: Python cycles/byte for v2 (re-enable the commented timeit code in a harness) and v1 encrypt.
2. C: `bench/` with `clock_gettime` + optional `rdtsc`; report cycles/byte at 16 B, 1 KiB, 1 MiB, 100 MiB.
3. Compare `__int128` vs portable u64 path on each target (Q5).

## Key-selected loops: prototype measurements (Session 02, 2026-11-27)
Intel i7-8700T, gcc 13.3. Sources: `bench/prototype/scalar_rot.c`, `bench/prototype/avx2_rot.c`, built with
`gcc -O2 scalar_rot.c` / `gcc -O3 -march=native scalar_rot.c` and `gcc -O3 -mavx2 avx2_rot.c`. Best of 3 runs.

| Path | Fixed rotations | Key-selected | Ratio |
|---|---|---|---|
| Scalar, `-O2` | 583 MB/s | 375 MB/s | 1.55× slower |
| Scalar, `-O3 -march=native` | 635 MB/s | 386 MB/s | 1.65× slower |
| AVX2 8-way, all 4 rotations variable (`vpsllvd`/`vpsrlvd`) | 3 075 MB/s | 2 600 MB/s | 1.18× slower |
| AVX2 8-way, d rotations as key-selected byte shuffles + b rotations variable (**spec v0.2**) | 3 075–3 098 MB/s | 3 150–3 173 MB/s | 0.97–0.98× (no cost) |

Lessons:
- Shift-by-`xmm`-count (`vpslld ymm, ymm, xmm`) is 2 micro-ops on Intel. A first AVX2 attempt with it was 1.78× slower. Use `vpsllvd` with a broadcast count vector.
- Scalar x86 `rol r32, cl` is the slow case. It matters only on the scalar fallback.
- An earlier single-block benchmark at `-O3` reported 2.9 GB/s for scalar, because the compiler removed unused work. Benchmarks must consume the full output.
- Unmeasured: SSE2/SSSE3 (shift by `xmm` count, so probably slower than AVX2), NEON, scalar ARM/MCU.

## Real portable C implementation (Session 02, 2026-11-27)
Same machine, `gcc -O2`, `build/libkci.a`, 64 MiB of `kci_stream_xor`, best of 5:
- `kci_core`: **381 MB/s**. `kci_block_words`: 364 MB/s. Stream XOR: **~316 MB/s**. Key setup: ~0.43 µs.
- How it got there: wiping temporaries once per call instead of once per block (204 → 236 MB/s); unrolling 4 rounds so the
  round-constant target and the column/diagonal choice are fixed in the code (core 295 → 381); a full-block XOR fast path (stream 286 → 316).
  Interleaving the quarter-rounds step by step alone did not help in C.
- AEAD encrypt (KCI-20 + Poly1305, 32 MiB, best of 5): **~256 MB/s** portable.
- `kci_kdf_password` at 600 000 iterations: **0.52 s** (portable SHA-256, HMAC key state precomputed once). OpenSSL via `hashlib` does
  the same work in 0.33 s with assembly. Every 1.6× the defender is slower than an attacker's optimised code is a 1.6× smaller effective cost.
  A SHA-256 fast path (SHA-NI / ARMv8 SHA2 instructions) is a later option.

## Baseline numbers (Python)
_Not measured yet._
