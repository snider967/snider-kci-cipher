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
- CLI, 256 MiB file with a key file: enc 1.16 s, dec 1.16 s (~230 MB/s each), max RSS 1.6 MB whatever the file size (64 KiB chunks).

## AVX2 path (Session 02, `src/simd/kci_avx2.c`)
8 blocks at once, with the v0.2 rotation layout: d rotations are byte shuffles with masks picked in constant time, b rotations use `vpsllvd`/`vpsrlvd`.
It is selected at run time (`__builtin_cpu_supports("avx2")`) and `kci_impl()` reports which path is in use. Same machine, `gcc -O2`, best of 5:

| | Portable | AVX2 | Speed-up |
|---|---|---|---|
| Raw stream (128 MiB) | 311 MB/s | **3 077 MB/s** | 9.9× |
| AEAD encrypt (64 MiB) | 257 MB/s | **1 011 MB/s** | 3.9× (now limited by portable Poly1305) |
| CLI, 256 MiB file, enc / dec | 1.16 s / 1.16 s | **0.40 s / 0.41 s** | 2.9× (RSS 1.6 MB) |

The raw stream matches the prototype (3 150 MB/s, [[KCI-Primitive-Design]] §11), so the real kernel kept the prototype's
"key-selected loops cost nothing" result.

## Poly1305 with 64-bit limbs (Session 02)
Where the compiler has `unsigned __int128` (x86-64, ARM64), Poly1305 uses 44/44/42-bit limbs; elsewhere it uses 26-bit limbs (`-DKCI_NO_INT128` forces those).
- Poly1305 alone: 1 502 → **2 160 MB/s** (1.44×; the 2–3× estimate was optimistic on this CPU).
- AEAD encrypt: 1 011 → **1 268 MB/s**. CLI, 256 MiB: **0.35 s** each way.
- Reference point: OpenSSL's assembly ChaCha20-Poly1305 does 2 349 MB/s on this machine.
- Next step if wanted: a vectorised AVX2 Poly1305 (4 blocks at a time, as OpenSSL does). It is the remaining AEAD bottleneck.

## Spec v0.4 (D-027)
Same machine, alternating runs of v0.4 and v0.3 builds: raw stream AVX2 2 673–2 722 MB/s (v0.3 2 728–2 738), portable 315–317 (v0.3 304–317),
AEAD 1 227–1 233 (v0.3 1 237–1 250). Unchanged within noise, as expected: the d rotations are still byte shuffles. (The raw-stream figure is below the
earlier 3 077 MB/s for both versions alike, which points at the machine state that day, not the table.)

## Baseline numbers (Python)
_Not measured yet._
