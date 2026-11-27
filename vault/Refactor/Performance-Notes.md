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

## Baseline numbers
_Not measured yet._
