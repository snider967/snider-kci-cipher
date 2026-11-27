# Goals and Scope

Back to [[00-Index]] · Related: [[Open-Questions]], [[Decisions-Log]]

## Goals (owner-confirmed 2026-11-27)
1. **Redesign** the Snider-KCI cipher as a **new original KCI-based primitive** in C ([[Decisions-Log]] D-007, D-009).
   KCI loops become a real round/keystream function: nonlinear and nonce-based, with no fixed points.
2. Performance first: portable C11 core that is fast on x86-64, ARM64, desktop OSes **and 32-bit microcontrollers** (D-010).
3. Deliverables: `libkci` + `kci` CLI + GUI (toolkit TBD, built last) (D-008).
4. Keep the project's identity: both v1 ideas (password → key derivation) and v2 ideas (stream cipher) survive on a shared core (D-006).
5. Measurable: reproducible test vectors, statistical test runs and cycles/byte benchmarks ([[Test-Vector-Strategy]], [[Performance-Notes]]).

## Non-goals
- Bit-for-bit compatibility with the 2023 Python (D-007).
- Claiming production-grade security. The cipher is an **experimental, unreviewed design**, and docs and the CLI must say so.
- A general MtG rules engine.

## Success criteria
- [x] Written design spec for the new primitive ([[KCI-Primitive-Design]]) reviewed by the owner before coding the core.
- [x] C reference implementation + frozen test vectors (Session 02).
- [x] Fixes every weakness in [[Cryptanalysis-Notes]] (no repeating-key XOR, nonce, no degenerate cycles, nonlinear mixing).
- [ ] Passes statistical batteries on the keystream (e.g. PractRand / TestU01 SmallCrush/Crush). This is evidence, not proof.
- [x] Warning-free on gcc/clang (`-Wall -Wextra -Wpedantic`), clean under ASan/UBSan, builds for a 32-bit target (CI, Session 02; MCU target not yet).
- [ ] Benchmarks: cycles/byte on x86-64 and ARM64, vs the Python baseline (x86-64 MB/s only so far).
