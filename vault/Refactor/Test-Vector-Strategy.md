# Test Vector Strategy

Back to [[00-Index]] · Related: [[KCI-Primitive-Design]], [[Porting-Map]]

Updated 2026-11-27: after the redesign (D-007) the Python is **not** an oracle for the cipher output.

## Status (Session 02, 2026-11-27)
`make test` = 294 checks, all passing at -O0, -O2, -O3 -march=native and under ASan+UBSan:
the RFC 8439 §2.3.2 block, a 300-byte ChaCha-mode keystream checked against OpenSSL (a third implementation),
6 block KATs with their decks (including counters 0, 2³¹−1 and 2³²−1), 8 single-loop schedules, reduced rounds 1–8, a 300-byte
stream KAT with chunked in-place decryption, the counter limit, and the wipe.
Vectors come from the independent Python sketch, so they are **cross-implementation** checks, not self-generated.
Not yet: a 32-bit build (this machine has no `gcc-multilib`), ARM, Windows/macOS, dudect timing.

**Poly1305 + AEAD (Session 02, later):** `make test` = **687 checks**.
- Poly1305: RFC 8439 §2.5.2, plus 140 edge vectors (5 keys including max-clamped r and s = all ones, lengths 0–256 around every
  16-byte boundary, all-0xff and random messages), one-shot and streamed in uneven pieces. Plus 6 **final-reduction** vectors
  (r = 1, three blocks summing to p − 1 … p + 4). All 146 agree with OpenSSL's `POLY1305` MAC.
- AEAD: ChaCha mode reproduces **RFC 8439 §2.8.2** (ciphertext and tag). There are 18 KCI-20 AEAD KATs (AAD 0/12/17 bytes × lengths
  0/1/63/64/65/200) with in-place encrypt and decrypt. Tampering with the ciphertext, tag, AAD or nonce, truncating, or using the wrong key
  all return `KCI_ERR_AUTH` and write nothing. The length limit and `kci_ct_memcmp` are tested too.
- **Mutation check** on the Poly1305 finaliser: 4 of 5 hand-made mutants are caught. Before the final-reduction vectors, the `h0 + 5`
  mutant survived. The survivor is the top-limb overflow carry in `final()`, which needs the accumulator near 2¹³¹ (r = 1) or
  odds of about 2⁻⁷⁸ (general r). It is believed unreachable in practice and kept because it is part of the standard algorithm.

## Layers
0. **Kernel cross-check (KCI-20 spec §11):** a test build that forces ChaCha rotations into every round, turns round constants off and uses ChaCha constants must reproduce
   the RFC 8439 ChaCha20 block, keystream and AEAD vectors. Poly1305 is checked against RFC 8439 on its own.
   `tools/kci_ref.py` already does the block check in Python. It proves the plumbing, not KCI-20 security.
   Plus: a KAT per deck edge case (one loop repeated 20 times, for each loop) so every rotation set is exercised.
1. **Heritage check:** a small script verifies the 8 per-loop action sequences the C round schedules are built from
   against the Python action functions (table in [[KCI-Loop-Model]]). This keeps the MtG model traceable.
2. **Known-answer tests (KATs):** once the design is frozen, the portable C path generates vectors
   (`tests/kat/*.txt`: key, nonce, counter, keystream). Every SIMD/fast path and every target must match them.
3. **Cross-target:** the same KATs on x86-64, ARM64 (qemu/RPi), 32-bit (qemu-i386 / arm-none-eabi on a simulator), Windows/macOS CI.
4. **Property tests:** enc∘dec = id for lengths 0..4096 and random offsets; streaming in chunks = one shot.
5. **Statistical:** PractRand / TestU01 on the keystream, avalanche matrix, reduced-round cycle search.
6. **Sanitizers + constant-time:** ASan/UBSan; dudect-style timing test of `kci_xor` and the round function.
7. **KDF/MAC:** KATs; if SHA-256 is used, NIST FIPS 180-4 vectors.

## Legacy (only if Q14 becomes "yes")
v1 vectors need numpy 1.26 (numpy 2.x crashes, see [[Known-Issues-and-Quirks]] #1).
