# Test Vector Strategy

Back to [[00-Index]] · Related: [[KCI-Primitive-Design]], [[Porting-Map]]

Updated 2026-11-27: after the redesign (D-007) the Python is **not** an oracle for the cipher output.

## Status (Session 02, 2026-11-27)
`make test` = 294 checks, all passing at -O0, -O2, -O3 -march=native and under ASan+UBSan:
the RFC 8439 §2.3.2 block, a 300-byte ChaCha-mode keystream checked against OpenSSL (a third implementation),
6 block KATs with their decks (including counters 0, 2³¹−1 and 2³²−1), 8 single-loop schedules, reduced rounds 1–8, a 300-byte
stream KAT with chunked in-place decryption, the counter limit, and the wipe.
Vectors come from the independent Python sketch, so they are **cross-implementation** checks, not self-generated.
Not yet at that point: 32-bit, ARM, macOS (all now covered by CI, see below); still not: Windows, dudect timing.

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

**SHA-256 / HMAC / PBKDF2 (Session 02, later):** `make test` = **983 checks** (oracle: Python `hashlib`; FIPS/RFC values asserted in the generator).
- SHA-256: FIPS 180-4 "abc", the 448-bit message and one million 'a' (streamed), plus every length 0–129 and 191–193, 255–257 and 1000, one-shot and streamed.
- HMAC-SHA256: RFC 4231 cases 1, 2, 3, 4, 6 and 7 (keys longer than a block), plus key lengths 0, 63, 64 and 65.
- PBKDF2-HMAC-SHA256: RFC 7914 §11 #1 (c = 1) and #2 (c = 80 000), plus c = 2, 3, 5 and 4096, an empty password, a 100-byte password and a 97-byte output.
  `kci_kdf_password` at 600 000 iterations is checked, and so are refusals below 100 000 iterations or below a 16-byte salt.

**Poly1305 64-bit limbs (Session 02):** both implementations pass every Poly1305/AEAD vector: the default build (44-bit limbs on this
machine) and `-DKCI_NO_INT128` (26-bit limbs), plus ASan+UBSan. Mutation check on the 64-bit code: **7 of 8 mutants caught**. The
survivor is again the top-limb overflow carry in the finaliser, which is unreachable in practice, as for the 32-bit code.

**AVX2 path (Session 02):** **1336 library + 69 CLI checks**. The AVX2 kernel is compared directly against the portable `kci_block`
for 24 keys (24 decks) at counters including 0xfffffff0 and 0xfffffff8. It is also compared through the stream API with odd lead-ins and lengths
511–8192, which exercises the dispatch and the portable tail. The last 8 counters before the limit go through AVX2 and then the limit is enforced.
In the CLI, 5000-byte C ↔ Python cross-checks go through the AVX2 path. A mutant AVX2 kernel (wrong ρ3 mask) gives 129 failures.
Every build variant passes: -O0, -O2, -O3 -march=native, ASan+UBSan, and `-DKCI_NO_SIMD` (portable everywhere: 1312 checks, since the direct-kernel checks are skipped).

**Spec v0.3 (domain separation):** **1141 library + 67 CLI checks**. Added a raw-mode KAT (`kat_raw_ct`, from the Python `block_raw`), checks that raw ≠ AEAD
under the same key and nonce, that `kci_raw_init` leaves the caller's key alone, that a downgraded file decrypts to garbage even with `--raw`,
and that a raw file relabelled as AEAD fails authentication. The C ↔ Python raw-file cross-check uses the new raw domain on both sides.

**CLI (Session 02, later):** `make test` runs the 1135 library checks **and** `tests/cli_test.sh` (66 checks), both also under ASan+UBSan.
- Round trips at every chunk and tag-holdback boundary (0 … 1 MiB, around 65 536); output size = input + 56; random nonce per encryption.
- Password mode at the minimum and default iterations, plus refusal below the minimum.
- Wrong password or key → exit 2, with no output and no temp file left.
- Tampering with the body, the tag, the nonce, the mode, the reserved bytes, the iterations or the salt is refused, as are truncation, an appended
  byte, a short file, a non-KCI file and a hostile iteration count. Key-type mismatches are refused, and overwriting needs `-f`.
- Key files and outputs are created 0600.
- Raw mode: round trip, the warning, refusal without `--raw`, the **downgrade** being refused, and malleability shown.
- **Cross-implementation:** C enc → Python dec and Python enc → C dec (key, password, raw) with `tools/kci_file.py`, built only on
  `tools/kci_ref.py` and `hashlib`.
Not tested: the interactive password prompt (no terminal in the test run); the Windows code paths.

**CI (PR #2, D-025):** every push to `main` and every PR runs `make test`, `make sanitize` and the portable build
(`-DKCI_NO_SIMD -DKCI_NO_INT128`) on Linux x86-64 gcc and clang (AVX2 path, 1336 checks), Linux ARM64 gcc and macOS ARM64 clang
(portable path, 1312 checks), plus gcc `-m32` (1334 checks, AVX2 path on i386) and the CMake build with ctest and the CLI tests. All 69 CLI checks pass
everywhere. Not covered: Windows/MSVC, big-endian, MCUs.

**Spec v0.4 (D-027, D-028):** all KATs regenerated from the Python reference with the new table (`tools/gen_vectors.py`); `kci selftest` uses the new
key-`00..1f` block. **1336 library + 71 CLI checks**: the two new CLI checks are that new files carry `KCI\x02` and that a format-1 (v0.3) file is refused with a
message naming v0.3. Passing locally at -O0, -O2, -O3 -march=native, ASan+UBSan, and `-DKCI_NO_SIMD -DKCI_NO_INT128` (1312 + 71).

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
