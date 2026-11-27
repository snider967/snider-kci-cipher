# Test Vector Strategy

Back to [[00-Index]] · Related: [[KCI-Primitive-Design]], [[Porting-Map]]

Updated 2026-11-27: after the redesign (D-007) the Python is **not** an oracle for the cipher output.

## Layers
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
