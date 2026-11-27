# Known Issues and Quirks

Back to [[00-Index]] · Q2 is answered (redesign, D-007): the new design must avoid all of these; none need reproducing.

Verified 2026-11-27 by running the code in scratch venvs (numpy 1.26.x and 2.x).

## 1. v1 result depends on the numpy version — 🔴 critical
`key_gen_function` uses `numpy.power` on Python ints.
- **numpy 1.x:** values that fit in int64 are computed as **int64 and silently wrap**. In **64-bit mode**, 6 of 6 test keys
  gave a different gen_key from exact big-int math. 128/256-bit modes fall back to object dtype and are exact (6/6 matched).
- **numpy 2.x (NEP 50):** raises `OverflowError: Python int too large to convert to C long` for **every** key tried,
  in all three modes. **v1 does not run on current numpy.**
- Port options: (a) reproduce the numpy 1.x int64 wrap in 64-bit mode, (b) use the exact math everywhere (the intended behaviour), or
  (c) both behind a flag. Default proposal: (b), with (a) only if old ciphertexts must still decrypt.

## 2. v2 keystream fixed point (all-zero degeneracy) — 🔴
If a block gives `n = 0` (and the bools don't matter), then `R = 2` → next block `00…02` → `n = 0` again, so it is stuck
for good. Verified: from a zero block, every block is `0000…0002`. The same can happen whenever some Bᵢ has its first 15 bytes all zero.
Other short cycles are likely; not yet measured.

## 3. v1 misnamed helpers / overlapping bits
`get_nth_bit_from_end` actually indexes from the start (MSB). `n = bits[7:]` reuses the `sos_b` bit.
The port must copy this exactly.

## 4. v1 padding width taken from bit length, not hash size
`int_to_padded_binary_string` picks the width from `bin(n)` length. A 128-bit hash whose value is < 2⁶⁴ (probability
2⁻⁶⁴) would be treated as 64-bit. Negligible in practice, but bit-exact C should copy it (cheap: count leading zeros).

## 5. No PKCS#7 validation
`pkcs7_unpad` trusts the last byte. A wrong key gives garbage or an exception (`decode('utf-8')`). The C port should validate.

## 6. Global mutable state
`kci_loop_values` is a module global, mutated in place. v2's demo prints whatever state is left over. C: pass a struct.

## 7. v2 is ASCII-only, and dec needs the keystream
`.encode('ascii')` rejects non-ASCII. `dec` takes the keystream, so the "key" for decryption is as long as the message. Q11/Q12.

## 8. v2 import side effects
Importing the module runs the demo (no `if __name__ == "__main__"`). This matters for the test harness: import it with
the demo stripped, or call `exec` on the definitions only.

## 9. Asserts used for validation
`encrypt_block` etc. use `assert`, which is skipped under `python -O`.
