# Cryptanalysis Notes

Back to [[00-Index]]

Owner chose a redesign (D-007/D-009): **every weakness below is a requirement for the new design to fix**, see [[KCI-Primitive-Design]].
This is a hobby cipher and should not protect real data in its current form.

## v1
- **Repeating-key XOR.** Every block is XORed with the same `h/8`-byte key ("ECB" with XOR has no diffusion). Equal
  plaintext blocks give equal ciphertext blocks. One known-plaintext block reveals the block key, and that decrypts
  everything under the same password.
- **Small effective keyspace.** gen_key is a degree ≤ 3 polynomial in n with tiny coefficients, picked by
  (s, 5 bools). Many inputs collide after `mod (2^128−1)`. The final SHA-256 hides structure but adds no entropy.
- In practice security comes down to SHA-256(password) → block key. The KCI step is a deterministic remap.

## v2
- **First keystream block is invertible.** For a 64-bit key, n < 2⁵⁶, so `R ≈ c₂·n² + c₁·n + 2` stays < 2¹²⁸ with **no
  modular reduction**. Given 16 bytes of known plaintext, try the 8 values of s and 32 bool combinations, solve the
  integer quadratic for n, and the key is recovered almost instantly.
- **Deterministic chain** with no nonce/IV: the same key always gives the same keystream (two-time-pad risk).
- **Degenerate cycles** (see [[Known-Issues-and-Quirks]] #2).
- `dec` needs the keystream, so the real secret is as long as the message (one-time-pad key handling, without OTP security).

## If a redesign is wanted (ideas, not decisions)
- Use the KCI step only as a creative KDF component, then key a vetted stream cipher (ChaCha20) or a counter-mode
  construction with a nonce.
- At minimum, add a nonce and counter mode so blocks can be computed in parallel and keystreams are never reused.

## KCI-20 v0.2 (Session 02)
- **Mode downgrade (file format v1):** raw and AEAD modes share their keystream and ciphertext (D-021), so flipping the header mode byte
  turns an AEAD file into a raw file, which has no check. Mitigated in the CLI (D-023: raw files only with an explicit `--raw`). The proper
  fix is mode domain separation (Q19). See [[KCI-Primitive-Design]] §5.
- No cryptanalysis of the KCI-20 permutation yet; see the roadmap in [[KCI-Primitive-Design]] §12.
