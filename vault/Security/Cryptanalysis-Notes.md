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
  turns an AEAD file into a raw file, which has no check. **Fixed in v0.3** by mode domain separation (D-024), and the CLI still requires an
  explicit `--raw` (D-023). Tested both ways: a downgraded file decrypts to garbage, and an upgraded one fails authentication. See [[KCI-Primitive-Design]] §5.
- No cryptanalysis of the KCI-20 permutation yet; see the roadmap in [[KCI-Primitive-Design]] §12.

## KCI-20 v0.3: first empirical analysis (Session 02, 2026-11-27, spec §12 items 1–3)
Tools: `tools/analysis/kci_diffbias.c` and `tools/analysis/kci_deckstats.c` (`make analysis`), run against the real C core. Every
run is deterministic. Raw output is in `vault/Security/results/`. **This is evidence, not proof**, and it is not a substitute for the SAT/MILP trail bounds.

### Single-bit differential bias through reduced rounds (§12 items 1 and 2)
Method (Aumasson et al., FSE 2008, the test behind the Salsa/ChaCha PNB attacks): flip one counter or nonce bit (128 attacker-controlled bits),
run r rounds of the permutation without feed-forward, random key words every sample, and measure eps = 2·Pr[output-bit difference] − 1 for all
512 output bits. "Biased" means max |eps| is above 6/√N; noise alone stays below about 4.6/√N.

| Schedule | 3 rounds, max \|eps\| (N = 2²⁰) | 4 rounds |
|---|---|---|
| ChaCha rotations {16,12,8,7} (baseline) | 0.198 | clean (≤ 0.0041 at 2²⁰; ≤ 0.0021 at 2²²) |
| loop 0 ×20 {24,4,8,13} | **0.546** | clean (≤ 0.0018 at 2²²) |
| loop 1 ×20 {8,11,16,25} | 0.123 | clean |
| loop 2 ×20 {8,5,16,10} | 0.051 | clean |
| loop 3 ×20 {16,3,24,31} | 0.124 | clean |
| loop 4 ×20 {8,29,24,10} | **0.357** | clean |
| loop 5 ×20 {24,25,16,18} | 0.205 | clean |
| loop 6 ×20 {16,21,24,30} | 0.071 | clean |
| loop 7 ×20 {8,22,16,27} | 0.220 | clean |
| all 64 alternating pairs (s, t, s, t, …) | biased | clean at 4 for every pair (screening, 16 input bits) |
| 400 random decks from the real key setup | biased in most | clean at 4 for all 400 (screening) |
| worst of those decks (4,4,7,2,3,…) | **0.654** | clean (≤ 0.0022 at 2²²) |

Findings:
1. **Rounds to randomness: the same as ChaCha.** Every schedule tested, including the worst decks, shows no single-bit bias after 4 rounds,
   which is also where ChaCha's rotations stop showing one at this precision. By this measure, 20 rounds leave KCI-20 the same nominal
   margin as ChaCha20. That is not a security level: the best published ChaCha attacks reach 7 rounds with multi-bit differences, linear
   combinations and probabilistic neutral bits, none of which this tool tries.
2. **The 3-round bias varies 10× between loops** (0.05 to 0.55, ChaCha 0.20), and it is set by the first three loops of the deck. Loops 0
   and 4 are the weakest; with a bad start (4, 4, 7) a deck reaches 0.65, about 3.3× ChaCha's. A larger 3-round bias is the starting point
   of the 6- and 7-round PNB attacks on ChaCha, so keys with such decks are likely somewhat easier to attack at reduced rounds. The attacker
   does not know the deck (3 secret bits per round), which works against them, but that has not been quantified.
3. **Improvement within the core principles (proposal, Q20):** keep the 8 key-selected loops and the structure, and re-run the rotation search
   with a real filter: 3-round max single-bit bias no worse than ChaCha's (≤ 0.20). That would replace loops 0 and 4 (and maybe 5 and 7, which
   are level with ChaCha). It is a spec change (v0.4) with new KATs, so it waits for the owner.

### Deck statistics and related keys (§12 items 2 and 3), 2²⁴ random keys
- **Uniform:** every position and every adjacent pair of positions is uniform over the loops (largest chi-square z = 2.37 and 1.91).
- **Weak-looking decks occur at the ideal rate:** long runs of one loop and decks with few distinct loops match a uniform source exactly
  (for example, a run of ≥ 7 equal loops: 754 observed against 799 expected in 2²⁴ keys). The longest run seen was 9. Since the run tests above found
  no deck that needs more than 4 rounds, **no deck constraint is needed** on this evidence.
- **Related keys:** flipping one key bit leaves 2.5002 of the 20 deck positions equal on average (independent decks: 2.5), the worst of the 256 key bits
  has z = 2.58, the histogram matches Binomial(20, 1/8), and none of 67 million flips kept the deck. The setup block makes decks of
  related keys look independent.
- **Structured keys** (zero, all-ones, every single-bit key, every repeated-byte key, 00 01 … 1f): decks look random (loop-count z = 0.76).
- **Full block under related keys:** flipping one key bit gives no measurable bias in any output bit (max |eps| 0.0169, noise level 0.019; 2¹⁶ keys per bit).

### Not done yet
- SAT/MILP differential and linear **trail bounds** (§12 item 1 proper): needs a solver (none installed; a PyPI install is free under D-025 but needs the owner's OK).
- Multi-bit input differences, linear correlations, PNB attack estimates for 6–7 rounds.
- PractRand / TestU01 on the keystream (§12 item 4).
