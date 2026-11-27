# KCI Primitive Design: KCI-20 spec

Back to [[00-Index]] · Decisions: D-007, D-009, D-010, D-012..D-022 in [[Decisions-Log]] · Layout: [[C-Architecture-Plan]] · Speed: [[Performance-Notes]]

**Status:** **v0.2 accepted** by the owner on 2026-11-27 (P1–P6 → D-017..D-022). No C code yet. Changes from here need a new version and a decision entry.
Reference sketch: `tools/kci_ref.py` (pure Python, used to check this spec; it is not the KAT source).

> ⚠️ KCI-20 is an original, unreviewed cipher. It is for research and fun. Do not present it as secure for real data.

**Changes from v0.1:** the owner rejected the fixed schedule and the near-ChaCha20 core (D-016). The key now picks
which KCI loop each round plays. Each loop has its own rotation amounts and round constant. Measured cost on AVX2: none (§11).

---

## 1. Design stance
**Core principle (owner, D-016): the key chooses the loops.** As in the 2023 code, the key picks which KCI combo runs.
Here it picks one of the 8 loops for each of the 20 rounds, so each key gets its own round function. The owner accepts some
security risk in exchange for originality, and wants to improve the design over time rather than drop that principle.

How v0.2 keeps that principle fast and constant-time:
- **The loop choice changes data, never code.** Every round runs the same instruction sequence. The secret loop only
  decides which rotation amounts and round constant are loaded. So there are no secret branches or secret jumps, and timing
  cannot reveal the loop sequence.
- **The choice is made once per key** ("shuffling the deck"), not per block. Every block under one key then uses the same
  schedule, so the SIMD paths process 8 blocks at once with one shared set of rotation counts.
- **Rotation amounts are chosen so they are cheap to apply as data.** The two rotations on the d word are always 8, 16 or 24
  bits. Those are byte moves, done with one byte-shuffle instruction and a key-selected mask, so they cost the same as
  fixed rotations. The two rotations on the b word can be any amount, and use per-lane variable shifts (`vpsllvd`/NEON
  `vshl`), which cost the same as fixed shifts.

What is borrowed and what is new:
- **Borrowed (general ARX practice):** add-rotate-xor operations on a 4×4 word state, column then diagonal rounds,
  the feed-forward, and the RFC 8439 AEAD composition.
- **New (KCI):** a key-dependent loop schedule, 8 loop-specific rotation sets, loop-specific round constants taken from
  the Python loop table, the deck-shuffle key setup, the zones and constants, the password front end and the file format.

KCI-20 is no longer ChaCha20. It produces different output, its structure depends on the key, and none of ChaCha's security
analysis carries over automatically. The kernel is still general enough for one test trick: forcing ChaCha's rotations and constants into
every round reproduces the RFC 8439 vectors (§11). That proves the C kernel's plumbing, not KCI-20's security.

## 2. Requirements → how the spec meets them
| # | Requirement | Met by |
|---|---|---|
| R1 | key + nonce + counter, counter mode | §3, §5 |
| R2 | decrypt from key + nonce only | §5 |
| R3 | nonlinear state update | ARX rounds, §4 (replaces the linear `vec·n`) |
| R4 | no all-zero fixed point | round constants, §4.4 (verified, §11) |
| R5 | no repeating keystream | unique (nonce, counter) per block, §5 |
| R6 | 32-bit word ops only | add / xor / rotate on `uint32_t` |
| R7 | constant-time, **with key-selected loops** | loop choice = data only, §4.2 and §8 |
| R8 | salted, costly password KDF | §6 |
| R9 | optional authentication (D-013) | AEAD default + raw mode, §7 |

## 3. Parameters (D-012)
| Item | Size |
|---|---|
| Key | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes) |
| Block counter | 32 bits, so at most 2³² − 1 blocks ≈ 256 GiB per (key, nonce). The API must refuse longer input. |
| Block | 64 bytes (16 × 32-bit words) |
| Rounds | 20, each playing one key-selected loop. Reduced-round builds exist only for analysis, never in the library API. |
| Loop schedule | 20 picks × 3 bits = 60 bits from the key setup, so 8²⁰ = 2⁶⁰ possible round functions |
| Tag (AEAD) | 128 bits |

All words are **little-endian** on every target.

## 4. The KCI-20 block function
### 4.1 State layout ("zones")
4 × 4 matrix of 32-bit words `S[0..15]`:

| Row | Words | Zone | Contents |
|---|---|---|---|
| 0 | S0–S3 | **Stack** | constants (keystream: `"KCI 256-bit loop"`; key setup: `"KCI shuffle deck"`) |
| 1 | S4–S7 | **Battlefield** | key words 0–3 |
| 2 | S8–S11 | **Hand** | key words 4–7 |
| 3 | S12–S15 | **Library** | S12 = block counter, S13–S15 = nonce words 0–2 |

Constant words (LE):
- `"KCI 256-bit loop"` = `0x2049434b 0x2d363532 0x20746962 0x706f6f6c`
- `"KCI shuffle deck"` = `0x2049434b 0x66756873 0x20656c66 0x6b636564`

### 4.2 Key setup: shuffling the deck
Once per key:
1. Run the block function (§4.3–4.5) with the **deck** constants, counter 0 and nonce 0, using the fixed public
   **setup schedule** `s_r = r mod 8` (loops `0…7, 0…7, 0…3`).
2. From output words `W0` and `W1`, take 3 bits per round: `s_r = (W[r div 10] >> (3·(r mod 10))) & 7` for r = 0..19.
   This is the key's **deck**: the secret loop sequence.
3. Expand the deck into a per-key round table: for each round r, the rotation set `ρ[s_r]` (§4.3) and the round constant `RC(r, s_r)` (§4.4).
   Read `ρ[s]` with a constant-time select that scans all 8 rows and masks, so the read never indexes memory by a secret.
   SIMD builds also precompute the byte-shuffle masks and shift-count vectors here.
4. Wipe `W` and the deck itself. Only the expanded round table is kept, inside the key context.

Domain separation: the deck constants differ from the stack constants, so no keystream block ever equals the setup block.
The cost is one block per key, which is negligible.

### 4.3 Quarter-round "activation" A_ρ(a, b, c, d) and the 8 loops
```
a += b; d ^= a; d <<<= ρ1        // ρ1 ∈ {8, 16, 24}: a byte move
c += d; b ^= c; b <<<= ρ2        // ρ2: any amount, not a multiple of 8
a += b; d ^= a; d <<<= ρ3        // ρ3 ∈ {8, 16, 24}, ρ3 ≠ ρ1
c += d; b ^= c; b <<<= ρ4        // ρ4: any amount, not a multiple of 8, ρ4 ≠ ρ2; at least one of ρ2, ρ4 is odd
```
**Loop rotation sets** (normative table; `tools/kci_ref.py` stores it as `FROZEN`):

| Loop s | Pieces (from the 2023 code) | ρ1 | ρ2 | ρ3 | ρ4 | packed[s] |
|---|---|---|---|---|---|---|
| 0 | KCI, Trawler, Myr ×2, Mox Opal | 24 | 4 | 8 | 13 | `0x02253250` |
| 1 | KCI, Trawler, Spine, Mind Stone, Chromatic Star, Mox | 8 | 11 | 16 | 25 | `0x046a0aa1` |
| 2 | KCI, Trawler, Myr, Chromatic Star ×2, Mox | 8 | 5 | 16 | 10 | `0x04593691` |
| 3 | KCI, Trawler, Myr, Chromatic Star, Mox | 16 | 3 | 24 | 31 | `0x03580771` |
| 4 | KCI, Trawler ×2, Myr, Mox | 8 | 29 | 24 | 10 | `0x044a55a0` |
| 5 | KCI, Trawler ×2, Spine, Ichor Wellspring, Mox ×2 | 24 | 25 | 16 | 18 | `0x058d49d2` |
| 6 | KCI, Trawler, Myr, Chromatic Sphere ×2, Mox | 16 | 21 | 24 | 30 | `0x04493690` |
| 7 | KCI, Trawler, Myr, Pyrite Spellbomb, Mox | 8 | 22 | 16 | 27 | `0x04490770` |

**Where the rotation amounts come from.** For each loop, a deterministic search is seeded with that loop's packed vector
(`random.Random(packed[s])` in CPython). It draws candidate sets under the §4.3 rules, skips sets already taken, and keeps the
first one that passes a diffusion filter: used on its own for 2 rounds, it must reach ≥ 95 % of ChaCha's avalanche, and at 3 rounds
it must have a mean ≥ 254/512 flipped bits with a minimum ≥ 200. `python3 -I tools/kci_ref.py --search` reruns the search and
confirms it reproduces the table. **The table is normative, and the search only documents where it came from.**
⚠️ The filter is weak: almost any random set passes. It removes obviously bad sets, but it is no substitute for differential
trail analysis (§12, first improvement).

`packed[s] = cd | mpil<<4 | msil<<8 | nmp<<12 | gat<<16 | tos<<20 | sos<<24`, built from the loop vector
`(cd, mpil, msil, nmp, gat, tos, sos)` in [[KCI-Loop-Model]] (all entries ≤ 13, so they fit 4 bits).

### 4.4 Round r (r = 0..19), playing loop s = s_r
```
S[r & 3] ^= RC(r, s)                                                  // the loop's trigger goes on the stack
if r even:  A_ρ[s](0,4,8,12)  A_ρ[s](1,5,9,13)  A_ρ[s](2,6,10,14) A_ρ[s](3,7,11,15)   // column round
else:       A_ρ[s](0,5,10,15) A_ρ[s](1,6,11,12) A_ρ[s](2,7,8,13)  A_ρ[s](3,4,9,14)    // diagonal round
RC(r, s) = (packed[s] + (r + 1) · 0x9E3779B9) mod 2³²
```
The `(r + 1)·φ` term (golden ratio, the usual nothing-up-my-sleeve number) keeps constants distinct when the deck repeats a loop.
Round constants are public per (r, s), but **which one is used is secret**, because it follows the deck. They break slide
and rotational symmetries and remove the all-zero fixed point (R4).

### 4.5 Output (feed-forward)
`block(key, ctr, nonce) = serialize_LE( P_deck(S_in) + S_in )` (word-wise addition mod 2³²). Adding the input back stops anyone from
running the rounds backwards from known keystream (fixes the v2 inversion).

## 5. Stream encryption (raw mode)
- Keystream = `block(key, 1, nonce) ‖ block(key, 2, nonce) ‖ …`. Counter 0 is reserved for the AEAD MAC key (§7),
  so raw and AEAD modes give the **same ciphertext bytes**. Raw mode just leaves out the tag.
- `ct = pt ⊕ keystream`; decryption is the same operation (R2: needs only key + nonce).
- The last partial block uses the leading bytes of its keystream block.
- **Rule: never reuse a (key, nonce) pair.** The CLI generates a random 96-bit nonce per message. Under one key that
  stays safe up to about 2³² messages; password mode (§6) uses a fresh salt, so a fresh key (and a fresh deck), every time anyway.
- ⚠️ Raw mode is **malleable**: flipping a ciphertext bit flips the same plaintext bit, and nothing detects it. The CLI
  only offers it behind an explicit `--raw` flag with a warning.

## 6. Password front end (v1 heritage, D-014)
- `key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 bytes)`. The key then shuffles its deck (§4.2). This is where the v1 idea
  "the password picks the combo" now lives.
- Salt: 16 random bytes per file. Default iterations: **600 000** (the current OWASP figure for PBKDF2-SHA256), stored in the header
  so it can be raised later. The minimum accepted on decrypt is 100 000.
- SHA-256 is written in-house (Q6 default, needs owner confirmation) and checked against FIPS 180-4 vectors.
- Later option: a memory-hard KDF (Argon2id or scrypt) with a caller-provided buffer, which keeps the core heap-free. It resists GPU guessing better, but
  it is heavier on MCUs. It would get a new KDF id in the header.

## 7. AEAD mode (default, D-013)
This is the RFC 8439 composition with KCI-20 in place of ChaCha20:
1. `otk = first 32 bytes of block(key, 0, nonce)` → the Poly1305 one-time key.
2. Encrypt as in §5 (counter from 1).
3. `tag = Poly1305(otk, AAD ‖ pad16 ‖ CT ‖ pad16 ‖ LE64(len AAD) ‖ LE64(len CT))`.
4. Decrypt: recompute the tag, compare in **constant time**, and release plaintext only if it matches.
- Poly1305 uses a 32-bit-limb implementation (portable, MCU-friendly) and is checked against the RFC 8439 Poly1305 vectors on its own.
- Why Poly1305 and not HMAC-SHA256: it is several times faster (performance is the project goal), and the composition is the
  standard, analysed one. Its security rests on the keystream being unpredictable, which is exactly what KCI-20 has to deliver.

## 8. Constant-time rules
- **Secret:** the key, the deck, the expanded round table, state copies, otk.
- Every round runs the same instructions. The deck only changes **values loaded from the key context** (shift counts,
  byte-shuffle masks, round constants). No secret-dependent branch, function pointer, loop bound or table index.
- Deck expansion reads `ρ[s]` with a masked scan over all 8 rows (§4.2).
- Variable rotations by a secret amount are constant-time on every supported target: x86 `rol r32, cl`/`shlx`/`shrx`/`vpsllvd`, ARM
  `ROR Rd, Rm` (Cortex-M0/M3/M4/A-class) and NEON `vshl`. **Not** on 8- and 16-bit MCUs without a barrel shifter, which are out of scope (D-010).
- Secrets are wiped with a non-elidable `kci_wipe` before return. The dudect-style timing test covers key setup, `block`, `kci_xor`
  and the tag check, and it must include keys with very different decks.

## 9. Options considered
| Option | Decision | Why |
|---|---|---|
| Fixed public schedule (v0.1) | **Rejected by owner** (D-016) | Drops the core principle: the key chooses the loops. |
| Per-round loop choice via branches or function pointers | Rejected | Leaks the deck through timing and the branch predictor. |
| Compute all 8 loop variants each round and mask the result | Rejected | Constant-time, but about 8× slower. Making the choice data-only (v0.2) gets the same property for free. |
| Choose the deck per block (from the nonce or counter) instead of per key | Deferred | Blocks in a SIMD batch would need different rotations per lane. AVX2 `vpsllvd` can do it, SSSE3 byte shuffles cannot. Per-key keeps every path fast. Revisit if analysis shows per-key decks are weak. |
| Allow any rotation amount in all 4 positions | Kept as "**KCI-X**" research variant | Measured at 1.18× slower on AVX2 (§11), with no evidence that it helps security. |
| Key-selected round count (the old "n iterations") | Rejected | Timing would leak the round count. |
| Hash / sponge built on the KCI permutation (to drop SHA-256) | Deferred | A new hash design is another unreviewed primitive. |
| Chunked AEAD (STREAM construction) for huge files | Deferred to the CLI work | Version 1 does single-shot AEAD. The CLI writes to a temp file and renames it only after the tag verifies. |

## 10. Decisions (signed off 2026-11-27 → D-017..D-022)
- **P1** Key-selected loop schedule: one deck of 20 loop picks per key, shuffled by the setup block (§4.2).
- **P2** 8 loop rotation sets with the byte/any split (§4.3), table as given; round constants `RC(r, s)` (§4.4).
- **P3** 20 rounds, 32-bit counter, counter 0 reserved for the MAC key.
- **P4** KDF = PBKDF2-HMAC-SHA256, 16-byte salt, 600 000 iterations by default (§6).
- **P5** AEAD = RFC 8439 composition with Poly1305; raw mode = same ciphertext with no tag, behind `--raw` (§5, §7).
- **P6** File format below.

### File format v1 (CLI)
```
offset size  field
0      4     magic "KCI\x01"
4      1     mode       0 = AEAD, 1 = raw
5      1     kdf id     0 = raw key (no KDF), 1 = PBKDF2-HMAC-SHA256
6      2     reserved   0
8      4     iterations LE32 (0 when kdf id = 0)
12     16    salt       (zeros when kdf id = 0)
28     12    nonce
40     …     ciphertext
end-16 16    tag        (AEAD only)
```
In AEAD mode the 40-byte header is the AAD, so changing any header field makes decryption fail.

## 11. Verified so far (Session 02, 2026-11-27)
**Correctness and diffusion** (`python3 -I tools/kci_ref.py`):
- **Kernel cross-check:** with ChaCha rotations in every round, round constants off and ChaCha constants, the data-driven kernel reproduces
  the **RFC 8439 §2.3.2** block (first 16 bytes `10f1e7e4d13b5915500fdd1fa32071c4`).
- `--search` reproduces the frozen rotation table exactly.
- The all-zero state is not a fixed point under a loop schedule (R4).
- **Deck uniformity:** across 2 000 random keys, each loop was picked 4 903–5 070 times (ideal 5 000).
- **Avalanche**, flipping key bits with the deck held fixed, 12 random keys per row; numbers vary slightly per run:

  | Rounds | Mean flipped bits (of 512; ideal 256) | Minimum |
  |---|---|---|
  | 2 | about 197 (ChaCha in the same test: about 181) | 126 |
  | 3 | about 256 | 219 |
  | 4 | about 255 | 228 |
  | 20 | about 255 | 218 |

  This is a smoke test only, not cryptanalysis.
- **Provisional KCI-20 block** (key `00..1f`, nonce `000000090000004a00000000`, counter 1, deck
  `[2,7,2,3,7,5,5,5,0,1,0,7,5,3,0,1,0,7,6,5]`):
  `e5df9762136ae3da99d74fa612d12005e476386472aabb7abf420c81c929a406592ff123cf33355adc2f057ea8c2c99853fe4a1a8d60bd850468a2782776ff5d`.
  It becomes a real KAT only once the C portable path reproduces it.

**Speed** (prototype benchmarks in `bench/prototype/`, not the real implementation; Intel i7-8700T, gcc 13.3; full numbers in [[Performance-Notes]]):

| Path | Fixed rotations | Key-selected loops | Cost |
|---|---|---|---|
| AVX2, 8 blocks at once, v0.2 layout (byte shuffles + `vpsllvd`) | about 3 075–3 098 MB/s | about 3 150–3 173 MB/s | **none measurable** (0.97–0.98×) |
| AVX2, any amount in all 4 positions (KCI-X) | about 3 075 MB/s | about 2 600 MB/s | 1.18× |
| Scalar x86 fallback (`rol r32, cl`) | about 583–635 MB/s | about 375–386 MB/s | 1.55–1.65× |

The x86 scalar slowdown matters little in practice, because every x86-64 CPU has SSE2 and almost all have SSSE3/AVX2. On ARM, scalar
`ROR` by a register takes 1 cycle, so the scalar cost there should be small. That is **unmeasured**: no ARM toolchain or qemu yet.

**Not verified:** Poly1305, PBKDF2, AEAD, the file format (none implemented); SSE2/SSSE3/NEON speed; statistical batteries; timing tests.

## 12. Improvement roadmap (carry forward, don't abandon)
1. **Differential and linear trail bounds** for each of the 8 rotation sets, and for the worst decks (one loop repeated 20 times,
   alternating pairs). Use a SAT/MILP model like those published for ChaCha. Replace any set that comes out weak, or raise the round count.
2. Look for **weak decks**: schedules whose diffusion is clearly worse than average. If any exist, constrain the deck derivation
   (for example, forbid the same loop on 4 rounds in a row).
3. **Related-key behaviour of the deck:** do nearby keys give nearby decks? (The setup block should make decks look independent; test it.)
4. PractRand / TestU01 on the keystream across many keys; reduced-round (2–8) distinguisher search.
5. Revisit per-block decks (§9) and KCI-X once the analysis tooling exists.
