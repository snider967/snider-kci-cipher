# KCI Primitive Design: KCI-20 spec

Back to [[00-Index]] · Decisions: D-007, D-009, D-010, D-012..D-024 in [[Decisions-Log]] · Layout: [[C-Architecture-Plan]] · Speed: [[Performance-Notes]]

**Status:** **v0.4 accepted** (2026-11-27, P7/P8 → D-027/D-028): retuned loop rotation sets (§4.3, §13) and file format 2. v0.2 was signed off as P1–P6 → D-017..D-022. v0.3 adds raw/AEAD domain separation (Q19 → D-024).
Implemented in C (v0.4: draft PR #4, implementation PR #5). Changes from here need a new version and a decision entry.
Reference sketch: `tools/kci_ref.py` (pure Python, used to check this spec; it is not the KAT source).

> ⚠️ KCI-20 is an original, unreviewed cipher. It is for research and fun. Do not present it as secure for real data.

**Changes in v0.4:** six of the eight loops get new rotation amounts, so every 3-loop deck start is no weaker than ChaCha at 3 rounds
(v0.3: 58 of 512 starts were, worst 3.4×). The file magic becomes `"KCI\x02"`. Everything else is unchanged (§13).

**Changes in v0.3:** raw mode gets its own stack constants (`"KCI 256-bit raw!"`), so raw and AEAD keystreams never coincide
(§4.1, §5). This closes the mode-downgrade the CLI tests found in v0.2.

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
| 0 | S0–S3 | **Stack** | constants by domain: AEAD `"KCI 256-bit loop"`, raw `"KCI 256-bit raw!"`, key setup `"KCI shuffle deck"` |
| 1 | S4–S7 | **Battlefield** | key words 0–3 |
| 2 | S8–S11 | **Hand** | key words 4–7 |
| 3 | S12–S15 | **Library** | S12 = block counter, S13–S15 = nonce words 0–2 |

Constant words (LE):
- `"KCI 256-bit loop"` = `0x2049434b 0x2d363532 0x20746962 0x706f6f6c`
- `"KCI 256-bit raw!"` = `0x2049434b 0x2d363532 0x20746962 0x21776172` (v0.3)
- `"KCI shuffle deck"` = `0x2049434b 0x66756873 0x20656c66 0x6b636564`

Each domain gets its own block outputs. The deck itself (key setup) is shared, because it depends only on the key.

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
**Loop rotation sets, v0.4** (normative table; `tools/kci_ref.py` stores it as `FROZEN`; the v0.3 table is in §13):

| Loop s | Pieces (from the 2023 code) | ρ1 | ρ2 | ρ3 | ρ4 | packed[s] |
|---|---|---|---|---|---|---|
| 0 | KCI, Trawler, Myr ×2, Mox Opal | 16 | 3 | 24 | 27 | `0x02253250` |
| 1 | KCI, Trawler, Spine, Mind Stone, Chromatic Star, Mox | 8 | 11 | 16 | 25 | `0x046a0aa1` |
| 2 | KCI, Trawler, Myr, Chromatic Star ×2, Mox | 8 | 5 | 16 | 10 | `0x04593691` |
| 3 | KCI, Trawler, Myr, Chromatic Star, Mox | 8 | 13 | 16 | 2 | `0x03580771` |
| 4 | KCI, Trawler ×2, Myr, Mox | 8 | 14 | 24 | 17 | `0x044a55a0` |
| 5 | KCI, Trawler ×2, Spine, Ichor Wellspring, Mox ×2 | 8 | 3 | 16 | 14 | `0x058d49d2` |
| 6 | KCI, Trawler, Myr, Chromatic Sphere ×2, Mox | 8 | 4 | 16 | 25 | `0x04493690` |
| 7 | KCI, Trawler, Myr, Pyrite Spellbomb, Mox | 8 | 12 | 16 | 1 | `0x04490770` |

**Where the rotation amounts come from (v0.4).** `tools/analysis/kci_rotsearch.c` (`search 14`) fills loops 0…7 in order: it keeps the v0.3 set if it passes,
otherwise it draws candidates from splitmix64 seeded with `packed[s]` under the rules above. A set is accepted when every 3-loop deck start built from it and the
loops accepted so far has a 3-round single-bit differential bias no larger than ChaCha's (all 512 starts, so it covers every deck). Loops 1 and 2 are kept from v0.3.
Details and measurements: §13 and [[Cryptanalysis-Notes]]. **The table is normative; the search documents where it came from.**

_v0.3 provenance (history):_ for each loop, a deterministic search is seeded with that loop's packed vector
(`random.Random(packed[s])` in CPython). It draws candidate sets under the §4.3 rules, skips sets already taken, and keeps the
first one that passes a diffusion filter: used on its own for 2 rounds, it must reach ≥ 95 % of ChaCha's avalanche, and at 3 rounds
it must have a mean ≥ 254/512 flipped bits with a minimum ≥ 200. `python3 -I tools/kci_ref.py --search` still reproduces the v0.3 table.
That filter was weak: almost any random set passed, which is why v0.4 replaced it.

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
- Keystream = `block_raw(key, 1, nonce) ‖ block_raw(key, 2, nonce) ‖ …`, where `block_raw` is the block function with the
  **raw-mode stack constants** (v0.3, D-024). The AEAD message keystream uses the AEAD constants, so the two modes never share
  keystream or ciphertext. (In v0.2 they were identical, which allowed the downgrade below.) Counters run from 1, giving both modes the same length limit.
- `ct = pt ⊕ keystream`; decryption is the same operation (R2: needs only key + nonce).
- The last partial block uses the leading bytes of its keystream block.
- **Rule: never reuse a (key, nonce) pair.** The CLI generates a random 96-bit nonce per message. Under one key that
  stays safe up to about 2³² messages; password mode (§6) uses a fresh salt, so a fresh key (and a fresh deck), every time anyway.
- ⚠️ Raw mode is **malleable**: flipping a ciphertext bit flips the same plaintext bit, and nothing detects it. The CLI
  only offers it behind an explicit `--raw` flag with a warning.
- ⚠️ **Downgrade finding (v0.2, found by the CLI tests) and fix:** in v0.2, raw and AEAD files shared their ciphertext. Flipping the
  header's mode byte turned an authenticated file into a "raw" one, which a decrypter would accept with no check. Two defences now:
  1. **v0.3 domain separation (D-024):** a downgraded file decrypts to garbage, and a raw file relabelled as AEAD fails its tag check.
  2. **CLI (D-023):** `kci dec` refuses raw-mode files unless the user passes `--raw`.
- In the C API, raw mode is `kci_raw_init` + `kci_stream_xor`. The general `kci_stream_init` is internal, so callers cannot rebuild the
  v0.2 mistake by using the AEAD-domain keystream as "raw mode".

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
- Poly1305 uses 44-bit limbs where `unsigned __int128` exists and 26-bit limbs elsewhere (portable, MCU-friendly); both are checked against the RFC 8439 Poly1305 vectors and OpenSSL.
- Why Poly1305 and not HMAC-SHA256: it is several times faster (performance is the project goal), and the composition is the
  standard, analysed one. Its security rests on the keystream being unpredictable, which is exactly what KCI-20 has to deliver.

## 8. Constant-time rules
- **Secret:** the key, the deck, the expanded round table, state copies, otk.
- Every round runs the same instructions. The deck only changes **values loaded from the key context** (shift counts,
  byte-shuffle masks, round constants). No secret-dependent branch, function pointer, loop bound or table index.
- Deck expansion reads `ρ[s]` with a masked scan over all 8 rows (§4.2).
- Variable rotations by a secret amount are constant-time on every supported target: x86 `rol r32, cl`/`shlx`/`shrx`/`vpsllvd`, ARM
  `ROR Rd, Rm` (Cortex-M0/M3/M4/A-class) and NEON `vshl`. **Not** on 8- and 16-bit MCUs without a barrel shifter, which are out of scope (D-010).
- Poly1305 uses 64×64→128-bit multiplies on x86-64/ARM64 (constant-time there: `MUL`, `MUL`/`UMULH`). Elsewhere it needs a constant-time 32×32→64-bit multiply. That holds on x86, ARMv7-A/ARMv8 and Cortex-M4/M7 (`UMULL` takes 1 cycle). It does
  **not** hold on Cortex-M3, whose `UMULL`/`SMULL` take 3–5 cycles depending on the operands, and possibly not on Cortex-M0 when a library supplies the 64-bit multiply.
  If the M3/M0 targets become real, they need a multiply routine with a fixed cycle count.
- The AVX2 path picks each round's byte-shuffle mask with compare-and-mask (no secret index), and broadcasts the shift counts.
  Its compiled code has only loop-control branches. Its per-call schedule is wiped. Register spills of the state are not, which is the same limit any C implementation has.
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
- **P5** AEAD = RFC 8439 composition with Poly1305; raw mode behind `--raw` (§5, §7). v0.3 (D-024): raw mode uses its own constants, no longer the AEAD ciphertext minus the tag.
- **P6** File format below.
- **P7** (v0.4, D-027) Rotation table of §4.3, chosen by the all-starts 3-round criterion (§13).
- **P8** (v0.4, D-028) File magic `"KCI\x02"` = format 2 = KCI-20 v0.4; `kci dec` refuses format 1 (v0.3) files with a clear message.

### File format 2 (CLI; v1 layout, magic bumped in v0.4)
```
offset size  field
0      4     magic "KCI\x02"   (format 2; "KCI\x01" was KCI-20 v0.3 and is refused)
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
**v0.4 (implemented in C):** see [[Test-Vector-Strategy]]. 1336 library checks and 71 CLI checks, cross-checked against the
Python reference; v0.3 passed in CI on Linux x86-64 (gcc, clang), Linux ARM64, macOS ARM64 and 32-bit x86. **The values below are from the
design stage (v0.2/v0.3 table) and are history:** v0.4 changes every deck and block. The v0.4 block for key `00..1f`, nonce `000000090000004a00000000`,
counter 1 (deck `[0,3,5,6,6,4,6,7,3,7,4,5,2,4,2,4,3,7,4,6]`) is
`40b9da6580f402a175df9b60394cab46d57e073c98252ad92b2df9962a6ca139a5ab360260272181fa5c66e6dad33d7457f2a7d3d9b5acce32bb89c80bf35d0d` (C, Python and `kci selftest` agree).

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
`ROR` by a register takes 1 cycle, so the scalar cost there should be small. ARM64 **correctness** is verified in CI; ARM **speed** is still unmeasured.

**Real implementation (later in Session 02):** the C AVX2 path runs the raw stream at **3 077 MB/s**, against 311 MB/s portable, which
confirms the prototype. See [[Performance-Notes]].

**Not verified:** SSE2/SSSE3/NEON speed; statistical batteries; timing tests.

## 12. Improvement roadmap (carry forward, don't abandon)
Status 2026-11-27: first empirical pass done for items 1–3 (single-bit differentials, deck and related-key statistics), see [[Cryptanalysis-Notes]].
Result: every loop and deck is clean after 4 rounds, like ChaCha; 58 of the 512 three-loop starts have a weaker 3-round bias than ChaCha (worst 3.4×) → fixed in v0.4 (§13); no weak decks or related-key structure found.
1. **Differential and linear trail bounds** for each of the 8 rotation sets, and for the worst decks (one loop repeated 20 times,
   alternating pairs). Use a SAT/MILP model like those published for ChaCha. Replace any set that comes out weak, or raise the round count.
   _Empirical part done; SAT/MILP bounds still open (no solver installed)._
2. Look for **weak decks**: schedules whose diffusion is clearly worse than average. If any exist, constrain the deck derivation
   (for example, forbid the same loop on 4 rounds in a row).
3. **Related-key behaviour of the deck:** do nearby keys give nearby decks? (The setup block should make decks look independent; test it.)
4. PractRand / TestU01 on the keystream across many keys; reduced-round (2–8) distinguisher search.
5. Revisit per-block decks (§9) and KCI-X once the analysis tooling exists.

## 13. v0.4: retuned loop rotation sets (Q20; signed off 2026-11-27 as P7/P8 → D-027/D-028; implemented)
This section keeps the case for the change as it was put to the owner. Evidence and method:
[[Cryptanalysis-Notes]] and `tools/analysis/kci_rotsearch.c`.

**Why.** The 3-round single-bit differential bias, the usual starting point of reduced-round attacks on ChaCha-like designs (PNB attacks), is
fully determined by a deck's first three loops. So all 8³ = 512 possible starts cover every deck. Under v0.3, **58 of the 512 starts are
weaker than ChaCha**, and the worst, (3, 3, 7), has a bias of 0.683, 3.4× ChaCha's 0.203. Every v0.3 loop appears in at least one weak start, so the
problem is how loops combine, not just loops 0 and 4. All schedules are still clean after 4 rounds, so this is a margin issue, not a break.

**What changes.** Only the rotation amounts of six loops. Everything else stays as in v0.3: the principle that the key chooses the loops (D-016), 8 loops, the
ρ1/ρ3 byte-rotation rule, the loop round constants `packed[s]` and their 2023 heritage, the deck derivation, 20 rounds, the modes and the KDF.

| Loop s | v0.3 (ρ1, ρ2, ρ3, ρ4) | **v0.4** | Source |
|---|---|---|---|
| 0 | 24, 4, 8, 13 | **16, 3, 24, 27** | search candidate 2 |
| 1 | 8, 11, 16, 25 | 8, 11, 16, 25 | kept |
| 2 | 8, 5, 16, 10 | 8, 5, 16, 10 | kept |
| 3 | 16, 3, 24, 31 | **8, 13, 16, 2** | candidate 15 |
| 4 | 8, 29, 24, 10 | **8, 14, 24, 17** | candidate 26 |
| 5 | 24, 25, 16, 18 | **8, 3, 16, 14** | candidate 18 |
| 6 | 16, 21, 24, 30 | **8, 4, 16, 25** | candidate 1 |
| 7 | 8, 22, 16, 27 | **8, 12, 16, 1** | candidate 130 |

**Where the amounts come from (replaces the v0.3 provenance in §4.3).** `build/kci_rotsearch search 14` fills loops 0…7 in order. For each loop it
first tries the v0.3 set, then candidates from splitmix64 seeded with `packed[s]` under the §4.3 rules. It accepts the first candidate for which **every
start built from it and the loops already accepted** has a 3-round max |eps| no larger than ChaCha's, measured with the same samples and seeds (N = 2¹⁴ per input
bit, all 128 counter/nonce bits, all 512 output bits). The search is deterministic and runs in about 6 minutes on 12 threads. A variant that allows 10% slack
for estimation noise (`search 14 1.10`) kept no more v0.3 sets and gave a worse table, so the strict version is proposed.

**Measured (N = 2¹⁶, independent of the search's own estimates):**

| | v0.3 | v0.4 | ChaCha |
|---|---|---|---|
| starts weaker than ChaCha (of 512) | 58 | 2 (at 1.02×, within the measurement noise) | — |
| worst 3-round start, max \|eps\| | 0.683 (3.4×) | 0.208 (1.02×) | 0.203 |
| 4 rounds, worst start | clean | clean (0.0023 at 2²², threshold 0.0029) | clean (0.0022) |
| 4 rounds, each loop repeated 20 times | clean | clean | clean |

**Costs and caveats.**
- Speed: unchanged within noise, as expected (ρ1/ρ3 are still byte rotations). Measured: raw stream AVX2 2 673–2 722 MB/s (v0.3 2 728–2 738), portable 315–317 (v0.3 304–317), AEAD 1 227–1 233 MB/s (v0.3 1 237–1 250), same machine, alternating runs.
- Loops 7 and 3 now have ρ4 = 1 and 2. Those are allowed by §4.3 and pass the filter, but very small rotations spread bits slowly, so they should be watched in the trail-bound work (Q21).
- The criterion is one statistic: single-bit, forward, 3 rounds. It does not cover multi-bit or linear trails, or the backward direction from the output that PNB
  attacks also use. The SAT/MILP bounds (§12 item 1, Q21 approved) are the next check of this table.
- Changing the table changes every deck (the setup block uses it), so every KAT changes and v0.3 files cannot be decrypted by v0.4.

**Confirmed on the implemented v0.4** (`kci_diffbias 18`, `kci_deckstats 22`, raw output `vault/Security/results/v04-*.txt`): worst of 400 random decks
at 3 rounds 0.201 (v0.3: 0.654; ChaCha 0.197); every constant deck, alternating pair and random deck clean at 4 rounds; decks uniform, related-key decks independent.

**Signed off (2026-11-27):**
- **P7** Adopt the v0.4 rotation table above and the search criterion as its provenance (§4.3 is rewritten on adoption; `tools/kci_ref.py` `FROZEN` updated; KATs regenerated).
- **P8** File format: bump the magic to `"KCI\x02"` for KCI-20 v0.4, so v0.4 tools refuse v0.3 files with a clear message instead of an authentication failure.
  The layout is unchanged. Alternative: keep `"KCI\x01"`, since no real v0.3 files are expected to exist (experimental cipher).
