# KCI Primitive Design (new, original)

Back to [[00-Index]] · Decisions: D-007, D-009, D-010 in [[Decisions-Log]]

Status: **requirements only**. The design itself is next session's work and needs owner review before coding.

> ⚠️ This is an original, unreviewed cipher. It is for research and fun. Do not present it as secure for real data.

## Requirements (from the owner's answers + [[Cryptanalysis-Notes]])
| # | Requirement | Fixes |
|---|---|---|
| R1 | Key + **nonce** + block **counter** → keystream block (counter mode) | v2 no-IV reuse; serial chain (allows parallel/SIMD) |
| R2 | Decrypt from key + nonce only | v2 `dec` needs the keystream (Q11) |
| R3 | **Nonlinear** state update: loop counters must not be `vec·n` | linear/quadratic invertibility of v1/v2 |
| R4 | Round constants + counter injection so the all-zero state is not a fixed point | v2 `0…02` fixed point |
| R5 | Every keystream block is distinct; no repeating key | v1 repeating-key XOR |
| R6 | 32-bit word operations only in the core (add/xor/rotate/mul32) | MCU target (D-010) |
| R7 | Constant-time: no secret-dependent branches or table indexes | timing side channels. **Note:** "select loop s from key bits" is secret-dependent; do it branch-free (e.g. compute all 8 and mask, or bake the selection into data) |
| R8 | Password front-end (v1 heritage): a KCI-flavoured KDF with salt + iteration cost | v1 unsalted single SHA-256 |
| R9 | Optional authentication tag (Q17) | malleability of XOR ciphers |

## Design direction to explore (not decided)
- State = 16 × 32-bit words (512 bits), like other ARX designs, labelled with KCI "zones": battlefield, graveyard, hand,
  stack, mana pool.
- Each round = one **KCI loop** chosen by data-dependent but branch-free mixing. Card "actions" become fixed
  ARX micro-ops (e.g. *sacrifice* = add + rotate into the mana words; *cast* = xor from mana into the stack words;
  *Trawler trigger* = word permutation graveyard → hand). The 8 Python loops give the action sequences.
- Keystream = state after R rounds + feed-forward of the input (prevents inversion).
- Parameters to propose: key 256-bit, nonce 96/128-bit, counter 32/64-bit, block 64 bytes, rounds R (tunable).

## Validation plan
Statistical batteries, avalanche/diffusion tests (bit-flip of key/nonce/counter → ~50% output change), cycle/
fixed-point search on reduced-round versions, timing (dudect-style) checks.
