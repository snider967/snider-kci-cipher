# Decisions Log

Back to [[00-Index]] · Questions pending: [[Open-Questions]]

Format: `ID | date | decision | rationale | status (provisional/accepted/superseded)`

| ID | Date | Decision | Rationale | Status |
|---|---|---|---|---|
| D-001 | 2026-11-27 | Clone upstream into `/home/cfs/Documents/ChatGPT/Snider-KCI-Cipher`. | Owner request. | accepted |
| D-002 | 2026-11-27 | Vault lives at `vault/` in the repo, **committed**, Obsidian wikilinks. | Owner answer Q4. | accepted |
| D-003 | 2026-11-27 | ~~Python is the bit-exact oracle.~~ Python stays as **historical reference** for the KCI loop model; its loop table is still verified against the C table. | Changed by D-007. | superseded by D-007 |
| D-004 | 2026-11-27 | The Python loop model is linear (`vec[s]·n`), so the C port can use an 8×7 constant table. | Measured; Python already multiplies. Note: in the redesign this linearity is a **weakness** to remove. | accepted (as an analysis fact) |
| D-005 | 2026-11-27 | ~~Mod 2¹²⁸−1 arithmetic for bit-exact compatibility.~~ | No longer needed after D-007; may still appear in the new design. | superseded by D-007 |
| D-006 | 2026-11-27 | Cover both v1 and v2 ideas on one shared C core. | Owner answer Q1. | accepted |
| D-007 | 2026-11-27 | **Free to redesign.** No bit-for-bit compatibility with the Python; numpy quirks and known weaknesses do not need reproducing. | Owner answer Q2. | accepted |
| D-008 | 2026-11-27 | Deliverables: library + CLI + GUI. GUI toolkit decided later; library + CLI first. | Owner answers Q3, Q15. | accepted |
| D-009 | 2026-11-27 | Build a **new original KCI-based primitive** (KCI loops as the core keystream/round function), with nonce + counter. | Owner answer Q13. ⚠️ An unreviewed original cipher is experimental; documentation must say so and not claim production security. | accepted |
| D-010 | 2026-11-27 | Targets: x86-64 Linux, ARM64, Windows/macOS, 32-bit/microcontrollers. Core = **portable C11 on 32-bit words**, no `__int128` needed, no heap in the core. Optional SIMD/`__int128` fast paths behind feature checks. | Owner answer Q5: the MCU target sets the lowest common denominator. | accepted |
| D-011 | 2026-11-27 | Git: work on branch `c-refactor`, PRs into `main`; `main` keeps the Python until the C version is ready. | Owner answer Q9. Update 2026-11-27: owner merged `c-refactor` into `main` (PR #1, C + `legacy/python/`); later work uses topic branches + PRs. | accepted |
| D-012 | 2026-11-27 | Key 256 bits, nonce 96 bits, 32-bit word state (ChaCha-style sizing). | Owner answer Q16. Random nonces stay safe up to about 2^32 messages per key; fits MCUs. | accepted |
| D-013 | 2026-11-27 | Authentication is **optional**: AEAD (encrypt + tag) is the default; a raw stream mode stays available for experiments. | Owner answer Q17. The raw mode is malleable and must be documented as such. | accepted |
| D-014 | 2026-11-27 | **Merge v1 and v2 into one design**: the v1 idea becomes the password/KDF front end, the v2 idea becomes the stream core. Refines D-006. | Owner answer Q18. | accepted |
| D-015 | 2026-11-27 | License: **Apache-2.0** for the C code. | Owner answer Q10. Permissive, with an explicit patent grant. | accepted |
| D-016 | 2026-11-27 | **The key chooses the loops** (core principle). Reject the fixed schedule and the near-ChaCha20 core of spec v0.1; accept some security risk for originality and improve the design over time. Spec v0.2 does this with a per-key deck of loop picks that changes data only (constant-time, SIMD-friendly). | Owner feedback on spec v0.1. Measured cost on AVX2: none (spec §11). | accepted |
| D-017 | 2026-11-27 | Key-selected loop schedule: one deck of 20 loop picks per key, shuffled by a setup block with the "KCI shuffle deck" constants (spec v0.2 P1, §4.2). | Owner signed off spec v0.2. | accepted |
| D-018 | 2026-11-27 | 8 loop rotation sets (d rotations ∈ {8,16,24}, b rotations free) as frozen in the spec table; round constants RC(r, s) = packed[s] + (r+1)·0x9E3779B9 (P2, §4.3–4.4). | Owner signed off spec v0.2. | accepted |
| D-019 | 2026-11-27 | 20 rounds, 32-bit block counter, counter 0 reserved for the MAC key (P3). | Owner signed off spec v0.2. | accepted |
| D-020 | 2026-11-27 | KDF = PBKDF2-HMAC-SHA256, 16-byte salt, 600 000 iterations by default, minimum 100 000 on decrypt (P4, §6). | Owner signed off spec v0.2. | accepted |
| D-021 | 2026-11-27 | AEAD = RFC 8439 composition with Poly1305 (default); raw mode = same ciphertext without tag, CLI flag `--raw` with a warning (P5, §5, §7). | Owner signed off spec v0.2. | accepted; raw-mode ciphertext part superseded by D-024 |
| D-022 | 2026-11-27 | File format v1: 40-byte header (magic, mode, kdf id, iterations, salt, nonce) used as AAD (P6, §10). | Owner signed off spec v0.2. | accepted |
| D-023 | 2026-11-27 | `kci dec` refuses raw-mode files unless `--raw` is given, so a flipped mode byte cannot silently turn off authentication. | Downgrade found by the CLI tests (spec §5). Implementation-level safety fix, made without asking; owner can revisit. Spec-level fix pending as Q19. | accepted (owner to confirm) |
| D-024 | 2026-11-27 | **Spec v0.3: domain-separate raw and AEAD modes.** Raw mode uses its own stack constants `"KCI 256-bit raw!"`, so raw and AEAD keystreams and ciphertexts never coincide. `kci_stream_init` becomes internal; the public raw API is `kci_raw_init`. File format layout stays v1 (no files from the v0.2 raw mode exist). | Owner answer Q19, after the CLI tests found the v0.2 mode downgrade. | accepted |
| D-025 | 2026-11-27 | **HARD RULE: the project incurs $0 cost, always.** GitHub Actions only on free standard GitHub-hosted runners, and only while the repo is public (every job has `if: !github.event.repository.private`); job timeouts ≤ 20 min; superseded runs cancelled; no schedules, caches, uploaded artifacts, Pages, package publishing, third-party actions, larger/self-hosted runners or secrets for paid services. Enforced by `tools/check_ci_cost.py` (first CI job). No paid service of any kind is added without the owner's explicit approval. | Owner instruction when CI was added. GitHub account has no billing card, so overage would be blocked anyway; the rule keeps quota use at zero too. | accepted (hard rule) |
| D-026 | 2026-11-27 | Install a free SAT/MILP solver (Python package from PyPI, into a project-local virtual environment, not system-wide) for the spec §12 trail bounds, once the v0.4 draft is done. | Owner answer Q21. Free, so within D-025. | accepted |
