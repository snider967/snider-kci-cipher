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
| D-011 | 2026-11-27 | Git: work on branch `c-refactor`, PRs into `main`; `main` keeps the Python until the C version is ready. | Owner answer Q9. | accepted |
