# Open Questions

Back to [[00-Index]] · Answers go to [[Decisions-Log]] once settled.

Status key: 🔴 open · 🟡 provisional default in use · 🟢 answered

## Answered
| # | Question | Answer | Decision |
|---|---|---|---|
| Q1 | Which version(s) to port? | Both, on a shared core | D-006 |
| Q2 | Bit-exact vs redesign? | **Free to redesign**: Python is inspiration, not oracle | D-007 |
| Q3 | Interface? | Library + CLI + GUI | D-008 |
| Q4 | Vault location? | In the repo, committed | D-002 |
| Q5 | Targets? | x86-64 Linux, ARM64, Windows/macOS, **32-bit/microcontrollers** | D-010 |
| Q9 | Git workflow? | Branch + PRs into `main` | D-011 |
| Q13 | Role of KCI in the redesign? | **New original KCI primitive** (KCI loops are the core keystream/round function) | D-009 |
| Q15 | GUI toolkit? | Decide later; library + CLI first | D-008 |

## Still open
| # | Question | Status | Notes / default |
|---|---|---|---|
| Q6 | SHA-256 / hash: in-house or a library? | 🟡 | Default: in-house, no dependencies (needed for microcontrollers). |
| Q7 | Build system? | 🟡 | Default: Makefile + CMake (CMake helps Windows/macOS/MCU toolchains). |
| Q8 | Keep the Python files in the repo? | 🟡 | Default: keep them under `legacy/python/` as historical reference. |
| Q10 | License for the C code? | 🔴 | Repo has none. |
| Q11 | Decrypt from the key (not the keystream)? | 🟡 | With the redesign: yes, key + nonce. |
| Q12 | Arbitrary bytes/files instead of ASCII? | 🟡 | With the redesign: yes. |
| Q14 | A "legacy" mode that reads old v1/v2 ciphertexts? | 🟡 | Default: no (no known stored ciphertexts). |
| Q16 | Key/nonce/block sizes for the new primitive (e.g. 256-bit key, 96/128-bit nonce)? | 🔴 | To propose in the design note. |
| Q17 | Authentication (MAC/AEAD) as well as encryption? | 🔴 | Recommended: yes, even for an experimental cipher. |
| Q18 | Should v1/v2 survive as separate "modes", or be merged into one new design? | 🔴 | Q1 said "both"; with a redesign, propose v1 → password/KDF front-end and v2 → stream core. |
