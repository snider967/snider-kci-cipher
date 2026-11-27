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
| Q10 | License for the C code? | Apache-2.0 | D-015 |
| Q16 | Key/nonce sizes? | 256-bit key, 96-bit nonce | D-012 |
| Q17 | Authentication? | Optional: AEAD by default, raw stream mode for experiments | D-013 |
| Q18 | v1/v2 as modes or merged? | Merged: v1 → password/KDF front end, v2 → stream core | D-014 |
| Q19 | Domain-separate raw and AEAD modes? | Yes: raw mode gets its own constants (spec v0.3) | D-024 |

## Still open
| # | Question | Status | Notes / default |
|---|---|---|---|
| Q6 | SHA-256 / hash: in-house or a library? | 🟡 | Default **applied** (Session 02): in-house `kci_sha256.c`. Owner did not object. |
| Q7 | Build system? | 🟡 | Default **applied** (Session 02): Makefile + CMakeLists.txt, both tested in CI. Owner did not object. |
| Q8 | Keep the Python files in the repo? | 🟡 | Default **applied** (Session 02): moved to `legacy/python/`. Owner did not object. |
| Q11 | Decrypt from the key (not the keystream)? | 🟡 | With the redesign: yes, key + nonce. |
| Q12 | Arbitrary bytes/files instead of ASCII? | 🟡 | With the redesign: yes. |
| Q14 | A "legacy" mode that reads old v1/v2 ciphertexts? | 🟡 | Default: no (no known stored ciphertexts). |
