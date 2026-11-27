# Session 02 Audit — 2026-11-27

Back to [[00-Index]] · Session note: [[2026-11-27-Session-02]] · Template: [[Audit-Template]]

## Repo state checked
- git: `main` at `f18a141` (merge of PR #2); PR #1 (`c-refactor`, KCI-20 v0.3 in C) and PR #2 (`ci-workflow`) are both merged. Audit on branch `analysis`.
- build/tests (CI run 46051704065 on `main`, all 6 jobs green):
  - Linux x86-64 gcc and clang: 1336 library checks (AVX2 path), `make sanitize` and the portable build (1312) all pass.
  - Linux ARM64 gcc, macOS ARM64 clang: 1312 checks (portable path), sanitizers and portable build pass.
  - gcc `-m32`: 1334 checks, AVX2 path selected on i386. CMake build + ctest pass.
  - 69/69 CLI checks in every job. `check_ci_cost.py`: 0 violations.
- Local: the portable variant (`-DKCI_NO_SIMD -DKCI_NO_INT128`) passes, 1312 + 69.
- bench: not re-run in this audit (figures in [[Performance-Notes]] are from earlier in Session 02, same machine).

## Note-by-note check
| Note | Accurate? | Fixes made |
|---|---|---|
| 00-Index | stale | status (PRs merged, CI), branch line, upstream HEAD, audit link, hard-rules pointer |
| Project-Overview | yes (history) | — |
| Goals-and-Scope | stale checkboxes | ticked spec, C reference + vectors, weakness fixes, warnings/sanitizers/32-bit; benchmark item annotated |
| Open-Questions | Q7 stale | CMake now tested in CI |
| Decisions-Log | D-011 stale | noted the merge and topic-branch workflow; D-025 present |
| Repository-Map | stale | `main` not `c-refactor`; added `.github/workflows/ci.yml`, `tools/check_ci_cost.py`; toolchain line |
| KCI-Loop-Model, v1/v2 notes | yes (historical) | — |
| Known-Issues-and-Quirks | yes (legacy Python) | — |
| C-Architecture-Plan | stale | `__int128` principle, layout marked as original proposal, toolchain line |
| KCI-Primitive-Design | §7 and §11 stale | Poly1305 limbs; check counts and CI platforms; ARM correctness verified, speed not |
| Porting-Map | yes | — |
| Test-Vector-Strategy | stale gap list | added the CI coverage paragraph |
| Performance-Notes | yes | — |
| Cryptanalysis-Notes | yes, but no KCI-20 analysis yet | to be extended by the §12 analysis that follows this audit |
| Workflow | yes | hard rules section added earlier this session (D-025) |
| Session-02 note | yes | checkpoint 14 added after this audit |

## Wikilinks
- Scripted check over every note: 0 dead links; every note is linked from [[00-Index]].

## Open questions status
- Answered this session: Q10, Q16, Q17, Q18, Q19. Defaults applied without objection: Q6, Q7, Q8.
- Still open (provisional defaults): Q6, Q7, Q8, Q11, Q12, Q14. D-023 is still marked "owner to confirm".

## Verified vs unverified
- Verified: everything under "Repo state checked" (commands or CI logs read).
- Unverified: Windows/MSVC build, big-endian, MCU targets, ARM/macOS speed, timing (dudect) tests, statistical batteries, and any cryptanalysis of KCI-20.

## Carry-over to next session
- Security analysis per spec §12 (started right after this audit, same session).
- Owner: confirm D-023 and the Q6/Q7/Q8 defaults; decide whether to add Windows to CI (free on public repos, within D-025).
