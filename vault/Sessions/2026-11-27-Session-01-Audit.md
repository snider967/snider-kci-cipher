# Session 01 Audit — 2026-11-27

Back to [[00-Index]] · Session: [[2026-11-27-Session-01]]

## Repo state checked
- `git status` / `git log`: branch `c-refactor`, upstream history intact (10 commits, HEAD of `main` `2a837a4`), vault commit on top. Python files unchanged (`git diff origin/main -- '*.py'` is empty, verified).
- Build/tests/bench: N/A (no C code yet).

## Note-by-note check
| Note | Accurate? | Fixes made |
|---|---|---|
| 00-Index | Yes after fix | Removed a literal double-bracket "wikilinks" example (dead link); added [[KCI-Primitive-Design]]; updated status/branch |
| Project-Overview | Yes after fix | Added the redesign decision to "Why C" |
| Goals-and-Scope | Yes | Rewritten after owner answers |
| Open-Questions | Yes | Answered Q1–Q5, Q9, Q13, Q15; added Q14, Q16–Q18 |
| Decisions-Log | Yes | D-003, D-005 marked superseded by D-007; D-006…D-011 added |
| Repository-Map | Yes | — |
| KCI-Loop-Model | Yes after fix | "Key insight" reframed as an analysis of the old code (no longer a port plan) |
| v1-GUI-Block-Cipher | Yes after fix | Port notes marked historical |
| v2-Lite-Stream-Cipher | Yes | — |
| Known-Issues-and-Quirks | Yes after fix | Header updated: nothing needs reproducing |
| Cryptanalysis-Notes | Yes after fix | Weaknesses are now design requirements |
| KCI-Primitive-Design | Yes (requirements only) | New note |
| C-Architecture-Plan | Yes | Rewritten for portable 32-bit core |
| Porting-Map | Yes | Turned into a concept map; dropped items marked ⛔ |
| Test-Vector-Strategy | Yes | Python is no longer the oracle |
| Performance-Notes | Yes after fix | Old 1:1 estimate labelled; counter mode noted |
| Workflow / templates | Yes | — |

## Wikilinks
- Dead links: 2 found (`wikilinks` example in the index; this audit note before it existed). Both resolved. Re-checked by script: 0 dead, every note indexed.

## Open questions status
- Answered this session: Q1, Q2, Q3, Q4, Q5, Q9, Q13, Q15.
- Still open: Q10, Q16, Q17, Q18 (blocking the design); Q6, Q7, Q8, Q11, Q12, Q14 have provisional defaults.

## Verified vs unverified
- Verified by running code: loop table, v2 fixed point, v1 numpy 1.x/2.x behaviour.
- Unverified: v1 GUI was not launched; no performance baseline; the MtG-legality notes in [[KCI-Loop-Model]] are not checked.

## Carry-over to next session
- See "Next session: start here" in [[2026-11-27-Session-01]].
