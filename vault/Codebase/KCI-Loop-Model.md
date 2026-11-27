# KCI Loop Model

Back to [[00-Index]] · Used by [[v1-GUI-Block-Cipher]] and [[v2-Lite-Stream-Cipher]]

## Counters (the `kci_loop_values` dict)
| Key | Meaning |
|---|---|
| `cd` | cards drawn |
| `mpil` | mana produced in loop |
| `msil` | mana spent in loop |
| `nmp` | net mana produced (`mpil − msil`) |
| `gat` | game actions taken |
| `tos` | triggers on stack |
| `sos` | spells on stack / spells cast (`sos` is missing from the header comment) |

Assumptions (from the source): infinite mana, no lands, no other cards in hand or graveyard.

## Actions (each adds to the counters)
| Function | gat | mpil | msil | tos | cd | sos |
|---|---|---|---|---|---|---|
| `tap_n_sac_mopal` (Mox Opal) | +2 | +3 | | | | |
| `tap_n_sac_mstone(t)` (Mind Stone) | +2 | +3 | | +t | | |
| `sac_retriever(t)` (Myr Retriever) | +1 | +2 | | +1+t | | |
| `activate_chromatic_star` | +1 | | +1 | +2 | +1 | |
| `activate_sbomb` (Pyrite Spellbomb) | +1 | | +1 | +1 | | |
| `sac_artifact(spine, draw, t)` | +1 | +2 | | spine: 1+t · draw: 1+t (+1 cd) · else: t | draw: +1 | |
| `cast_artifact(cmc, etb, wellspring)` | +1 | | +cmc | wellspring or etb: +1 | wellspring: +1 | +1 |

`t` = number of Scrap Trawlers.

## The 8 loops — per-iteration vectors (measured by running the Python, n = 1)
| s | Loop pieces (from comments) | cd | mpil | msil | nmp | gat | tos | sos |
|---|---|---|---|---|---|---|---|---|
| 0 | KCI, Trawler, Myr Retriever ×2, Mox Opal | 0 | 5 | 2 | 3 | 5 | 2 | 2 |
| 1 | KCI, Trawler, Spine of Ish Sah, Mind Stone, Chromatic Star, Mox | 1 | 10 | 10 | 0 | 10 | 6 | 4 |
| 2 | KCI, Trawler, Myr, Chromatic Star ×2, Mox | 1 | 9 | 6 | 3 | 9 | 5 | 4 |
| 3 | KCI, Trawler, Myr, Chromatic Star, Mox | 1 | 7 | 7 | 0 | 8 | 5 | 3 |
| 4 | KCI, Trawler ×2, Myr, Mox | 0 | 10 | 5 | 5 | 10 | 4 | 4 |
| 5 | KCI, Trawler ×2, Spine, Ichor Wellspring, Mox ×2 | 2 | 13 | 9 | 4 | 13 | 8 | 5 |
| 6 | KCI, Trawler, Myr, Chromatic Sphere ×2, Mox | 0 | 9 | 6 | 3 | 9 | 4 | 4 |
| 7 | KCI, Trawler, Myr, Pyrite Spellbomb, Mox | 0 | 7 | 7 | 0 | 9 | 4 | 4 |

## Key insight (analysis of the 2023 code)
`perform_n_iterations` **multiplies** each counter by `n`, so the state after n iterations is `vec[s] × n`. Nothing is
simulated step by step, so the cost does not depend on n. The linearity makes the old key generation invertible; the redesign replaces it with nonlinear rounds ([[KCI-Primitive-Design]] R3). The action sequences are kept as the "flavour" of the round schedules.
The action functions can be kept as documentation, or as a unit test that rebuilds the table from the action list.

All `nmp ≥ 0`, so no negative numbers appear in the loop state.

## MtG-accuracy notes (owner to confirm; does not affect the port)
- Loop 6 comment says Chromatic **Sphere** but uses `sac_artifact(..., does_draw=False)`. Sphere does draw when activated, but here it is sacrificed to KCI rather than activated. Probably intentional.
- Loop 3 sacrifices KCI to itself (`# Sac KCI`) and recasts it for 4. Worth checking that this is legal.
