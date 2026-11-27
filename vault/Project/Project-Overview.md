# Project Overview

Back to [[00-Index]]

## What it is
A passion project combining **Magic: The Gathering** and **cryptography**. The "Snider-KCI Cipher" derives key material
by modelling *n* iterations of infinite combos built around the card **Krark-Clan Ironworks (KCI)**, a sacrifice-for-mana
engine. Each combo ("loop") produces counters (cards drawn, mana produced/spent, game actions, triggers, spells cast).
A key picks which loop runs, how many iterations happen, and which counters go into a polynomial. The polynomial's
output is the generated key.

From the README: the aim is "a working, fast and secure cipher by using 'n' iterations of infinite loops".

## Two implementations exist
| | [[v1-GUI-Block-Cipher]] | [[v2-Lite-Stream-Cipher]] |
|---|---|---|
| File | `snider_kci_cipher.py` (641 lines) | `kci_cipher_v2_lite.py` (418 lines) |
| UI | Tkinter GUI | Script with hard-coded demo |
| Key input | Any string → SHA-256 → 64/128/256 bits | 64-bit integer |
| Keystream | SHA-256 of generated key, repeated per block | Chained 16-byte blocks, no hash |
| Mode | XOR "ECB" with PKCS#7 padding | XOR stream, truncated to message |
| Deps | `numpy`, `hashlib`, `tkinter` | `numpy` only in commented-out benchmark |

Both share the same [[KCI-Loop-Model]] code (copy-pasted, not shared).

## Why C (and why a redesign)
Owner goal: **full refactor to C to get the most performance out of it**. v2's last commit message says it "needs refining for
computation speed on less powerful devices". See [[Performance-Notes]]: the loop simulation is already O(1), so most
of the speed-up will come from replacing Python big-int and byte handling with fixed-width arithmetic. On 2026-11-27 the owner chose to **redesign** the cipher as a new original KCI primitive ([[Decisions-Log]] D-007, D-009), so the C version will not match the Python output.

## Owner
GitHub `snider967`. Python 3.11 per PyCharm config (`.idea/misc.xml`).
