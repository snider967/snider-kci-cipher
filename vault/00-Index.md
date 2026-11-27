# Snider-KCI Cipher — Vault Index

> Knowledge base for the **Python → C refactor** of `snider-kci-cipher`.
> Obsidian-compatible (double-bracket wikilinks). Keep this index current whenever a note is added/renamed.

**Status:** Phase 2 in progress: spec **v0.3** implemented with an **AVX2 path** (3 GB/s raw stream, ~10× portable); library + CLI pass 1336 + 69 checks. Next: faster Poly1305, cross-target builds, first PR.
**Branch:** `c-refactor` (PRs into `main`, see D-011)
**Last updated:** 2026-11-27 (Session 02)
**Upstream:** https://github.com/snider967/snider-kci-cipher (branch `main`, HEAD `2a837a4`)

## Start here
- [[Project-Overview]] — what the project is and why we are refactoring
- [[Goals-and-Scope]] — refactor goals, non-goals, success criteria
- [[Open-Questions]] — **unanswered questions for the owner**
- [[Decisions-Log]] — every decision, with rationale (ADR-lite)
- Latest handoff → [[2026-11-27-Session-02]]

## Codebase (current Python)
- [[Repository-Map]] — files, history, dependencies
- [[KCI-Loop-Model]] — the MtG combo model that drives key generation
- [[v1-GUI-Block-Cipher]] — `legacy/python/snider_kci_cipher.py` (Tkinter, SHA-256, XOR/ECB)
- [[v2-Lite-Stream-Cipher]] — `legacy/python/kci_cipher_v2_lite.py` (chained keystream)
- [[Known-Issues-and-Quirks]] — bugs and behaviour the port must decide on
- [[Cryptanalysis-Notes]] — security observations

## Refactor (C), a redesign rather than a 1:1 port (D-007)
- [[KCI-Primitive-Design]] — **KCI-20 spec v0.3 (accepted)**
- [[C-Architecture-Plan]] — proposed layout, API, build
- [[Porting-Map]] — Python function → C function mapping & status
- [[Test-Vector-Strategy]] — how we prove the C port matches
- [[Performance-Notes]] — where time actually goes, optimisation plan

## Process
- [[Workflow]] — handoff & audit rules for every session
- [[Handoff-Template]] · [[Audit-Template]]
- Sessions: [[2026-11-27-Session-01]] · [[2026-11-27-Session-02]] · Audit: [[2026-11-27-Session-01-Audit]]
