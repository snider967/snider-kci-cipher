# Snider-KCI Cipher — Vault Index

> Knowledge base for the **Python → C refactor** of `snider-kci-cipher`.
> Obsidian-compatible (double-bracket wikilinks). Keep this index current whenever a note is added/renamed.

**Status:** Phase 2: spec **v0.3** implemented and merged to `main` (PR #1); CI on 5 platforms (PR #2, $0 hard rule D-025). AVX2 keystream 3.1 GB/s, AEAD 1.27 GB/s; 1336 library + 69 CLI checks. Next: security analysis (spec §12).
**Branch:** work on topic branches, PRs into `main` (D-011). `c-refactor` (PR #1) and `ci-workflow` (PR #2) are merged.
**Last updated:** 2026-11-27 (Session 02)
**Upstream:** https://github.com/snider967/snider-kci-cipher (branch `main`, HEAD `f18a141`; the 2023 Python HEAD was `2a837a4`)

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
- [[Workflow]] — **hard rules ($0 cost)**, handoff & audit rules for every session
- [[Handoff-Template]] · [[Audit-Template]]
- Sessions: [[2026-11-27-Session-01]] · [[2026-11-27-Session-02]] · Audits: [[2026-11-27-Session-01-Audit]] · [[2026-11-27-Session-02-Audit]]
