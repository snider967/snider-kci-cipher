# Vault Workflow

Back to [[00-Index]]

## During a session
- Record every decision in [[Decisions-Log]] when it is made; move answered items out of [[Open-Questions]].
- Update [[Porting-Map]] status as functions are ported or tested.
- New findings go into the relevant note (quirks → [[Known-Issues-and-Quirks]], numbers → [[Performance-Notes]]).

## Handoffs (regularly, and at least at every milestone or before a long task)
Append a checkpoint to the current session note (`Sessions/YYYY-MM-DD-Session-NN.md`) using [[Handoff-Template]]:
state, what changed, what is next, blockers. A new session should be able to resume from the **latest handoff + [[00-Index]]** alone.

## End-of-session full audit
Create `Sessions/YYYY-MM-DD-Session-NN-Audit.md` from [[Audit-Template]]:
1. Re-read every vault note against the actual repo state (files, git log, build/test results).
2. Fix stale facts, dead wikilinks, and status mismatches.
3. Check that the index lists every note.
4. Record what was verified and what was not.

## Conventions
- Dates are absolute (YYYY-MM-DD).
- File paths are relative to the repo root.
- "Verified" means a command was actually run. Otherwise write "unverified".
