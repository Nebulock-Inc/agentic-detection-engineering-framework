---
name: coverage-review
description: Assess MITRE ATT&CK coverage from the ADEF catalog (read-only) and turn it into a work plan. Use when the user asks how good their detection coverage is, where the gaps or blind spots are, which techniques are single points of failure or ride one log source, what to build or tune next, or wants a shareable MITRE Navigator layer. To find or inspect individual detections, use the detection-explorer skill.
---

# Coverage Review

Run `adef coverage`, interpret it, and turn it into a prioritized plan — not just
a heatmap. The value is the per-detection context (log source, review state,
depth) a plain green/red matrix throws away.

## Rules

- **Read-only.** `coverage` reads the catalog + ATT&CK reference; it writes nothing.
- **Orchestrate** `adef coverage`; never recompute coverage or parse the INDEX yourself.
- **Coverage is only as honest as the catalog's MITRE tags.** If many records are
  `no_mitre` (check `adef detection list --needs-review no_mitre`), say so —
  gaps are overstated until those are tagged — and offer the `mitre-tagger` handoff.
- Hand off: finding/inspecting one detection → `detection-explorer`; adding ATT&CK
  IDs → `mitre-tagger`.

## Flow

1. Run `adef coverage` (add `--gaps` when the user wants the specific uncovered
   technique IDs by tactic).
2. Read the report as four questions:
   - **Trust** — solid vs fragile (fragile = single detection *or* all need review; not the same green as battle-tested coverage).
   - **Gaps** — N-of-M techniques covered, per-tactic covered/total, fully-blind tactics.
   - **Concentration** — techniques riding one log source (that feed breaks → they go dark together).
   - **Fragility** — single-points-of-failure (depth-1); **fictional** coverage (mapped IDs absent from ATT&CK).
3. Prioritize into a plan: blind / thin tactics + SPOFs on techniques that matter → build;
   fragile → harden or review; fictional → fix the mapping.
4. To share, `adef coverage --navigator layer.json` → a scored Navigator v4.5 layer.

## Notes

- **Cold-catalog caveat:** freshly catalogued rules are all `draft` and often single-source,
  so a fresh catalog reads mostly fragile — honest, not a bug (status is deliberately not a tier input).
- `--workspace PATH` (default `ADEF_WORKSPACE`/cwd). Tactic names track the shipped
  ATT&CK snapshot (e.g. 19.1 "Stealth" was "Defense Evasion").
