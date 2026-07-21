# ADEF Next Steps — 2026-07-21

**Context:** follows `docs/2026-07-20-status-and-design-changes.md`. Since that
summary shipped: scope on declared sources + scope-aware `schema check`,
`query_language` persisted on records, `adef detection list`/`show` (story
7393), the `examples/` demo pack (rules + 14-source scoped declaration built
from a live Splunk export), the declaring-data-sources guide, and E2E fixes
(rule-root-relative `rule_ref`, data_source fallback + SQL comment stripping).

Ordered by what unblocks what.

## Immediate — makes the branch mergeable

1. ✅ *(done 2026-07-21)* **Local quality gates.** `pytest`, `ruff check adef/`,
   `mypy adef/` in a real dev environment; evidence in ISA `## Verification`.
   Result: pytest 165 passed / 2 skipped; ruff clean; mypy clean (fixed 14
   errors incl. two real bugs — a crashing `init_tools` import and a
   loop-variable shadow in `schema check`). Was "the only blocker."
2. ✅ *(done 2026-07-21)* **Co-worker sign-off** on the three implemented design decisions, per ISA
   discipline: extraction profiles + plugin (`2026-07-20-claude-plugin-design.md`),
   declarations (`2026-07-20-schema-declaration-design.md`), and its scope
   section (2026-07-21). All changed schema-shared surfaces.
3. ✅ *(shipped 2026-07-21, `5bb621c`)* **`needs_review` rework**. The demo showed 8/9 rules
   flagged → zero signal. Scope:
   - `review_reasons: [no_platform, no_mitre, malformed, external_logic]` on
     records; boolean kept for compat; `list --needs-review <reason>` triage.
   - **Platform inheritance from declarations**: a rule whose literals match a
     scoped source inherits that source's `platform` at catalog time —
     declaring data makes the catalog cleaner (kills 7/8 demo flags, moves
     records out of `multi-platform/`).
   - `no_mitre` demoted: visible in `show`/JSON, excluded from the ⚠ marker
     and headline count (it's enrichment work, not a defect).
   - **Tier-2 MITRE parity for profile rules**: fall back to the technique-ID
     text sweep (title + description + query) when the profile map yields no
     MITRE — same behavior conf rules already get. (Why the Panther scheduled
     queries came back 0% MITRE.)

## Near-term — makes the launch demo compelling

4. **The coverage epic — in this order** (decided 2026-07-21: the reference
   layer is the cheap foundation everything expensive stands on; building
   tagger/Navigator first would mean re-auditing every mapping made before
   validation existed):
   1. **ATT&CK reference layer.** Compact snapshot of the ATT&CK catalog
      (`id → name, tactics, deprecated/revoked + replacement, parent`)
      generated at build time from official STIX via `mitreattack-python`
      (dev-time tool, NOT a runtime dependency), shipped as package data;
      `adef attack refresh` pulls a newer snapshot on demand. Consumers:
      catalog-time validation (new reasons: `invalid_mitre`,
      revoked-with-replacement), true `by_tactic` resolution (INDEX renamed
      `by_technique` 2026-07-21 until then), tagger grounding.
   2. **`mitre-tagger` skill.** Drains the `no_mitre` queue: agent selects
      from the shipped snapshot (never from model memory — hallucinated IDs),
      deterministic validation confirms, human approves, enrichment written
      to *catalog records* (ADEF's layer — upstream rules stay untouched).
   3. **Coverage report + MITRE Navigator layer export.** The "first 15
      minutes" artifact — honest only once 1–2 exist; the
      screenshot-into-Slack moment for a skeptical DE lead.
   Not a v0.1.0 blocker: everything shipped today works without ATT&CK
   knowledge, and the `no_mitre` queue accumulates correctly meanwhile.
5. **`declaration-author` skill.** Performed manually twice this session
   against live Splunk exports; logic now fully specified: internals filter,
   case-dupe → aliases, enum harvesting with value-length caps, numeric/hex
   typing, and mixed-shape detection → "re-export per sourcetype" guard.
6. **`schema check` report polish.** Union-matched rules attribute a missing
   field to every matched source (`NotARealField` × 14 rows in the demo).
   Correct but noisy — collapse union findings into one row.

## Strategic — design before build

7. **`adef sync` design doc.** The biggest unaddressed trust risk: stale
   catalogs. Already designed verbally: identity cascade (rule UUID → content
   hash → path → fuzzy), git-based diffing (SHA at catalog time,
   rename detection), staleness-aware reads (CLI + MCP annotate or auto-resync),
   and auto-journaling of out-of-band edits with harvested commit messages —
   edits that bypass ADEF become history, not lost value. Write the doc before
   v0.1.0 even if implementation follows later.
8. **Benchmark corpus in CI.** Recognition/extraction rates per public repo
   (SigmaHQ, security_content, panther-analysis, Sentinel, elastic) as
   tracked numbers — the objective merge gate for community-contributed
   profiles.
9. **v0.1.0 release framing.** Gap to releasable is small: items 1–3, a
    README pass, and confirming `examples/` + the Claude plugin are part of
    the launch story (recommended — they *are* the demo). "Release and
    iterate" was the plan from day one.

## Standing follow-ups (tracked, not scheduled)

- Per-SIEM recipe docs beyond the two worked examples (Sentinel `getschema`,
  Elastic `_mapping`).
- Plugin skills wave 2: `journal-backfill`, `forge-stage` (rendered from
  `adef/data/prompts/`), `coverage-gaps`.
- `schema list` + per-detection `schema validate`; `detection search`.
- Deploy-prep flow for SIEM-stored teams (prepare-don't-push + intended-vs-
  deployed drift on next export).
- Shape-literal extractors beyond SPL `sourcetype=` (CQL `#event_simpleName`,
  Elastic `event.dataset`) — each upgrades a platform from union- to
  exact-matching in `check`.
