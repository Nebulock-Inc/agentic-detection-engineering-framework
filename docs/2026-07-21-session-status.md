# Session Status — end of 2026-07-21

**Branch:** `feature/adef-v1-design` — all work committed; push any remaining
local commits from a terminal (`git push origin feature/adef-v1-design`;
pushes fail from the Cowork sandbox by design).
**Roadmap:** `docs/2026-07-21-next-steps.md` (items 1–3 done; branch mergeable).
**Decisions:** all in `ISA.md ## Decisions` (2026-07-20 and 2026-07-21
entries), co-worker signed off.

## What works right now (all sandbox-verified end to end)

- **Catalog** any rules repo read-only: built-ins (Sigma, ESCU, Panther,
  SPL conf, raw sql/kql/cql) + **extraction profiles** for in-house formats
  (draft → `--profile` scoreboard → install to `config/profiles/`).
  Unclaimed files nudge the user into the profile loop on every path.
- **Browse**: `adef detection list` (filters + `--report json`) / `show`
  (record + query + journal history).
- **Schemas**: declaration-driven (`adef-sources.yml`) with `scope` for
  many-shapes-per-container, `declared|corrected` provenance, drift on
  re-ingest; `schema check` cross-references rule field usage
  (most-specific-match, union on ties). **NEW:** `adef schema recipe
  <platform>` generates SIEM-specific field extraction recipes (7 platforms:
  Splunk, Sentinel, Elastic, Chronicle, Sumo, QRadar, Other) with command,
  export instructions, and reshaping scripts.
- **Review triage**: `review_reasons` (structural vs `no_mitre` enrichment
  queue); platform auto-inherited from declared schemas at catalog time.
- **MITRE tagging**: `adef detection tag-mitre` writes attack.* tags via LLM
  inference; `mitre-tagger` skill orchestrates batch workflows. `adef attack
  show` displays technique details; `adef coverage` generates ATT&CK
  Navigator layers with quality scoring.
- **Claude plugin** (`claude-plugin/`, repo = marketplace): catalog-onboarding
  skill + profile-author sub-agent + mitre-tagger skill + **schema-declaration
  skill**. **Inactive until installed** — quickstart step 5b has the
  local-path install.
- **Workspace AGENTS.md**: `adef init` scaffolds an operator briefing for AI
  assistants (drive-not-describe workflows); `--force` refreshes. **NEW:**
  `adef init --interactive` prompts for SIEM platform preferences.
- **Examples**: `examples/` = demo rules + thrunt declaration (from a real
  Splunk export) + fake in-house format with its profile — the quickstart
  runs against these, every command sandbox-executed verbatim.

## The one blocker — CLEARED 2026-07-21

**Local quality gates run to green** in a real dev env (Python 3.13.9,
ruff 0.15.21, mypy 2.3.0): `pytest` **165 passed / 2 skipped**,
`ruff check adef/` clean, `mypy adef/` clean (fixed 14 errors incl. two real
bugs — a crashing `init_tools` import of a since-refactored constant, and a
loop-variable shadow in `schema check`). Fixes are typing/wiring only; suite
unchanged pre/post. Evidence in ISA `## Verification` ("Local quality gates"
entry). **Branch is mergeable.**

## Next up after that (see next-steps doc for detail)

Coverage epic in order: ATT&CK reference layer (build-time snapshot via
`mitreattack-python`, never a runtime dep) → `mitre-tagger` skill →
coverage report + Navigator export. Then `declaration-author` skill,
check-report union collapse, `adef sync` design doc.

## Field-testing notes (Eric)

Two real stumbles, both fixed same-day and regression-protected: PyPI install
documented before the package existed (→ quickstart rewrite), and the
profile loop not self-starting on 138 unclaimed in-house rules (→ CLI nudge,
profile guide, AGENTS.md loop instructions, plugin-install docs). His next
run should exercise the catalog-onboarding skill with the plugin installed —
grab that transcript.
