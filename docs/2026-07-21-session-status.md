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

## Late-session gap-closure (2026-07-21, post-review of the recipe feature)

A review of the recipe feature (`889e7dc`) against its original plan found it
complete but untested. Closed same day:

- **`tests/test_recipes.py` (28 tests)** — recipes core, `adef schema recipe`
  CLI, and the schema MCP tools (fake-server harness). Caught a real bug:
  `--format json` emitted through rich `console.print`, which soft-wraps at
  terminal width → invalid JSON for any parser; now `click.echo` (the catalog
  convention). Full suite **219 passed / 2 skipped**; ruff + mypy clean.
- **MCP `schema_recipe` honesty fix** — unconfigured no longer silently
  defaults to splunk; returns error + supported-platform list (ISA Decisions).
- **Doc drift fixed** — `adef schema recipe` added to the workspace AGENTS.md
  template; README/quickstart/plugin.json now name all bundled skills and the
  `pip install -e ".[mcp]"` prerequisite (previously the plugin pointed at an
  `adef-mcp` command that fails on import from a base install).

## Next up (see next-steps doc for detail)

Coverage epic ✅ shipped (ATT&CK reference layer → `mitre-tagger` →
coverage report + Navigator export). Remaining: `declaration-author` skill
(§5 — the codified reshape step the `schema-declaration` skill currently
improvises), check-report union collapse (§6), `adef sync` design doc (§7),
v0.1.0 release framing (§9).

## Field-testing notes (Eric)

Two real stumbles, both fixed same-day and regression-protected: PyPI install
documented before the package existed (→ quickstart rewrite), and the
profile loop not self-starting on 138 unclaimed in-house rules (→ CLI nudge,
profile guide, AGENTS.md loop instructions, plugin-install docs). His next
run should exercise the catalog-onboarding skill with the plugin installed —
grab that transcript.
