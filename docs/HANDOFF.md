# ADEF Feature-Branch Handoff — `feature/adef-v1-design`

**Living pointer doc.** Where the branch stands, how to run it, and what's next.
Keep it short — historical session logs are archived, not accumulated here.

- **What actually works:** `docs/STATUS.md`
- **Why decisions were made (system of record):** `ISA.md` (`## Decisions` / `## Verification`)
- **Command reference:** `CLAUDE.md`
- **Hands-on walkthrough:** `docs/quickstart.md`
- **Prior session logs:** `docs/archive/` (the full pre-2026-07-22 HANDOFF + dated session docs)

**Last updated:** 2026-07-22.

---

## The environment (read this first if commands fail)

- No committed virtualenv. `.venv/` (gitignored) is built from pyenv Python
  **3.11.11** — the only interpreter with `adef` editable-installed + `pytest`.
- Run tests: `.venv/bin/python -m pytest -q`
- Run the CLI: `.venv/bin/adef ...`
- Recreate `.venv` if missing:
  `~/.pyenv/versions/3.11.11/bin/python -m venv .venv && .venv/bin/pip install -e ".[dev]"`
  (or `scripts/fresh-install.sh`).
- `sqlglot` is a real runtime dep (SQL parsing). The `.[llm]` extra and `jinja2`
  were removed 2026-07-20 — don't reference them.
- **Before pushing:** run the full gate (`pytest` / `ruff check adef/` /
  `mypy adef/`). Currently green: 309 passed / 2 skipped, ruff (adef/ + tests/)
  + mypy clean.
- Stale-metadata gotcha (bit twice on 2026-07-22): a stale repo-root
  `agentic_detection_engineering_framework.egg-info/` can mask newly-registered
  entry points (commands silently missing from `adef --help`). Fix:
  `rm -rf *.egg-info && pip install -e . --force-reinstall --no-deps` (or
  `scripts/fresh-install.sh`, dev-only tool).

## Who's building what

| Area | Owner | Status |
|------|-------|--------|
| Schema (`adef schema *`) — declaration-driven | Eric | shipped: ingest/lint/check/show/recipe/reshape |
| Cataloging (`adef catalog`) + profiles | Jarrett | shipped |
| Browse (`adef detection list/show`) | Jarrett | shipped |
| Coverage epic (attack layer / mitre-tagger / coverage report + gaps) | Jarrett | shipped |
| Authoring (`detection new --source` + detection-author skill) | Jarrett | shipped |
| Claude plugin (`claude-plugin/`) | shared | shipped (6 skills + profile-author agent) |

**Shared seam — coordinate before changing:** `adef/core/rule_discovery.py`, the
catalog record shape (`adef/core/catalog.py`), or the schema YAML shape — each is
consumed across both people's features.

## Open threads (roadmap)

1. **`adef sync`** — **core shipped** (`docs/plans/2026-07-22-adef-sync-design.md`,
   steps 1–3): identity fields persisted (`rule_uuid`/`source_hash`/`catalog_sha`),
   `reconcile()` cascade + `adef sync [--dry-run] [--check]` — refreshes changed
   rules, **preserves enrichment**, orphans deleted rules (never deletes). Closes
   the wipe-on-recatalog risk. Remaining follow-ups: fuzzy rename-match (step 4;
   UUID-less renames fall to `new` today — safe), staleness-aware reads (CLI/MCP
   "N commits behind"), richer commit-message harvest, CI action.
2. **ADEF as a detection home (repo-less teams)** — design doc:
   `docs/plans/2026-07-22-adef-as-detection-home-design.md`. Decision: ADEF
   becomes a system of record for detections *authored* in it. Steps 1–2
   **shipped 2026-07-22**: `origin: authored|catalogued` marker + sync skips
   authored records (the orphaning data bug is closed), and the git-friendly
   workspace guide (`docs/detection-home.md`). The README's "pick your
   on-ramp" section now routes repo-less teams to both. `adef export`
   (records → rule files) **deferred** — speculative + hard to do right until
   teams actually author in ADEF. Read-only invariant over the *rule repo*
   unchanged.
3. **Benchmark corpus in CI** — recognition/extraction rates per public repo
   (SigmaHQ, security_content, panther-analysis, Sentinel, elastic) as tracked
   numbers — the objective merge gate for community profiles.
4. **v0.1.0 release framing** — gap to releasable is small. The README pass
   landed 2026-07-22 (on-ramps rework, all commands verified against the live
   CLI, north-star labeled not-yet-built); remaining: confirm `examples/` + the
   plugin are the launch story.

### Standing follow-ups (tracked, not scheduled)
- **v2: per-alias values + namespace preference.** Folded fields keep only the
  canonical spelling's vocabulary → alias-spelling + harvested-value queries
  never fire and no gate catches them; canonical-by-count also can't express a
  CIM-first/raw-first team convention. Sketch in roadmap v0.2.0; evidence +
  today's mitigations in ISA Decisions 2026-07-22.
- **v2: data-model schemas.** `tstats`/datamodel rules use a third field
  namespace (`Processes.process_name`) absent from index `fieldsummary`
  exports — ~39% of ESCU's active detections. Declaring a data model as a
  source is the seam (roadmap v0.2.0 has the sketch; ISA Decisions 2026-07-22
  has the evidence).
- Plugin skills wave 2: `journal-backfill`, `forge-stage`, `coverage-gaps`.
- `schema list` + per-detection `schema validate`; `detection search`.
- Deploy-prep flow for SIEM-stored teams (prepare-don't-push + drift on export).
- Shape-literal extractors beyond SPL `sourcetype=` (CQL `#event_simpleName`,
  Elastic `event.dataset`) — upgrades a platform from union- to exact-matching
  in `schema check`.
- `schema check` flags stats-derived output fields (`count` from
  `| stats count by ...`) as missing-from-schema — correct but noise (demo
  D-0002). Teach the SPL extractor that aggregation outputs aren't event
  fields, or add them to `_CHECK_IGNORED_FIELDS`.
