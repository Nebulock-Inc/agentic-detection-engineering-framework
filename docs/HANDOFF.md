# ADEF Feature-Branch Handoff — `feature/adef-v1-design`

**Living pointer doc.** Where the branch stands, how to run it, and what's next.
Keep it short — historical session logs are archived, not accumulated here.

- **What actually works:** `docs/STATUS.md`
- **Why decisions were made (system of record):** `ISA.md` (`## Decisions` / `## Verification`)
- **Command reference:** `docs/cli-reference.md` (per-command; `CLAUDE.md` = project/dev instructions)
- **Skills ↔ commands map:** `docs/skills-reference.md` (which skill fronts which command)
- **Hands-on walkthrough:** `docs/quickstart.md`
- **Prior session logs:** `docs/archive/` (the full pre-2026-07-22 HANDOFF + dated session docs)

**Last updated:** 2026-07-23.

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
| Claude plugin (`claude-plugin/`) | shared | shipped (7 skills + profile-author agent) |

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
   CLI, north-star labeled not-yet-built). **PyPI pipeline shipped 2026-07-23**
   (`ab3bf80`): `.github/workflows/publish.yml` (Release-triggered build + upload,
   ATHF-style token auth) + `docs/publishing.md` runbook; package **verified on
   Test PyPI** (builds, uploads, installs from index, CLI runs). Remaining before
   the real PyPI push: (a) `[project.urls]` point at the INTERNAL repo → 404 for
   the public — apply public-safe URLs or flip the repo public; (b) confirm
   `examples/` + the plugin are the launch story. Real push is on hold until v1
   is further along. Full runbook: `docs/publishing.md`.
   **Pre-release polish push (2026-07-23, feature-freeze):** CLI hardening
   (filter validation, clean errors, `schema list`, `init` env-var precedence,
   `catalog --force` warning) + canonical `docs/cli-reference.md` + a
   `catalog-sync` skill / `schema-declaration` trigger rewrite /
   `docs/skills-reference.md` all landed. README reshape **proposed**
   (`docs/plans/2026-07-23-readme-reshape-proposal.md`); README rework + broad
   E2E remain. Full detail: ISA Decisions 2026-07-23.

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
- **Authoring write seam.** Skills finishing an authored draft must hand-edit
  the record YAML (`query:`) and journal Find section — no CLI/MCP write path
  exists, and the first live run (D-1470) forgot to bump `updated:`. Candidate:
  `adef detection set-query D-XXXX` + a journal Find-seed seam (or MCP tools).
  Skill carries interim guidance (edit-is-OK for `origin: authored` + bump
  `updated:`) as of 2026-07-23.
- Plugin skills wave 2: `journal-backfill`, `forge-stage`, `coverage-gaps`.
  Live evidence for `forge-stage` (2026-07-23, D-1470 Observe): with no skill
  governing the stage, the agent drafted an excellent 8-query baseline
  methodology — and wrote it to `/tmp`. Workspace AGENTS.md now prescribes
  `analysis/<D-XXXX>/` + a journal pointer note; the skill should encode the
  same.
- ✅ *(shipped 2026-07-23)* `adef schema list` (browse declared sources) and
  `adef detection search` (BM25 CLI over journals + records). (Per-detection
  validation shipped 2026-07-23 as `schema check --detection D-XXXX` — a scope
  flag, not a separate command; a distinct `schema validate` verb was rejected
  as check-duplication. CLI-design positions on this + sync namespacing are in
  the 2026-07-23 Slack thread with Josh.)
- Deploy-prep flow for SIEM-stored teams (prepare-don't-push + drift on export).
- Shape-literal extractors beyond SPL `sourcetype=` (CQL `#event_simpleName`,
  Elastic `event.dataset`) — upgrades a platform from union- to exact-matching
  in `schema check`.
- ✅ *(fixed 2026-07-23)* `schema check` flags stats-derived output fields
  (`count` from `| stats count by ...`) as missing-from-schema — the SPL
  extractor now subtracts aggregation outputs (`count`, `... as total`).
- ✅ *(fixed 2026-07-23)* **Coverage trust tier vs metadata gaps.** `no_platform`
  zeroed out solid coverage on mass-flagged corpora (ESCU: 0/308 solid → 219/308
  after the fix). Trust now keys on integrity reasons only
  (`malformed`/`external_logic`/`invalid_mitre`). **Jarrett: semantic change in
  your coverage component — see ISA Decisions 2026-07-23.**
- ✅ *(fixed 2026-07-23)* **Sigma field validation in `schema check`.** The
  extractor map now includes `sigma` (`extract_sigma_fields` in
  `rule_parser.py`): fields are the `detection:` block's search-identifier map
  keys, stripped of `|modifiers`; `condition` (logic over identifier names)
  and pure keyword lists contribute none. A Sigma rule matches a schema by its
  logsource category (its `data_source`). The largest public rule format now
  gets field validation — previously skipped. No declaration-format change.
- **v2 pair sequencing (per-alias values / namespace preference / data-model
  schemas):** next step is a design doc for sign-off, not code — it changes
  the declaration format (a shared surface). Reasoning in the 2026-07-23
  session discussion; sketches in roadmap v0.2.0.
