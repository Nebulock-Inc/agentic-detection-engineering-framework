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
  `mypy adef/`). Currently green: 257 passed, ruff + mypy clean.

## Who's building what

| Area | Owner | Status |
|------|-------|--------|
| Schema (`adef schema *`) — declaration-driven | Eric | shipped: ingest/lint/check/show/recipe/reshape |
| Cataloging (`adef catalog`) + profiles | Jarrett | shipped |
| Browse (`adef detection list/show`) | Jarrett | shipped |
| Coverage epic (attack layer / mitre-tagger / coverage report + gaps) | Jarrett | shipped |
| Authoring (`detection new --source` + detection-author skill) | Jarrett | shipped |
| Claude plugin (`claude-plugin/`) | shared | shipped (4 skills + profile-author agent) |

**Shared seam — coordinate before changing:** `adef/core/rule_discovery.py`, the
catalog record shape (`adef/core/catalog.py`), or the schema YAML shape — each is
consumed across both people's features.

## Open threads (roadmap)

1. **`adef sync` design doc** — the biggest unaddressed trust risk: stale
   catalogs. Designed verbally: identity cascade (rule UUID → content hash →
   path → fuzzy), git-SHA diffing with rename detection, staleness-aware reads
   (CLI + MCP annotate or auto-resync), auto-journaling of out-of-band edits
   with harvested commit messages. Now more pressing: authored records +
   MITRE-tag enrichment live in the catalog a re-catalog would clobber. Write
   the doc before v0.1.0; implementation can follow.
2. **Repo write-back for authored rules** — authored rules land in the ADEF
   catalog only; getting them into the user's repo is deferred (PR / branch /
   emit-and-copy options weighed in `ISA.md`).
3. **Benchmark corpus in CI** — recognition/extraction rates per public repo
   (SigmaHQ, security_content, panther-analysis, Sentinel, elastic) as tracked
   numbers — the objective merge gate for community profiles.
4. **v0.1.0 release framing** — gap to releasable is small: a README pass +
   confirming `examples/` + the plugin are the launch story.

### Standing follow-ups (tracked, not scheduled)
- Plugin skills wave 2: `journal-backfill`, `forge-stage`, `coverage-gaps`.
- `schema list` + per-detection `schema validate`; `detection search`.
- Deploy-prep flow for SIEM-stored teams (prepare-don't-push + drift on export).
- Shape-literal extractors beyond SPL `sourcetype=` (CQL `#event_simpleName`,
  Elastic `event.dataset`) — upgrades a platform from union- to exact-matching
  in `schema check`.
