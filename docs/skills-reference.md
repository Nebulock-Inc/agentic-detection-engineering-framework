# ADEF Skills Reference — skills ↔ CLI commands

**What this is.** The map between the ADEF Claude-plugin **skills** and the CLI
**commands** they drive. Read it to see which skill covers a task, what each skill
runs under the hood, and — in reverse — which skill fronts a given command.

- Command flags and behavior: **`docs/cli-reference.md`** (canonical).
- What's actually shipped: the **[README](../README.md)**.
- Per-skill activation tests: each skill's **`EVALS.md`**.

## How skills relate to the CLI

Skills are thin **orchestration + judgment** layers over the shipped CLI and the
`adef-mcp` tools. A skill decides *when* and *why* to run a command and interprets
the result; it **never reimplements** catalog, schema, or reconcile logic. The same
guarantees hold whether you type the command or a skill runs it: read-only over the
rules repo, enrichment preserved, four engines only.

Skills ship in `claude-plugin/skills/` and are **inactive until `/plugin install`**
(then `/reload-plugins`). Without the plugin, run the commands directly.

## Skills at a glance

| Skill | Use it for | Primary CLI commands | Hands off to |
|-------|-----------|----------------------|--------------|
| **catalog-onboarding** | First-time cataloging of a rules repo | `adef catalog` (`--dry-run`/`--report json`/`--profile`), `adef profile lint` | catalog-sync, detection-explorer, schema-declaration |
| **catalog-sync** | Reconcile the catalog after the repo changes | `adef sync` (`--dry-run`/`--check`) | catalog-onboarding, detection-explorer, mitre-tagger |
| **detection-explorer** | Find/inspect catalogued detections | `adef detection list`, `adef detection show`, `adef attack show` | coverage-review, mitre-tagger, catalog-sync |
| **coverage-review** | Read coverage *quality* + gaps, Navigator export | `adef coverage` (`--gaps`/`--navigator`), `adef detection list` | mitre-tagger, detection-explorer |
| **mitre-tagger** | Drain the `no_mitre` queue with validated ATT&CK IDs | `adef detection list --needs-review no_mitre`, `adef detection tag-mitre`, `adef attack show` | coverage-review, detection-explorer |
| **detection-author** | Author a new schema-grounded rule through Find/Observe | `adef detection new --source`, `adef detection observe`, `adef schema check --detection`, `adef schema show`, `adef detection tag-mitre` | schema-declaration, mitre-tagger |
| **schema-declaration** | Build/refresh data-source schema declarations | `adef schema recipe` → `reshape` → `ingest`, `adef schema check`/`show` | catalog-onboarding, detection-author |
| **forge-stage** | Drive Observe/Refine/Govern/Evolve with the workspace conventions (artifacts in `analysis/`, one summary per stage, honest status claims) | `adef detection observe/refine/govern/evolve` (`--note`/`--chain`), `adef schema check --detection`, `adef detection tag-mitre --remove`, `adef reindex` | detection-author, mitre-tagger, coverage-review |

**Sub-agent:** `profile-author` (not a skill) drafts an extraction profile for an
in-house rule format; validated with `adef profile lint`, consumed by
`adef catalog --profile`.

## MCP-tool equivalents

In an MCP session (`adef-mcp`), schema-declaration prefers the tools over shelling
out: `schema_list_platforms`, `schema_recipe`, `schema_reshape`,
`schema_lint_declaration`, `schema_ingest`. These mirror the `adef schema *`
commands; the CLI reference documents the underlying behavior.

## Reverse map — which skill fronts each command

| CLI command | Skill(s) | Notes |
|-------------|----------|-------|
| `adef init` | — | `--interactive` offers to chain into `install-skills` |
| `adef install-skills` | — | activates the skills below |
| `adef catalog` | **catalog-onboarding** | detection-explorer / schema-declaration reference it |
| `adef profile lint` | **catalog-onboarding** | pairs with the `profile-author` sub-agent |
| `adef sync` | **catalog-sync** | the reconciling re-run (never re-`catalog`) |
| `adef detection new` | **detection-author** | `--source` grounds the draft in a schema |
| `adef detection observe` | **forge-stage**, detection-author | baselining + hypothesis validation |
| `adef detection refine/govern/evolve` | **forge-stage** | gates, deployment decision, tune/deprecate |
| `adef reindex` | **forge-stage** | the only safe INDEX rebuild |
| `adef detection list` | **detection-explorer**, coverage-review, mitre-tagger, detection-author | shared browse verb |
| `adef detection show` | **detection-explorer** | record + query + tactics + journal tail |
| `adef detection tag-mitre` | **mitre-tagger**, detection-author | validated against the ATT&CK reference |
| `adef schema recipe/reshape/ingest/show` | **schema-declaration** | declaration-driven setup + refresh |
| `adef schema check` | **detection-author** (`--detection`), schema-declaration | field-vs-rule cross-reference |
| `adef coverage` | **coverage-review** | quality tiers + `--gaps`/`--navigator` |
| `adef attack show/info/refresh` | **detection-explorer**, mitre-tagger | ATT&CK reference lookups |
| `adef hunt-promote` | — | no skill yet |
| `adef backfill journals` | — | `journal-backfill` deferred (wave 2) |

## Not yet skilled (roadmap)

`journal-backfill` and `coverage-gaps` are planned for a second skills wave —
post-release. (`forge-stage` shipped 2026-07-24, built from three live D-1470
stage-session transcripts.) Until then, drive those commands directly per
`docs/cli-reference.md`.
