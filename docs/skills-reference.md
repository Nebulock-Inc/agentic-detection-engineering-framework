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

Skills ship inside the installed package (`adef/data/claude-plugin/skills/`, so
a `pip install` carries them, not only a clone) and are **inactive until
they're in an assistant's skills directory**. Two ways to get them there: `adef
install-skills` (the primary path — works for Claude Code *and* Codex/ChatGPT,
and puts the files in your repo so a team can commit them), or `/plugin install
adef@adef-marketplace` then `/reload-plugins` (Claude-only, but bundles the
`adef-mcp` wiring too). Without either, run the commands directly. `adef doctor`
reports which are installed.

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
| **forge-stage** | Drive Observe/Refine/Govern/Evolve with the workspace conventions (artifacts in `analysis/`, one summary per stage, honest status claims) | `adef detection observe/refine/govern/evolve` (`--note`/`--chain`), `adef schema check --detection`, `adef detection tag-mitre --remove`, `adef reindex` | health-capture, detection-author, mitre-tagger, coverage-review |
| **health-capture** | Turn real SIEM numbers into capture documents so Evolve has evidence | `adef ingest` (`--dry-run`), `adef health show` (`D-XXXX`/`--source`), `adef doctor`, `adef detection evolve --chain` | forge-stage |

**Sub-agent:** `profile-author` (not a skill) drafts an extraction profile for an
in-house rule format; validated with `adef profile lint`, consumed by
`adef catalog --profile`.

## MCP-tool equivalents

In an MCP session (`adef-mcp`), schema-declaration prefers the tools over shelling
out: `schema_list_platforms`, `schema_recipe`, `schema_reshape`,
`schema_lint_declaration`, `schema_ingest`. These mirror the `adef schema *`
commands; the CLI reference documents the underlying behavior.

health-capture does the same with `health_ingest` (which takes the document's
*path*, exactly as the CLI does, and hands back the ingest result as structured
data rather than stdout to parse) and `health_show`, and forge-stage with `refine_chain` and
`evolve_chain`. `tune_recommend` and `deprecation_recommend` read the stored
health themselves when their metrics argument is omitted. One deliberate
difference from the CLI: `refine_chain` defaults to `similarity_mode="agent"`
because an MCP caller is an agent by definition, where the CLI defaults to
`bm25`. The split is by entry point, not by environment sniffing.

## Reverse map — which skill fronts each command

| CLI command | Skill(s) | Notes |
|-------------|----------|-------|
| `adef init` | — | `--interactive` offers to chain into `install-skills` |
| `adef install-skills` | — | activates the skills below |
| `adef doctor` | **catalog-onboarding** (step 0), health-capture | one-command workspace state; each finding prints the next command where there is one |
| `adef catalog` | **catalog-onboarding** | detection-explorer / schema-declaration reference it |
| `adef profile lint` | **catalog-onboarding** | pairs with the `profile-author` sub-agent |
| `adef sync` | **catalog-sync** | the reconciling re-run (never re-`catalog`) |
| `adef detection new` | **detection-author** | `--source` grounds the draft in a schema |
| `adef detection observe` | **forge-stage**, detection-author | baselining + hypothesis validation |
| `adef detection refine/govern/evolve` | **forge-stage** | gates, deployment decision, tune/deprecate |
| `adef ingest` | **health-capture** | the five capture kinds; counts, never ratios |
| `adef health show` | **health-capture** | readback — `D-XXXX` positionally, `--source NAME` for the source-keyed kinds |
| `adef reindex` | **forge-stage** | the only safe INDEX rebuild |
| `adef detection list` | **detection-explorer**, coverage-review, mitre-tagger, detection-author | shared browse verb |
| `adef detection show` | **detection-explorer** | record + query + tactics + journal tail |
| `adef detection tag-mitre` | **mitre-tagger**, detection-author | validated against the ATT&CK reference |
| `adef schema recipe/reshape/ingest/show` | **schema-declaration** | declaration-driven setup + refresh |
| `adef schema check` | **detection-author** (`--detection`), schema-declaration | field-vs-rule cross-reference |
| `adef coverage` | **coverage-review** | quality tiers + `--gaps`/`--navigator` |
| `adef attack show/info/refresh` | **detection-explorer**, mitre-tagger | ATT&CK reference lookups |
| `adef hunt-promote` | — | no skill yet |

## Not yet skilled (roadmap)

`coverage-gaps` is planned for a second skills wave — post-release. Until then, drive those commands directly per
`docs/cli-reference.md`.
