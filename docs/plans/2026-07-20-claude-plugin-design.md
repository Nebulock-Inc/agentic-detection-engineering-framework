# ADEF Claude Plugin — Skills, Sub-Agents, Profiles

**Date:** 2026-07-20
**Status:** Proposed (plugin files drafted alongside this doc for review)
**Depends on:** `docs/plans/2026-07-17-format-detection-plan.md` (recognizer registry) and the **profile engine** (new, specified here — not yet built)
**Touches:** new `claude-plugin/` tree, repo-root `.claude-plugin/marketplace.json`, later `adef/commands/catalog.py` (`--profile`, dry-run stats) and `adef init --claude`

---

## Why

The catalog's long-tail format problem (in-house YAML wrappers, vendor
packagings we haven't seen) cannot be closed with hand-written Python
recognizers. The fix is two-part:

1. **Declarative extraction profiles** — a rule format becomes a YAML file
   (signature + field map), executed by one generic engine in
   `rule_discovery`. New formats are data, not code.
2. **Agentic profile authoring** — when `adef catalog` hits files no profile
   claims, an agent inspects samples, drafts a profile, the deterministic
   engine validates it, and a human approves it. One inference; repeatable
   extraction forever.

Part 2 is what the plugin ships. It is the flagship of a broader division of
labor:

| Layer | Owns | Examples |
|---|---|---|
| CLI / MCP tools | Anything deterministic & repeatable | walk, profile engine, INDEX rebuild, journal writes |
| Skills | Methodology — how to think through a task | catalog onboarding flow, FORGE stage guidance (later) |
| Sub-agents | Context-heavy grunt work returning a small artifact | read 50 sample rules → return one profile YAML + stats |

Rule that keeps it clean: **skills never reimplement what a CLI command does.**
They orchestrate `adef` commands and MCP tools and add judgment between them.

## What ships (v1)

```
claude-plugin/
  .claude-plugin/plugin.json        # plugin manifest
  .mcp.json                         # wires up adef-mcp on install
  skills/
    catalog-onboarding/SKILL.md     # flagship skill
  agents/
    profile-author.md               # profile-drafting sub-agent
.claude-plugin/marketplace.json     # repo root — the ADEF repo doubles as a marketplace
```

Install: `/plugin marketplace add Nebulock-Inc/agentic-detection-engineering-framework`
then `/plugin install adef`. One command wires skills + agent + MCP server —
which matters most for the less-mature teams we most want to reach.

Deferred skills (agreed 2026-07-20, ship after the flagship proves the shape):
`journal-backfill`, `forge-stage` (rendered from `adef/data/prompts/` — single
source of truth, never a hand-maintained second copy of the methodology),
`coverage-gaps`.

## Profile schema v1

The contract between the skill, the sub-agent, and the engine. Profiles live
in `<workspace>/config/profiles/*.yml` (user/agent-authored, reviewable,
committable) and — later — `adef/data/profiles/` for built-ins migrated from
today's hand-coded recognizers.

```yaml
# <workspace>/config/profiles/acme-custom.yml
name: acme-custom          # unique; filename stem by convention
version: 1                 # profile schema version
signature:                 # how the engine recognizes a file as this format
  container: yaml          # yaml | json | toml | conf | raw
  all_keys: [alert, query] # top-level keys that must ALL be present
  any_keys: []             # at least one must be present (optional)
  none_keys: [pack_id]     # excludes near-misses (packs, stories)
  extension: [.yml, .yaml] # hint only — narrows candidates, never decides
query_language: spl        # spl | kql | cql | sql | none
map:                       # dot-paths into the parsed container
  title: alert.name
  query: alert.query
  mitre: alert.tags        # normalised downstream by _normalise_mitre
  uuid: alert.id
  data_source: alert.index
  severity: alert.severity # optional
platform:                  # one of:
  path: alert.os           #   read from the document, or
  # const: windows         #   constant for single-platform repos
```

Engine semantics (implementation in `rule_discovery`, later phase):

- **Recognition** = container parses + `all_keys`/`any_keys`/`none_keys`
  satisfied. Extension only orders candidates — consistent with decision 4 of
  the format-detection plan (general-shape-first).
- **Container parse returns a list of documents.** Most containers yield one
  document per file; `conf` (one per stanza, header exposed as `_stanza`),
  ndjson, and ARM-style JSON exports yield many. v1 implements
  single-document yaml/json only, but the contract is multi-doc from day one
  so adding those containers is not a breaking schema change.
- User profiles are checked **before** built-ins, so an org can override how
  its own wrapper format is read.
- Existing recognizers (`sigma`, `splunk-escu`, `panther`, `spl-conf`)
  translate one-for-one into built-in profiles over time; `DiscoveredRule`
  stays the normalized target, so nothing downstream changes.
- This resolves the three conflated axes: `signature.container` (packaging),
  the profile itself (metadata dialect), `query_language` (query language).
  `engine` folding and the four-engine CI guard are untouched.

## CLI seams the skill depends on (to build)

1. `adef catalog <root> --dry-run --report json` — machine-readable outcome
   report: per-file `{path, outcome: supported|recognized_unsupported|
   unclaimed, format, missing_fields}` plus aggregate counts. (Today's
   dry-run prints human text only; `unclaimed` = would-be NOT_A_RULE files
   that still look rule-shaped, i.e. have a plausible query/logic field.)
2. `adef catalog <root> --dry-run --profile <file.yml>` — same report with the
   candidate profile loaded, plus per-field extraction rates
   (`title: 98%, query: 100%, mitre: 61%`). This is the validation loop's
   scoreboard.
3. `adef profile lint <file.yml>` — schema-validate a profile (cheap,
   also used by CI on contributed profiles).

Until these land, the skill's validation step degrades gracefully (see
SKILL.md "Before the profile engine lands").

## The catalog-onboarding flow

```
adef catalog --dry-run --report json
        │
        ├─ everything recognized → report, offer full run, done
        │
        └─ unclaimed / recognized_unsupported files
                │  cluster by structure (extension, container, top-level key sets)
                │  per cluster:
                ▼
        profile-author sub-agent (isolated context)
                │  reads ≤50 samples, drafts profile YAML, self-checks
                ▼
        adef catalog --dry-run --profile draft.yml   ← deterministic scoreboard
                │  rates poor → revise (≤3 iterations)
                ▼
        human approves (AskUserQuestion, profile shown)
                │  save <workspace>/config/profiles/<name>.yml
                ▼
        real `adef catalog` run → summary (counts by platform/format,
        needs_review, unclaimed remainder)
```

Design points:

- **Context isolation is the point of the sub-agent.** Reading dozens of rule
  files would trash the main conversation; the sub-agent returns ~1 profile +
  stats.
- **Draft → score → revise** is what makes agent-written profiles
  trustworthy: the agent never grades its own work; the engine does.
- **Human approval is a hard gate.** A profile changes how every future
  catalog/sync run reads the repo. Never silently installed.
- **Community contribution shifts** from "write a Python extractor, open a
  PR" to "here's the profile YAML my agent drafted for QRadar exports" — the
  benchmark corpus (separate effort) becomes the objective merge gate.

## `adef init --claude` (secondary path, later phase)

For teams not using plugin marketplaces (or on Cursor/Copilot where MCP is the
only surface):

- `adef init --claude` copies `claude-plugin/skills/` and
  `claude-plugin/agents/` (packaged as `adef.data` package-data) into the
  target project's `.claude/`, and writes/merges a `.mcp.json` entry for
  `adef-mcp`.
- MCP remains the portable layer; skills/sub-agents are the Claude-native
  enhancement, never a requirement.
- Non-interactive, consistent with decision 3 of the format-detection plan.

## Anti-goal check

- No vendor connectors: profiles parse *files*; no APIs, no credentials.
- Read-only on source repos: unchanged; profiles only affect how ADEF reads.
- No new engine types: `query_language` is the source-format axis; folding to
  the four engines is untouched.
- No web UI: skills/agents are markdown; the plugin adds no dependencies.

## ISA entries to record on acceptance

- **Decision:** rule-format support is delivered as declarative extraction
  profiles executed by one generic engine; hand-coded recognizers migrate to
  built-in profiles; user profiles override built-ins.
- **Decision:** agent-drafted profiles are validated by the deterministic
  engine and gated on human approval before install.
- **Decision:** ADEF ships a Claude plugin (`claude-plugin/`, repo doubles as
  marketplace); skills orchestrate CLI/MCP, never reimplement it; the FORGE
  stage prompts remain the single source for any future forge-stage skill.

## Resolutions (accepted 2026-07-20; co-worker signed off 2026-07-21)

1. **Path syntax: dot-paths + `[]` array iteration only. No JSONPath.**
   Profiles must be human-reviewable — the approval gate is only meaningful
   if a reviewer can verify `alert.tags[]` against a sample in seconds, which
   filter/wildcard expressions defeat. Every observed format (ESCU, Panther,
   Sentinel YAML, in-house wrappers) is shallow. The schema is versioned;
   if the benchmark corpus surfaces a format that needs more, that is a v2
   extension backed by evidence.
2. **Conf semantics: contract now, implementation later.** Generalized into
   the multi-document container contract above (conf stanzas, ndjson, ARM
   `resources[]` are all the same shape). `spl-conf` stays hand-coded until
   the multi-doc path is built; Sigma/ESCU/Panther/custom-YAML cover the
   volume for v1.
3. **Sample cap lives in the agent definition; selection lives in the
   skill.** The cap (50) is the agent's defense of its own context budget —
   an invariant regardless of caller. The skill owns which files to pass
   because only it sees the cluster; it may pass fewer, never more. The
   holdout ratio (~20%) lives with the cap in the agent, as part of the same
   self-check mechanic. (Current SKILL.md / profile-author.md already
   reflect this split.)
