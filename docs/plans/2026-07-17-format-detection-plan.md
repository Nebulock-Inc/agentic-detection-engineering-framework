# ADEF Format Detection — Plan

**Date:** 2026-07-17
**Status:** Proposed (for Jarrett + co-worker review before building)
**Shortcut:** Epic 6996 — refines story 7387 (Catalog) and the shared discovery layer
**Depends on / touches:** `adef/core/rule_discovery.py` (shared by catalog + schema)

---

## Why

ADEF is meant to be **format-agnostic**, but the current sniffer is effectively
**Sigma-shaped-YAML-only**. Testing `adef catalog` against three real corpora
(`test-rules/`) exposed the problem — see `docs/HANDOFF.md` "Test corpora":

| Repo | Found | Reality |
|------|-------|---------|
| splunk/security_content | 0 | Splunk ESCU YAML (`search:` + `type:`) — not Sigma |
| panther-labs/panther-analysis | 0 | Panther YAML + sibling `.py` — not Sigma |
| palantir/osquery-configuration | 2 (both false positives) | osquery `.conf`, matched a naive Splunk sniff |

The Sigma bias was never intended. **Accurate format detection is the foundation**
for everything else — you can't catalog, journal, coverage-report, or schema-scan
rules you don't recognize.

## Scope & framing (decided 2026-07-17)

- **The test repos are samples, not the spec.** They exercise the recognizer
  against real-world messiness; they do **not** define "what a rules repo looks
  like." Do not over-fit to any vendor's specific packaging (stories, packs, data
  models). A production repo can be laid out any way.
- **The job, stated plainly:** given an arbitrary rules repo, decide per file
  *"is this a detection rule?"*, and for the ones that are, capture **(a) the
  query/logic** and **(b) the detection metadata** (title, MITRE, severity, data
  source, …). Everything else (docs, config, packs, stories, data models) is
  simply *not a rule* → skip.
- **"Is it a rule?" = has a query/logic field + detection metadata.** A story or
  pack is skipped not because we special-case it, but because it has no query.
  This is more general and more robust than enumerating vendor file types.
- **Corpus scoping for testing** (these paths are where the real rules live in the
  samples — used to validate extraction, not to hardcode):
  - Splunk: `security_content/detections/` — 2,124 `.yml`, each with a `search:`
    (SPL) + metadata (`name`, `type`, `mitre_attack_id`, `data_source`). Note a
    `deprecated/` subfolder exists.
  - Panther: `panther-analysis/rules/` — 877 `.yml` with `RuleID`, `DisplayName`,
    `LogTypes`, `Reports` (MITRE), and `Filename:` → sibling `.py` (the logic).
  - osquery: **dropped** — not a good example of a detection rules repo; ignore.

## Core principles

1. **Extension is a hint, not the answer.** `.yml` may be Sigma, Splunk ESCU,
   Panther, a pack/story, or CI config. Detection is **content-signature-driven**;
   extension only narrows/orders candidates.
2. **Recognize all, parse incrementally.** Detect the *format* for every rule so
   coverage is honest; fully extract metadata only for formats we've implemented.
   A recognized-but-unsupported rule is catalogued with its `format` +
   `needs_review`, never silently dropped.
3. **Three outcomes, not two.** Every file resolves to one of:
   `supported` (recognized + parsed) · `recognized_unsupported` (format known,
   extractor pending) · `not_a_rule` (config, docs, pack, story, CI). The catalog
   must be able to *report* the middle bucket — that's the honesty fix.
4. **One shared module.** Recognizers live in `rule_discovery`, consumed by both
   catalog and schema. No divergence.

## Design

### Recognizer registry

A priority-ordered list of small, pure recognizer functions. Each takes
`(filename, text, parsed_yaml_or_none)` and returns a `format` string or `None`.
Content signature decides; extension only gates which recognizers run.

```
RECOGNIZERS = [
    recognize_sigma,        # yaml: has detection: AND logsource:
    recognize_splunk_escu,  # yaml: has search: AND type: (mitre_attack_id/datamodel)
    recognize_panther,      # yaml: AnalysisType (!= pack) AND RuleID
    recognize_elastic,      # toml/json: query + rule.* (future)
    recognize_spl_conf,     # conf: [stanza] with real `search =` (tighten vs osquery)
    recognize_raw_sql,      # .sql content that parses as SQL
    recognize_raw_kql,      # .kql / KQL-shaped
    recognize_raw_cql,      # .cql
]
```

Signatures confirmed from the corpora:

| Format | Positive signature | Excludes |
|--------|--------------------|----------|
| sigma | `detection:` + `logsource:` | — |
| splunk-escu | `search:` + `type:` (+ `mitre_attack_id`/`datamodel`) | ESCU **story** (no `search:`/`type:`) |
| panther | `AnalysisType:` + `RuleID:` | Panther **pack** (`AnalysisType: pack`, `PackID:`) |
| osquery-conf | `.conf`/JSON with `schedule`/`packs`/`options` | **not** a rule → `not_a_rule` |
| spl-conf | `.conf` stanza with `search =` AND Splunk markers | osquery `.conf` |

### DiscoveredRule changes

- `format` becomes the full recognized set (add `splunk-escu`, `panther`, …).
- Add `support: "supported" | "recognized_unsupported" | ...` (or reuse
  `needs_review` + a new `recognized` bool — decide in build).
- `query_text` may be **empty or in a sibling file** (Panther `.py`); record the
  logic location, don't assume it's inline. Affects `rule_ref` and schema scan.

### engine / format / query_language

Unchanged separation (ISA 2026-07-15): `engine` stays the internal 4-set;
`format` carries the true source; `query_language` drives schema field extraction.
New formats map: splunk-escu → language `spl`; panther → language depends on
`LogTypes`/the `.py` (likely no query-language extraction v1 → recognized_unsupported
for schema).

## Phased build (all TDD, against `test-rules/` corpora)

**Phase 1 — Recognizer framework + honest outcomes.**
Refactor `sniff_format` into the registry; add the three-outcome model; make
`discover_rules` yield recognized-unsupported rules instead of dropping them.
Tighten `.conf` so osquery configs resolve to `not_a_rule`. *Exit:* osquery
false positives gone; framework in place. Sigma/SQL/KQL/SPL still parse as today.

**Phase 2 — Splunk ESCU (highest-volume real corpus).**
Recognizer + metadata extractor: title (`name`), MITRE (`mitre_attack_id`),
query (`search:` → SPL, feeds schema), data_source (`datamodel`/`data_source`),
platform (heuristic). *Exit:* `adef catalog test-rules/security_content` catalogs
thousands, not zero; schema-from-catalog produces SPL schemas from them.

**Phase 3 — Panther.**
Recognizer + metadata extractor from the `.yml` (`DisplayName`, `Reports`→MITRE,
`LogTypes`→data_source). Logic lives in the sibling `.py` (`Filename:`) — record
its path; decide whether v1 extracts fields from Python (likely defer →
recognized_unsupported for schema, supported for catalog). *Exit:*
`adef catalog test-rules/panther-analysis` catalogs the rules with correct
metadata.

**Phase 4 (optional/after) — Elastic + others** as corpora demand.

## Test strategy

- Unit: one signature test per recognizer (positive + the near-miss it must
  exclude — e.g. a Splunk story/pack, which has no query, must resolve to
  *not a rule*).
- Corpus smoke: run `discover_rules` over a small vendored slice and assert counts
  by outcome (guards against regressions and silent drops).

## Decisions (2026-07-17)

1. **Panther `.py` field extraction — DEFER.** A Panther rule has metadata → it
   *is* a rule and gets catalogued from its `.yml` (title, MITRE via `Reports`,
   `LogTypes`, sibling-`.py` path). For **schema** field-extraction it's
   `recognized_unsupported` — we don't parse arbitrary Python in v1. Revisit later.
2. **New explicit `support` enum** — `supported | recognized_unsupported |
   not_a_rule`, distinct from `needs_review`. `support` = how well we handle the
   format; `needs_review` = low confidence in inferred metadata. Keeps the
   coverage report honest. Goes on `DiscoveredRule` and `CatalogRecord`.
3. **Auto-detect only — no user format prompt.** ADEF does **not** ask the user
   what rules to expect (at init or catalog). Content-signature detection does all
   the work; `adef catalog` reports what it found. `adef init` stays
   non-interactive scaffolding. (The only existing prompt, `adef schema init`'s
   query-language question, is unrelated and out of scope here.)
4. **Recognizer bias — general-shape-first.** Primary test is "has a query/logic
   field + detection metadata"; vendor signatures (Sigma `detection:`, Splunk
   `search:`, Panther `RuleID:`) are hints for *where* to read them, not a closed
   list — an unlisted-but-rule-shaped file is still caught.
5. **Test fixtures — skip for now.** Test directly against the cloned `test-rules/`
   repos (Splunk `detections/`, Panther `rules/`); more repos to come. Revisit
   vendored/synthetic fixtures later if CI needs offline stability.

## Remaining gate

**Coordination:** this reshapes `rule_discovery` + `CatalogRecord` (`format`
values, new `support` enum). Both are schema-shared surfaces — co-worker sign-off
before Phase 1. All design questions above are settled.
