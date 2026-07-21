# Creating Extraction Profiles

`adef catalog` recognizes Sigma, Splunk ESCU, Splunk `savedsearches.conf`,
Panther, and raw `.sql`/`.kql`/`.cql` out of the box. Everything else — your
in-house YAML wrapper, a vendor export we haven't met — shows up as
**unclaimed**. An *extraction profile* teaches ADEF the format: a small YAML
file describing how to recognize it and where its fields live. No code, and
every future catalog/sync run uses it automatically.

Rule of thumb: **one profile per format** (one field layout). If your repo
has three in-house formats (say `scheduled-sql`, `composites`,
`hunting-triggers`), that's three profiles, each ~15 lines.

## 1. Find and cluster the unclaimed files

```bash
adef catalog /path/to/rules --dry-run --report json > report.json
```

Every unclaimed file is listed with its `top_level_keys`. Files sharing a key
set are one format. Group them (an AI assistant does this well — so does
`jq`):

```bash
jq -r '.files[] | select(.outcome=="unclaimed") | .top_level_keys | join(",")' report.json \
  | sort | uniq -c | sort -rn
```

## 2. Write the profile

Open two or three sample files from one cluster and fill in the map:

```yaml
# one file per format; name it after the format
name: nebulock-scheduled-sql          # kebab-case, unique
version: 1
signature:                            # how ADEF recognizes the format
  container: yaml                     # yaml | json (v1)
  all_keys: [query, schedule]         # top-level keys EVERY file of this format has
  none_keys: [composite_of]           # keys that identify near-misses to EXCLUDE
  extension: [.yml, .yaml]            # hint only
query_language: sql                   # spl | kql | cql | sql | none
map:                                  # dot-paths into the document; [] iterates lists
  title: name                         # required
  query: query                        # required — the detection logic
  uuid: id                            # strongly recommended: stable identity for sync
  mitre: tags[]                       # raw tokens; technique IDs are extracted downstream
  data_source: source                 # table/index literal, if the format has one
  description: description           # optional — also swept for MITRE technique IDs
  severity: severity                  # optional
platform:
  const: windows                      # or `path: <dot-path>`; omit if unknowable
```

Choosing the signature: pick keys that are (a) present in **every** sample
and (b) distinctive — `query` + `schedule`, not `name`. If a sibling file
type shares those keys (a suppression list, a pack), exclude it with
`none_keys`. Profiles are checked **before** built-in recognizers, so a
profile can also override how ADEF reads a format it thinks it knows.

Notes on optional fields: `data_source` can usually be omitted for SQL/SPL/KQL
formats — ADEF falls back to extracting the table/index literal from the query
itself. If the format has no MITRE field, technique IDs mentioned in the
title/description/query text are picked up automatically.

## 3. Validate — the engine is the scoreboard

```bash
adef profile lint nebulock-scheduled-sql.yml       # schema errors
adef catalog /path/to/rules --dry-run --profile nebulock-scheduled-sql.yml
```

The dry-run reports how many files the profile claimed and per-field
extraction rates:

```
Profile nebulock-scheduled-sql claimed 61 rules; title 100%, query 100%, mitre 3%, uuid 100%, ...
```

Targets: `query` ≥ 95%, `title` ≥ 90%. A low rate means a wrong dot-path or
a cluster that's actually two formats (split it into two profiles). Low
`mitre` usually just means the rules genuinely carry no ATT&CK mapping —
that's the enrichment queue, not a profile bug.

## 4. Install and run

```bash
mkdir -p $ADEF_WORKSPACE/config/profiles   # or ~/work/adef-workspace/config/profiles
cp nebulock-scheduled-sql.yml $ADEF_WORKSPACE/config/profiles/
adef catalog /path/to/rules                # picks up all installed profiles
```

Profiles are plain YAML in your workspace — commit them wherever you keep
config. A broken profile never kills a catalog run; it's reported and
skipped.

## The agent path

If you're using Claude with the ADEF plugin installed, all of the above is
one conversation: the **catalog-onboarding** skill runs the triage, clusters
the unclaimed files, has the profile-author sub-agent draft profiles from
samples, validates them with the same scoreboard, and asks you to approve
before installing. Same artifact, no hand-authoring.

## Worked example

The repo's Panther corpus has 95 scheduled-query files no built-in claims —
two formats (`Query:` vs `SnowflakeQuery:`), so two profiles. See
`docs/plans/2026-07-20-claude-plugin-design.md` for the full schema and
matching semantics.
