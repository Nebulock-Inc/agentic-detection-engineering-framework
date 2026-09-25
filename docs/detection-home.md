# Using ADEF as Your Detection Home (no repo)

Most ADEF users point it at an existing rules repository — it catalogs and
journals what's already there, read-only. But if you **don't have a
detection-as-code repo** (rules live in your SIEM, or nowhere durable yet), you
can use ADEF itself as the place your detections live: author them here, and the
workspace becomes your system of record.

This guide is for that case.

## The mental model

- Detections you **author in ADEF** (`adef detection new --source <schema>`)
  carry `origin: authored`. ADEF owns the durable copy — there is no upstream
  file.
- Detections **catalogued from a repo** carry `origin: catalogued`. The repo is
  the source of truth; ADEF's record is a derivation.

`adef detection list --origin authored` shows what you've created here.

## 1. Make the workspace durable — version-control it

Your authored detections are the only copy, so treat the workspace like the
important data it is. The workspace is plain markdown + YAML — no ADEF-specific
tooling needed, just native git.

```bash
adef init ~/detections            # scaffold the workspace
cd ~/detections
git init && git add -A && git commit -m "Initialize detection workspace"
```

A minimal `.gitignore` keeps out the cruft:

```gitignore
__pycache__/
*.pyc
.DS_Store
*.tmp
```

Now every `journals/`, `catalog/`, and `schema/` change gets history, blame, and
backup — push it to a private remote and it's off-machine too. Commit after
authoring sessions the same way you'd commit code.

## 2. Author detections here

Declare your data sources once (see `declaring-data-sources.md`), then:

```bash
adef detection new "Suspicious mshta child" --source wineventlog_xml
```

This scaffolds a draft grounded in that schema (real fields/scope) plus a
journal for the *why*. The `detection-author` skill (Claude plugin) interviews
you for intent, threat model, and known false positives, and fills in the query
against real fields. Tag ATT&CK with `adef detection tag-mitre`; see coverage
with `adef coverage`.

**A note on hand-editing the journal:** this caveat applies only to the
template **preamble** (the fields before the first `## [<timestamp>] Stage:`
heading): if you hand-edit one of those fields yourself, keep new reasoning in
the template's `- **Field:** value` bullet grammar (or a wrapped continuation
of one), since a free-text paragraph there won't turn up in `adef detection
search`. Text inside a stage block (after the first `## Stage:` heading) has
no such restriction — it is indexed as written.

## 3. Sync is safe here

You can still run `adef sync` (e.g. if you later *also* catalog a repo). **It
never touches `origin: authored` records** — they have no upstream to reconcile
against, so your authored detections pass through untouched. Sync only
reconciles catalogued rules.

## Getting rules into your SIEM

ADEF formats and reasons about detections; it does not deploy them (no vendor
connectors — a deliberate anti-goal). For now, copy the query from
`adef detection show D-XXXX` into your SIEM by hand. A future version may add an
export/graduation path (records → rule files, so you can move to
detection-as-code) — it's deferred until teams authoring here ask for it.

## When you outgrow this

If you decide to go full detection-as-code later, the path is open: your journals
and catalog are already in git, and the authored records hold the queries. That
migration (emit real rule files → a proper rules repo → normal `catalog`/`sync`)
is the deferred export work; ask if you need it.
