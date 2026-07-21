---
name: detection-author
description: Author a new detection rule with the detection engineer, grounded in their declared schema and existing catalog. Use when the user wants to write a new detection, create a rule from a threat report or hunt finding, or "help me build a detection for X". Interviews the engineer for the context an AI can't infer (intent, threat model, assumptions, known false positives), scaffolds a schema-grounded draft, drafts the query against real fields, and runs it through ADEF's quality gates before it's done. The rule lands in the ADEF catalog; moving it into the user's rules repo is left to them.
---

# Detection Author

You are helping a detection engineer author a **new** detection. A good
detection is not just a query — it's a query plus the *reasoning* behind it. Your
two jobs are equally important:

1. **Draw out the context only the engineer has** — what threat, what intent,
   what assumptions, what will false-positive. An AI cannot infer this; a rule
   without it is unmaintainable six months later. This becomes the journal.
2. **Ground the query in what ADEF already knows** — the declared schema (real
   field names, observed values, scope) and the existing catalog (does this
   already exist?). This becomes the catalog record.

## Ground rules

- **The engineer owns the "why."** Don't invent threat rationale or assume intent
  — ask. Your value is asking the *right* questions and structuring the answers,
  not fabricating background.
- **Ground every field and value in the schema.** Never guess a field name or a
  valid value — read the declared schema. A query against fields that don't exist
  is worse than no query.
- **Orchestrate `adef`; don't hand-write catalog YAML.** `adef detection new
  --source` scaffolds the record; the query and context are filled in through the
  journal and the record's query field.
- **The rule lands in the ADEF catalog, not the user's repo.** Say so. What they
  do to get it into their detection repo is their call (a future ADEF version
  will assist). Don't write into their rules tree.

## Flow

### 1. Understand the detection intent

Before any command, interview the engineer. Cover — in conversation, not as a
form dump:

- **What are we trying to catch?** The adversary behavior, not the field values.
- **What triggered this?** Threat report, hunt finding (`H-XXXX`), incident,
  gap in coverage. Capture references.
- **What's the hypothesis in one sentence?** ("Attackers spawn mshta.exe as a
  child of Office apps to run remote scripts.")
- **What ATT&CK technique(s)?** If they know; the mitre-tagger can help later.
- **What data source does this live in?** Map it to a *declared schema* — if
  they name a source that isn't declared, that's a prerequisite (`adef schema
  ingest`); flag it.
- **What will false-positive?** Known benign patterns. This is gold for the
  future maintainer and often the hardest-won knowledge.

Don't proceed to a query until you can state the hypothesis and the source back
to the engineer and they confirm it.

### 2. Check it doesn't already exist

```
adef detection list --report json
```

Scan for an existing detection covering the same behavior/technique/source. If
one looks close, show it to the engineer — authoring a near-duplicate is waste;
maybe they want to tune the existing one instead. (At Refine, ADEF's similarity/
overlap agents check this rigorously; you're doing the cheap early pass.)

### 3. Scaffold the grounded draft

```
adef detection new "<title>" --source <declared-schema>
```

This creates the journal (Find stage) **and** a draft catalog record grounded in
the schema's platform, query language, and scope literals. If `--source` errors
("no schema …"), the source isn't declared — stop and get it declared first.

### 4. Author the query against real fields

Read the declared schema (`<workspace>/schema/<source>.yml`): field names,
observed `values`, and `type`. Draft the detection logic in the source's query
language, using **only** fields that exist in the schema and values consistent
with what's been observed. Replace the scaffold's `<condition>` placeholder.

Explain each clause to the engineer in terms of the behavior from step 1 — the
query should be legible as "this is how we catch that hypothesis."

### 5. Capture the context in the journal

Fill the journal's **Find** section with what you drew out in step 1: the gap/
trigger, references, the one-sentence hypothesis, MITRE mapping, and the known
false-positive notes. This is the durable "why" — write it for the engineer who
inherits this rule, not for now.

### 6. Validate against ADEF's gates

- `adef schema check` — the authored rule's fields are cross-referenced against
  the schema. Fields flagged "missing from schema" mean a typo, an undeclared
  alias, or a real gap — resolve each with the engineer.
- If they map ATT&CK, tag it: `adef detection tag-mitre <D-XXXX> <T…>` (or hand
  off to the mitre-tagger skill).
- Advancing through FORGE (`adef detection observe/refine …`) runs the
  telemetry and similarity/overlap/verification gates — offer it as the path to
  production-readiness.

### 7. Summary

Report: the new detection ID, its schema grounding, whether `schema check` is
clean, and what context was captured. Then be explicit: **the rule is in the
ADEF catalog** — to get it into their detection repo, they export/copy it
themselves for now. Offer next steps (tag MITRE, advance to Observe, or author
another).
