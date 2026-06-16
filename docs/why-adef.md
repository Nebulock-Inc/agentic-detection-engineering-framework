# Why ADEF — Adoption Guide

> ADEF is the agentic, journaled detection-engineering framework. This page is for teams asking *"why this, why now, where do I start?"*

## The one-paragraph pitch

Detection engineering programs have a memory problem. Rules ship as YAML; the *why* lives in DMs, tickets, and senior-engineer brains. When the original author leaves, the rule becomes load-bearing software with no documentation. ADEF gives every detection a sibling markdown journal, structures the lifecycle as **FORGE** (Find → Observe → Refine → Govern → Evolve), and bolts in agent assistance at every stage. The journals are durable memory. The lifecycle is a habit loop. The agents are colleagues — not autopilots.

## What ADEF replaces

Nothing. ADEF is a layer above your existing detection store, not a fork of it.

- Your detection rules continue to live where they are. ADEF reads them through a vendor-neutral bridge (configured by `ADEF_RULE_ROOT`) and is strictly read-only.
- Your platform of record (Splunk, Sigma+pipeline, ClickHouse, Sentinel) is unchanged.
- Your CI/CD for rule deployment is unchanged.

What ADEF adds:

- A workspace at `~/work/adef-workspace/` (configurable) with `journals/`, `templates/`, and `config/`.
- A CLI (`adef`) that walks rules through FORGE.
- An MCP server (`adef-mcp`) that exposes the same operations to Claude Code, Copilot, Cursor.
- Twelve upstream rule-engineering agents wrapped as lifecycle-aware tools, plus four ADEF-native agents.

## What ADEF and ATHF are to each other

ADEF and **ATHF** ([Agentic Threat Hunting Framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework)) are **paired siblings, not a successor relationship**.

| Concern | ATHF | ADEF |
|---|---|---|
| Lifecycle pattern | LOCK (Learn → Observe → Check → Keep) | FORGE (Find → Observe → Refine → Govern → Evolve) |
| Unit of work | A hunt (`H-XXXX`) | A detection (`D-XXXX`) |
| Output | Findings, hypotheses, indicators of suspicion | Production rules with deployment evidence |
| Memory | Hunt journal | Detection journal |
| When to use | "Is this happening?" — you don't know yet | "Codify this so it pages someone" — you've decided to detect it |

A hunt that produces a durable signal *graduates* to a detection via `adef hunt-promote H-XXXX`. The hunt's journal lineage is preserved in the new detection's Find stage. ATHF is upstream of ADEF, but neither replaces the other.

## When to adopt ADEF

You should consider ADEF if **two or more** of these are true:

- New detection engineers spend their first month re-asking "why is this rule the way it is?"
- Tuning decisions are made by reading source-control blame instead of reading rationale.
- Your team has shipped agent-augmented hunting (ATHF, internal tools) and wants the same memory model on the detection side.
- Your detection store has no consistent home for *why* a rule exists, *how* it was characterized, or *what comes next*.
- Your team is curious about agent-augmented detection engineering but wants the agents to draft, not act.

You should NOT adopt ADEF if:

- You don't have a place where production rules live yet — fix that first.
- You're looking for a SIEM replacement, a log shipper, or a vendor connector. ADEF ships none of those and never will (see [anti-goals](./roadmap.md#anti-goals)).
- You want web-UI-driven detection authoring. v0.1.0 is CLI + MCP only.

## Adoption path

A pragmatic four-week ramp from "installed" to "habit":

**Week 1 — Install + journal one rule.**
- `pip install agentic-detection-engineering-framework`
- `adef init`
- Pick one production rule. Write its journal by hand, walking FORGE backward (start from where the rule is now, fill in why it got there).

**Week 2 — Backfill.**
- `adef backfill journals` to scaffold journals for every existing upstream rule.
- Audit: how many journals are blank? That's the size of the *why* gap. Don't try to fill them all at once.

**Week 3 — Habit loop.**
- All new detections start with `adef detection new`.
- All material tuning decisions get an Evolve-stage entry.
- Refine-stage agent chain runs as part of code review.

**Week 4 — Search.**
- Hook up `adef-mcp` to Claude Code / Copilot.
- Use `memory_search` before opening a new detection PR.
- Measure: how many proposed detections turn out to overlap with existing rules? Adjust review workflow accordingly.

By the end of a quarter, the team is at L1 (Documented) → L2 (Searchable) on the [maturity model](./maturity-model.md). L3 (Generative) is a culture shift, not a tooling shift, and arrives once the agent-drafted journals stop feeling foreign.

## What ADEF deliberately is not

A framework's anti-goals say more than its goals. ADEF v0.1.0 is **not**:

- A new YAML format. The four engine types (`sigma`, `sql`, `sch_sql`, `composite`) are taken as given. No new engines.
- A vendor connector layer. No CrowdStrike, Splunk, SentinelOne, etc. ADEF reads upstream YAML metadata; nothing more.
- A web app. No FastAPI, no Next.js, no Django. CLI and MCP only.
- A rewrite of the upstream rule-engineering agents. The 12 existing agents are wrapped — not reimplemented — so improvements there flow downstream.
- An autonomous deprecation tool. The DeprecationRecommender *recommends*. Humans approve.

## Where to go next

- [methodology.md](./methodology.md) — what FORGE actually is, stage by stage.
- [maturity-model.md](./maturity-model.md) — five levels, where to start, what to skip.
- [roadmap.md](./roadmap.md) — what's coming after v0.1.0; what's on the anti-goal list.
- [north-star.md](./north-star.md) — the v1 demo flow ADEF is converging toward.
