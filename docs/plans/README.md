# ADEF v1 Design Documentation

This directory contains the planning and design documents for ADEF v1. These were created through a series of brainstorming and decision-making sessions in late June / early July 2026.

## Where to Start

**For team review (read in this order):**

1. **[2026-07-07-adef-architecture.md](2026-07-07-adef-architecture.md)** ← START HERE
   - High-level system design with diagrams
   - Shows how all the pieces fit together
   - Visual/conceptual, not implementation details
   - ~15 minute read

2. **[2026-07-09-design-decisions-from-meeting.md](2026-07-09-design-decisions-from-meeting.md)** ← LATEST
   - Team meeting notes (July 9)
   - 6 locked design decisions (rule storage, cataloging, schema, syncing, CLI/skills, priorities)
   - 7 open questions for team input (reconciliation, auto-tagging, schema structure, etc.)
   - Directly actionable for implementation

3. **[2026-07-09-implementation-stories.md](2026-07-09-implementation-stories.md)**
   - 9 stories for 3-week sprint (Epic 6996)
   - Full acceptance criteria, effort estimates, dependencies
   - Ready to copy into Shortcut/Jira/Linear

4. **[2026-07-01-meeting-summary-open-questions.md](2026-07-01-meeting-summary-open-questions.md)**
   - What we've locked (6 core decisions from July 1)
   - What was open after the July 1 meeting (5 questions with options)
   - Team decisions are now resolved — see "Resolved" section below

5. **[2026-06-26-adef-day-in-the-life.md](2026-06-26-adef-day-in-the-life.md)**
   - End-to-end user experience walkthrough
   - Day 0 (backfill), authoring flow, drift detection, tuning
   - Shows what it *feels* like to use ADEF day-to-day

6. **[2026-06-26-adef-repo-design.md](2026-06-26-adef-repo-design.md)** (optional deep-dive)
   - Detailed design (11 sections)
   - Three-layer architecture, three artifacts, skills catalog, CLI surface
   - Read if you need implementation-level detail

## Resolved Decisions (From July 1 Meeting)

The 5 open questions in the meeting summary doc were resolved with the team:

- **Q1 (ADEF-authored rules → pipeline):** Point at existing repo, reference-and-enrich model. ADEF reads their repo (never writes). New detections authored in ADEF need a mechanism to land in their repo — manual copy or auto-write (TBD).
  
- **Q2 (Rule-writing assistance):** Schema-grounded + few-shot from corpus. Provide guidance docs for users on schema discovery and helping agents write good rules.

- **Q3 (ATHF integration):** Standalone for v1. No unified workspace. Focus on making ADEF usable independently; integration can come later.

- **Q4 (athf detect overlap):** Acknowledge overlap exists; build ADEF's detection lifecycle fully. Eventually remove duplicate functionality from ATHF (not blocking v1).

- **Q5 (Format parsers):** Sigma-first. Ship a solid Sigma parser for backfill auto-enrichment (extract MITRE, platform, kind). Other formats (Splunk, Elastic, KQL) are community-driven or v2.

## Key Design Principles

**v1 Scope — The Layer on Top:**
ADEF v1 is deliberately scoped as **the enrichment, memory, and guidance layer that sits on top of a team's existing rules repository.** It reads, catalogs, journals, organizes, tags, and documents detections — and assists in authoring new ones — without modifying the source repo or handling deployment.

**What v1 Does NOT Do:**
- Does not extract rules from a SIEM (assumes file-based repo)
- Does not deploy rules (teams deploy via their own pipeline)
- Does not modify the team's detection repo (read-only; reference-and-enrich model)
- Does not ship vendor connectors (results-in seam: you pipe data, ADEF consumes it)

**Core Architecture:**
- **Three layers:** Skills (brain, optional) → CLI (engine, always required) → Workspace (memory)
- **Three artifacts:** Catalog (enrichment records), Journals (history), Schema (ground truth)
- **State ownership rule:** All durable state writes go through the CLI. Skills think and recommend; CLI commits.

## Implementation Plan

See the architecture doc for the 7-chunk build plan:

1. Workspace + data model
2. Backfill (Sigma parser, catalog/journal creation)
3. Browsing (list, show, coverage)
4. FORGE lifecycle (observe, refine, govern, evolve)
5. Schema (learn, diff, show)
6. Detection test (query run recording)
7. Skills layer (5 skills + guidance docs)

**Target:** Week 1 = chunks 1-4 (usable CLI), Week 2 = chunks 5-7 (full agentic surface).

## Document History

- **2026-06-26:** Initial brainstorming session → repo design + day-in-the-life docs
- **2026-07-01:** Team meeting → scope tightening, 5 open questions surfaced
- **2026-07-07:** Team decisions resolved → architecture doc written
- **2026-07-08:** Consolidation for review
- **2026-07-09:** Team meeting notes → design decisions + implementation stories added. Epic 6996 created (6 stories, 28 points). 7 open questions for next discussion.

## Other Context Docs

- **[../forge-framework-comparison.md](../forge-framework-comparison.md)** — Compares ADEF's FORGE methodology against Snowflake and Palantir frameworks (industry context, gap analysis)
- **[../methodology.md](../methodology.md)** — FORGE lifecycle explained
- **[../why-adef.md](../why-adef.md)** — Adoption guide, ADEF vs ATHF relationship

## Questions or Feedback?

Discuss in the team channel or comment directly on the branch: `feature/adef-v1-design`
