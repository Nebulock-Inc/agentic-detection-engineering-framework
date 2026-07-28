---
id: D-XXXX
title: TODO — name this detection
status: draft
current_stage: find
owner: ""
created: ""
updated: ""
rule_uuid: ""
---

# Detection Journal

> This journal pairs with an upstream rule (`rule_uuid` above). The rule YAML
> is the source of truth for *what* the detection looks for; this journal is
> the source of truth for *why*, *how*, and *what next*. Each FORGE stage
> appends a timestamped block below.

## Find

What gap, signal source, intel report, or hunt outcome led to this detection?

- **Gap or signal source:**
- **Intel sources / references:**
- **Hypothesis (one sentence):**
- **MITRE ATT&CK mapping (if known):**

## Observe

Characterize the real-world telemetry behavior before defining "weird".

- **Data source(s):**
- **Field availability / population rates:**
- **Volume / cardinality estimates:**
- **Baseline of normal:**
- **Sample query that surfaces the behavior:**

## Refine

Iterate the rule with feedback from Similarity, Overlap, Verification.

- **Initial draft query:**
- **Iterations & rationale:**
- **Backtest outcomes (true positives, false positives, ratio):**
- **Similar / overlapping rules:**

## Govern

Deploy with quality gates, ownership, and review cadence.

- **Engine type (sigma | sql | sch_sql | composite):**
- **Severity / risk score / RBA contribution:**
- **Owner:**
- **On-call rotation accountable:**
- **Review cadence (every N days/weeks):**
- **Deployment gate evidence:**

## Evolve

Tune, deprecate, replace. Detections never finish — they iterate.

- **Recent tuning decisions:**
- **Performance trend (signal volume, fp ratio, latency):**
- **Replacement / deprecation rationale (if any):**
- **Successor rule(s) (if deprecated):**
