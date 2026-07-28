**FORGE / Govern — deploy with quality gates, ownership, review cadence.**

A detection without ownership is a detection without a future.

- **Engine type** — exactly one of `sigma | sql | sch_sql | composite`.
- **Severity / risk score / RBA contribution** — calibrate against neighbors.
- **Owner** — the human who carries the pager for this rule.
- **On-call rotation** — which rotation responds when this fires.
- **Review cadence** — every N days/weeks. Calendar it.
- **Deployment gate evidence** — peer review, backtest summary, false-positive review.
