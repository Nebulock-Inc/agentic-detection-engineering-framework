# Agentic Detection Engineering Framework (ADEF)

> Detection engineering with durable memory, a five-stage lifecycle, and an agentic surface — the sibling of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework).

ADEF gives every detection a journal, every transition a timestamp, and every lifecycle stage an agent surface that current and future engineers can read. Rules stay where they are (YAML in your detection repo) — ADEF wraps them with a sibling markdown layer (`journals/D-XXXX.md`) so the *why*, *how*, and *when next* of every rule is captured durably.

## The FORGE Lifecycle

ADEF detections move through five stages:

1. **Find** — a gap, a signal source, an intel report, a hunt outcome
2. **Observe** — characterize real telemetry behavior; understand normal before defining weird
3. **Refine** — iterate the rule with backtest, similarity, overlap, and verification feedback
4. **Govern** — deploy with quality gates, ownership, review cadence
5. **Evolve** — tune, deprecate, replace; detections never finish, they iterate

See [`docs/methodology.md`](docs/methodology.md) for the full FORGE walkthrough.

## Quick Start

```bash
pip install agentic-detection-engineering-framework

adef init                              # scaffold ~/work/adef-workspace/
adef detection new "Suspicious svchost.exe child process"
adef detection observe D-0001
adef detection refine  D-0001          # invokes Similarity → Overlap → Verification
adef detection govern  D-0001
adef detection evolve  D-0001
```

## ADEF and ATHF — paired siblings, not successor

ADEF and ATHF are *paired siblings*. ATHF owns the threat-hunting lifecycle (LOCK pattern, hunts repo). ADEF owns the detection-engineering lifecycle (FORGE pattern, journals repo). Hunts that earn detections cross the bridge via `adef hunt-promote H-XXXX`. Both frameworks share the same Click + entry-point + FastMCP shape, so analysts and agents that learn one recognize the other immediately.

In v0.1.0, any existing `athf detect` plugin keeps working but prints a deprecation banner pointing at `adef detect`. Removed cleanly in v0.2.0 — see [`docs/roadmap.md`](docs/roadmap.md).

## Maturity Model

| Level | Name | What you get |
|---|---|---|
| L0 | Ad-hoc | Rules in chat threads and tickets |
| L1 | Documented | Rules in a repo with metadata |
| L2 | Searchable | AI reads coverage, performance, overlap |
| L3 | Generative | AI proposes/drafts/backtests rules from intel or hunts |
| L4 | Agentic | Autonomous tuning, deprecation recommendations, scheduled gap sweeps |

See [`docs/maturity-model.md`](docs/maturity-model.md) for full descriptions and time-to-value estimates.

## Why ADEF

[`docs/why-adef.md`](docs/why-adef.md) is the adoption guide — what problem ADEF solves, where it fits in your stack, what you give up to use it, and how to bring it into an existing detection program.

## North-Star v1 Demo

```bash
adef detection new --from-intel https://example.com/cti-report
```

In minutes: a backtested, MITRE-tagged, deduplicated, journalled detection. Six months later, ADEF flags it for tuning when noise crosses threshold. See [`docs/north-star.md`](docs/north-star.md).

## License

MIT — see [`LICENSE`](LICENSE).
