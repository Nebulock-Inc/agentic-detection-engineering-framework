# ADEF North Star — the v1 Demo

> One command. One URL. Minutes, not afternoons. Every step journaled.

## The demo flow

```bash
adef detection new --from-intel https://example.com/cti-report
```

In v1, that single command produces a **backtested, MITRE-tagged, deduplicated, journaled detection in minutes** — without short-circuiting any FORGE stage.

## What "without short-circuiting FORGE" means

The agentic shortcut is real. It is also dangerous. The whole point of FORGE is that detections that skip stages produce signal nobody trusts and tuning decisions nobody can defend. The flow below doesn't compress FORGE — it accelerates it.

Here is what `--from-intel` actually does, expanded:

### Find — automated, journaled

- The intel URL is fetched (or pasted text is processed).
- `HypothesisFromIntelAgent` extracts MITRE ATT&CK technique IDs (the `T\d{4}(\.\d{3})?` pattern is intentionally simple — extraction is conservative).
- A heuristic classifier proposes candidate data sources (EDR, identity, cloud control plane, network).
- A draft hypothesis is written into the Find stage of a new `D-XXXX.md` journal.
- The intel URL itself is captured as `intel_sources` — provenance is durable.

### Observe — human-loop, agent-assisted

- `Observe` is **not** automated end-to-end in v1. It is *seeded*.
- The agent proposes candidate queries against the inferred data sources.
- The human (or the calling agent in MCP context) confirms the data source has the population rates needed.
- The Observe block in the journal is filled in by whoever approved the proposal.

### Refine — chained, deterministic

- `RuleSimilarityWrapper` flags any near-duplicate of an existing upstream rule.
- `RuleOverlapWrapper` measures finding overlap with neighboring rules.
- `VerificationWrapper` confirms schema validity and four-engine compliance.
- All three results land in the journal under `### Refine / <step>` headings.
- If similarity is high *and* overlap is high, the demo flow halts and asks the human "merge with existing, or proceed?"

### Govern — gate-aware

- The agent proposes severity, RBA contribution, owner, and review cadence based on neighbors.
- The human approves the gate evidence — no rule is auto-deployed.

### Evolve — empty by design

- The Evolve stage is intentionally empty for a brand-new detection. There is nothing to evolve yet.
- The journal carries forward as the rule operates and the Evolve block fills in over time.

## Why this is a north star, not today's CLI

ADEF ships every individual piece today:

- `HypothesisFromIntelAgent` — works today, network-free for non-URL inputs.
- Refine chain — works today.
- Journal scaffolding — works today.

What ADEF deliberately does **not** ship is the **single command that wires all of them into one orchestrated flow**. The reason is conviction, not capability: orchestrating an L3-Generative happy path before the journal corpus has been seeded produces confidently-wrong drafts. We earn the `--from-intel` happy path by getting teams to L1-Documented and L2-Searchable first.

The [roadmap](roadmap.md) walks toward `--from-intel` deliberately:

1. The agent-to-agent handoff available as a discrete chain.
2. `adef detection new --from-intel <url>`, behind a documented "experimental" flag.
3. The flag removed, and this flow the default new-detection path.

## What this demo proves when it works

- **FORGE is not theater.** Each stage produced a journal artifact. A reviewer can audit the chain.
- **Memory compounds.** The next intel report that overlaps gets matched against the journal corpus, not started from scratch.
- **Agents draft; humans approve.** The system is L3-Generative, not L4-Agentic. Trust is earned proposal by proposal.
- **The framework is small.** No new engines. No vendor connectors. No web UI. The demo is one command because the framework underneath is one shape.

That is the bet: ship the substrate first, and earn the demo.
