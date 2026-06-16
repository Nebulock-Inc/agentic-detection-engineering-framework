**FORGE / Refine — iterate the rule with feedback.**

`adef detection refine <id>` invokes the orchestration chain
(Similarity → Overlap → Verification) and appends each agent's output below
this block. Capture, alongside it:

- Each iteration of the draft query and *why* it changed.
- Backtest outcomes: true positives, false positives, ratio over a representative window.
- Similar or overlapping rules surfaced by Similarity / Overlap — link to their UUIDs.
- Verification agent's verdict on whether the rule fires for the intended behavior.
