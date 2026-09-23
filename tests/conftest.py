"""Suite-wide test fixtures.

Hermeticity is structural here, not per-test discipline: with the `llm` extra
installed, an `ANTHROPIC_API_KEY` in the developer's real environment would make
any test that explicitly passes `similarity_mode="auto"` to `RuleSimilarityAgent`
resolve to `"llm"` and attempt a billed network call (the agent's own default is
`"bm25"` now, not `"auto"`, but `auto` remains selectable and its tests still
need a deterministic environment). Unsetting the key for every test means a
test only reaches the LLM path when it deliberately injects a fake client or
sets the key back itself.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_anthropic_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
