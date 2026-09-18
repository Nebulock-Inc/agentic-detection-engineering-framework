"""Suite-wide test fixtures.

Hermeticity is structural here, not per-test discipline: with the `llm` extra
installed, an `ANTHROPIC_API_KEY` in the developer's real environment would make
`RuleSimilarityAgent`'s default `similarity_mode="auto"` resolve to `"llm"` and
attempt a billed network call. Unsetting it for every test means a test only
reaches the LLM path when it deliberately injects a fake client or sets the key
back itself.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_anthropic_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
