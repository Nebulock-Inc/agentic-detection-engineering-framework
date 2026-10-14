"""Suite-wide test fixtures.

Hermeticity is structural here, not per-test discipline: with the `llm` extra
installed, an `ANTHROPIC_API_KEY` in the developer's real environment would make
any test that explicitly passes `similarity_mode="auto"` to `RuleSimilarityAgent`
resolve to `"llm"` and attempt a billed network call (the agent's own default is
`"bm25"` now, not `"auto"`, but `auto` remains selectable and its tests still
need a deterministic environment). Unsetting the key for every test means a
test only reaches the LLM path when it deliberately injects a fake client or
sets the key back itself.

Terminal capabilities are structural for the same reason — see the
``FORCE_COLOR`` note below.
"""

from __future__ import annotations

import os

import pytest

# Keep Rich's output plain under `CliRunner`, whatever the shell says.
#
# Rich treats *any* value of `FORCE_COLOR` as "this is a terminal", which
# overrides the non-tty buffer `CliRunner` captures into. Colorized output puts
# escape sequences *inside* the strings CLI tests assert on — a path renders as
# `adef catalog \x1b[0m\x1b[1;35m/path/to/your/\x1b[0m…`, so
# `"adef catalog /path/to/your/rules" in result.output` is false while the
# command works perfectly. Twenty-eight tests went red at once on a machine
# whose terminal (Ghostty) and shell plugins export it.
#
# At import time, not in an autouse fixture: the command modules hold
# module-level `Console()` objects, and `Console.is_terminal` *memoizes*
# `_force_terminal=True` the first time it sees the var. A per-test
# `monkeypatch.delenv` runs after that cache is already poisoned — it was tried
# first and left all 28 failures in place. conftest is imported before the test
# modules that import `adef.commands.*`, so this is the one hook early enough.
#
# Production behavior is untouched: honoring `FORCE_COLOR` when a user pipes
# `adef health show` into a file is correct. Only the harness needs determinism.
for _color_var in ("FORCE_COLOR", "CLICOLOR_FORCE"):
    os.environ.pop(_color_var, None)


@pytest.fixture(autouse=True)
def _no_anthropic_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _uncached_attack_reference():
    """`attack_reference` is `lru_cache`d, so a warm entry answers for the test.

    Structural for the same reason as the API key above, not per-test
    discipline. The resolver is keyed on its `workspace` argument, so a test
    that plants a snapshot under its own `tmp_path` is usually safe — but the
    *zero-arg* key is shared by every test in the process, and any test that
    sets `$ADEF_WORKSPACE` writes into it. That is exactly the failure round 9
    found in production code: the answer depended on whether something earlier
    had warmed the cache.

    One clear, and it has to be this side. An *entry*-side clear is
    function-scoped, and pytest sets up higher-scoped fixtures first — so a
    module- or session-scoped fixture that calls `attack_reference` reads
    whatever the previous test left behind, before the entry clear has run.
    `test_attack.py`'s `ref` (module scope) is exactly that fixture: deleting
    the line below turns six of its seven consumers red, starting with
    `assert 0 > 500` on an empty technique map, plus
    `test_invalid_mitre_review_reason`, which reaches the same shared key
    through `finalize_review` rather than through `ref` — seven reds,
    measured. The one `ref` consumer that stays green,
    `test_unknown_id_resolve`, asserts an ID is *absent*, which an empty
    snapshot satisfies honestly; it is the only one of the seven **`ref`
    consumers** an empty snapshot cannot make lie. (Two different sevens, three
    lines apart: seven reds, and seven `ref` consumers, which are not the same
    set — the green one is not a red, and one red does not take `ref`.)

    Both sides were tried, in both orders, and only this one is load-bearing.
    Round 12 kept entry-only on the grounds that the *next* test's entry clear
    cleans up regardless; that holds only when every fixture in the next test
    is function-scoped, which is what the paragraph above is about. Round 13
    put both back and found the entry clear is the redundant one in the other
    direction: deleting it left the whole of `test_attack.py` green, because
    this clear had already emptied the cache when the previous test ended.
    What neither side covers is a cache warmed before the first test runs at
    all — at import time, or by a session-scoped fixture. Nothing does that
    today, and a clear for it could not be made to fail.
    """
    from adef.core.attack import attack_reference

    yield
    attack_reference.cache_clear()
