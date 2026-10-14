"""Shared terminal-rendering helpers for ADEF's table-ish command output.

Both ``adef detection list`` and ``adef catalog --dry-run`` print one row per
rule with a trailing review flag, and both have to fit a free-text upstream
title into whatever width is left. Keeping the fitting rule in one place keeps
the two from drifting — they made opposite choices about the trailing flag once
already.
"""

from __future__ import annotations

from rich.cells import cell_len, set_cell_size

__all__ = ["cell_width", "fit", "pad"]

#: Measure a string the way the terminal lays it out, in display cells.
cell_width = cell_len


def fit(value: str, width: int) -> str:
    """Trim ``value`` to ``width`` terminal cells, marking the cut with ``…``.

    Cells, not characters: a CJK glyph occupies two columns and a combining
    mark none, so ``len()`` is the wrong ruler for a budget measured against
    the terminal — a title of wide glyphs would fit by character count and
    still overrun the row. Rule titles come from whatever upstream repo the
    user points at, so that is not hypothetical. Rich already ships the
    measurement (``rich.cells``), which is also the ruler Rich itself uses
    when it decides whether to wrap the line.

    Line breaks inside ``value`` are collapsed to spaces first. Every caller is
    building ONE table row and reserving the width of a trailing flag against
    the terminal — and a newline defeats both halves of that: ``cell_len``
    scores it as zero cells so it never counts against the budget, and Rich
    honours it regardless of ``no_wrap`` (which only governs *soft* wrapping),
    so the row splits and the flag lands on a second line with nothing beside
    it identifying the detection. `set_cell_size` could also leave the newline
    mid-string, trimming a row to something that still breaks. Reachable from
    ordinary input: a rule ``title:`` written as a YAML block scalar, or a
    telemetry source name in a capture document. Collapsed via ``splitlines``
    so every Unicode line boundary is covered, not just ``\\n``.

    ``width`` is clamped to at least 1, so a row with nothing left over still
    renders a bare ``…`` — a visible "something was cut here" — instead of an
    empty column that reads as a missing value.

    Callers reserve the width of any trailing flag *before* calling, so the
    cells a narrow terminal does have go to the flag rather than the title: a
    title is recoverable with ``adef detection show``, a silently dropped
    ``⚠ no_platform`` is not.
    """
    width = max(width, 1)
    value = " ".join(value.splitlines())
    if cell_len(value) <= width:
        return value
    return set_cell_size(value, width - 1) + "…"


def pad(value: str, width: int) -> str:
    """``fit`` plus right-padding, so a column occupies exactly ``width`` cells.

    `str.ljust` counts characters, which is the same mismatch `fit` exists to
    avoid: one wide glyph in a column value pads one cell short and every
    column to its right shifts. All of ADEF's own column values are ASCII by
    construction (IDs, the stage/status enums, `safe_platform`'d platforms,
    profile names, normalized technique IDs) — but a record's `mitre` list is a
    field humans hand-edit, and a misaligned table is a poor way to find out.
    """
    return set_cell_size(fit(value, width), width)
