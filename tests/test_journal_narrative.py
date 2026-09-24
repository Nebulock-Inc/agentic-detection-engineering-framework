# tests/test_journal_narrative.py
from pathlib import Path

from adef.core.journal import GENERATED_MARKER, Journal, narrative_text


def _journal(tmp_path: Path) -> Journal:
    d = tmp_path / "journals"
    d.mkdir(parents=True)
    return Journal(d)


def test_narrative_drops_the_template_preamble():
    # Everything before the first timestamped stage block is unfilled
    # scaffolding, not reasoning — indexing it makes every detection look
    # alike on the template's own words.
    body = (
        "> A FORGE journal\n\n"
        "- **Hypothesis:**\n"
        "- **Data source:**\n\n"
        "## [2026-09-24T10:00:00-04:00] Stage: observe\n\n"
        "UNIQUEOBSERVATION mshta spawning from Office\n"
    )
    out = narrative_text(body)
    assert "UNIQUEOBSERVATION" in out
    assert "Hypothesis" not in out


def test_narrative_drops_marked_generated_blocks():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        "HUMANNOTE checked this by hand\n\n"
        f"### Refine / Similarity (2026-09-24T10:01:00-04:00)\n{GENERATED_MARKER}\n\n"
        "- **candidates:** MACHINEOUTPUT D-0002\n"
    )
    out = narrative_text(body)
    assert "HUMANNOTE" in out
    assert "MACHINEOUTPUT" not in out


def test_narrative_drops_unmarked_legacy_refine_blocks():
    # Journals written before the marker existed must still be filtered —
    # this fallback is permanent, not a migration step.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        "HUMANNOTE checked this by hand\n\n"
        "### Refine / Overlap (2026-09-24T10:01:00-04:00)\n\n"
        "- **overlaps:** LEGACYOUTPUT D-0002\n"
    )
    out = narrative_text(body)
    assert "HUMANNOTE" in out
    assert "LEGACYOUTPUT" not in out


def test_narrative_keeps_a_human_block_that_is_not_refine():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: govern\n\n"
        "### Deployment decision (2026-09-24T10:01:00-04:00)\n\n"
        "KEEPTHIS approved by the on-call lead\n"
    )
    assert "KEEPTHIS" in narrative_text(body)


def test_narrative_drops_catalogued_from_housekeeping():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: find\n\n"
        "Catalogued from /repo/rules/x.yml by adef catalog\n"
        "REALCONTENT here\n"
    )
    out = narrative_text(body)
    assert "REALCONTENT" in out
    assert "Catalogued from" not in out


def test_narrative_keeps_a_filled_preamble_field():
    # r1 findings, Important: a user who fills in a preamble field (before
    # any stage block exists to hold it) has written reasoning, not
    # scaffolding — dropping it silently stopped it from ever scoring.
    body = (
        "> A FORGE journal\n\n"
        "- **Hypothesis (one sentence):** HYPOTOKEN attacker abuses mshta\n"
        "- **Baseline of normal:** SPOOKYBASELINE mshta from Office ~3/day\n\n"
        "## [2026-09-24T10:00:00-04:00] Stage: find\n\n"
        "**Title:** t\n"
    )
    out = narrative_text(body)
    assert "HYPOTOKEN" in out
    assert "SPOOKYBASELINE" in out


def test_narrative_drops_an_unfilled_preamble_field():
    body = (
        "> A FORGE journal\n\n"
        "- **Hypothesis (one sentence):** HYPOTOKEN attacker abuses mshta\n"
        "- **Data source(s):**\n\n"
        "## [2026-09-24T10:00:00-04:00] Stage: find\n\n"
        "**Title:** t\n"
    )
    out = narrative_text(body)
    assert "HYPOTOKEN" in out
    assert "Data source" not in out


def test_narrative_of_an_unadvanced_journal_is_empty():
    # `detection new` writes template only. Nothing to index.
    body = "> A FORGE journal\n\n- **Hypothesis:**\n- **Data source:**\n"
    assert narrative_text(body).strip() == ""


def test_append_block_marks_generated_blocks(tmp_path):
    j = _journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.append_block("D-0001", "Refine / Similarity", "- **x:** 1", generated=True)
    text = (tmp_path / "journals" / "D-0001.md").read_text()
    assert GENERATED_MARKER in text
    # The block itself is still in the file — exclusion is index-only.
    assert "**x:**" in text


def test_append_block_is_unmarked_by_default(tmp_path):
    j = _journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.append_block("D-0001", "Deployment decision", "approved")
    text = (tmp_path / "journals" / "D-0001.md").read_text()
    assert GENERATED_MARKER not in text
