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


def test_narrative_ignores_sub_block_heading_inside_a_fence():
    # 10188 follow-up item 1: `run_refine_chain`'s generic-failure branch
    # writes a traceback inside a ``` fence. A traceback line that starts
    # with `### ` used to split the generated block it belonged to — the
    # tail piece carried neither the marker nor the legacy prefix, so it got
    # indexed. The fence must protect the whole generated block, including
    # everything after the fenced `### ` line.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        f"### Refine / Verification (2026-09-24T10:01:00-04:00)\n{GENERATED_MARKER}\n\n"
        "**Failed:** boom\n\n"
        "```\n"
        "Traceback (most recent call last):\n"
        "### something that looks like a heading\n"
        "MACHINETRACEBACK line after the fake heading\n"
        "```\n"
    )
    out = narrative_text(body)
    assert "MACHINETRACEBACK" not in out
    assert "something that looks like a heading" not in out


def test_narrative_keeps_a_note_written_after_a_generated_block():
    # Major finding (10188 follow-up): `_SUB_BLOCK_RE` used to split the stage
    # area on `### ` only, so a generated Refine block "extended" past the
    # next `## [ts] Stage:` transition and swallowed it whole — including a
    # human govern note written under it. This is the normal FORGE flow:
    # refine runs the chain, then govern adds a note.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        f"### Refine / Similarity (2026-09-24T10:01:00-04:00)\n{GENERATED_MARKER}\n\n"
        "- **candidates:** MACHINETOKEN D-0002\n"
        "## [2026-09-24T11:00:00-04:00] Stage: govern\n\n"
        "GOVERNNOTE approved by on-call lead\n"
    )
    out = narrative_text(body)
    assert "GOVERNNOTE" in out
    assert "MACHINETOKEN" not in out


def test_narrative_keeps_a_human_block_that_is_not_refine():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: govern\n\n"
        "### Deployment decision (2026-09-24T10:01:00-04:00)\n\n"
        "KEEPTHIS approved by the on-call lead\n"
    )
    assert "KEEPTHIS" in narrative_text(body)


def test_narrative_no_longer_filters_catalogued_from_by_content():
    # 10188 follow-up item 2: the content-based `"Catalogued from" in line and
    # "adef" in line` filter is gone — a human line that happens to contain
    # both substrings is no longer silently dropped. Provenance (the
    # generated marker) is the only thing that excludes machine housekeeping
    # now; see `test_narrative_drops_a_generated_note_by_marker_not_content`
    # below for the actual generated note, which IS excluded, by marker.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: find\n\n"
        "Catalogued from /repo/rules/x.yml by adef catalog\n"
        "REALCONTENT here\n"
    )
    out = narrative_text(body)
    assert "REALCONTENT" in out
    assert "Catalogued from" in out


def test_narrative_drops_a_generated_note_by_marker_not_content(tmp_path: Path):
    # The real production shape: `catalog`/`sync` mark their housekeeping note
    # generated at write time (`Journal.create(generated=True)`). Deliberately
    # NOT using "Catalogued from ... adef ..." wording here — that phrase also
    # happens to match the now-deleted content filter, which would make this
    # test pass even with a broken marker-scoping implementation (the same
    # false-pass trap this branch has hit five times already). MACHINETOKEN
    # has no content-based rule anywhere, so exclusion here can only be by
    # provenance.
    j = _journal(tmp_path)
    j.create("D-0001", title="t", note="MACHINETOKEN housekeeping text", generated=True)
    entry = j.read("D-0001")
    out = narrative_text(entry.body)
    assert "MACHINETOKEN" not in out


def test_narrative_keeps_a_human_note_after_a_generated_one(tmp_path: Path):
    # The marker must scope to just the generated note, not the whole stage
    # block: a later human re-advance to the same stage appends its note to
    # the SAME piece (idempotent path), and must not be swallowed along with
    # the generated one that came before it (10188 follow-up item 2).
    j = _journal(tmp_path)
    j.create("D-0001", title="t")
    j.advance_stage("D-0001", "observe", note="MACHINETOKEN sync housekeeping", generated=True)
    j.advance_stage("D-0001", "observe", note="HUMANTOKEN analyst follow-up")
    entry = j.read("D-0001")
    out = narrative_text(entry.body)
    assert "MACHINETOKEN" not in out
    assert "HUMANTOKEN" in out


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


def test_narrative_excludes_template_static_prose_from_a_real_journal(tmp_path: Path):
    # r2 review, Important (blocking): round 1's per-line fill-state filter
    # replaced position-based filtering, but the template's plain-prose
    # section descriptions under Find/Observe/Refine/Govern/Evolve (e.g.
    # "Tune, deprecate, replace. Detections never finish — they iterate.")
    # aren't `- **Field:**` shaped, so nothing dropped them — and they're
    # byte-identical in every journal ADEF has ever created. A synthetic body
    # (as in the tests above) can't exercise this: it never contains that
    # prose. This test uses the REAL shipped template via `Journal.create`,
    # then simulates a user filling in one of the template's own prompts —
    # the ordinary way anyone would actually use it — to confirm the fix
    # doesn't overcorrect and drop real answers along with the boilerplate.
    j = _journal(tmp_path)
    j.create("D-0001", title="okta mfa bypass fatigue")
    path = tmp_path / "journals" / "D-0001.md"
    text = path.read_text(encoding="utf-8")
    assert "- **Hypothesis (one sentence):**" in text  # sanity: real template
    text = text.replace(
        "- **Hypothesis (one sentence):**",
        "- **Hypothesis (one sentence):** HYPOTOKEN attacker abuses mshta",
    )
    path.write_text(text, encoding="utf-8")
    entry = j.read("D-0001")

    out = narrative_text(entry.body)
    assert "deprecate" not in out.lower()
    assert "iterate" not in out.lower()
    assert "telemetry" not in out.lower()
    assert "HYPOTOKEN" in out


def test_narrative_keeps_a_wrapped_preamble_field_value(tmp_path: Path):
    # r3 review, Important: `_FIELD_LINE_RE` matches a single physical line,
    # so a filled field whose value wraps onto a second line was truncated —
    # only the first line was indexed. Hand-editing the markdown is the ONLY
    # way ADEF provides to fill a preamble field (no CLI command writes one),
    # and `docs/detection-home.md` tells users to treat the workspace as
    # plain markdown to edit directly, so a wrapped, multi-sentence answer is
    # ordinary usage, not an edge case. Built from the real template via
    # `Journal.create`, per the finding's test requirement.
    j = _journal(tmp_path)
    j.create("D-0001", title="t")
    path = tmp_path / "journals" / "D-0001.md"
    text = path.read_text(encoding="utf-8")
    assert "- **Hypothesis (one sentence):**" in text  # sanity: real template
    text = text.replace(
        "- **Hypothesis (one sentence):**",
        "- **Hypothesis (one sentence):** MULTILINELINE1 adversary abuses push\n"
        "  MULTILINELINE2 fatigue against privileged accounts",
    )
    path.write_text(text, encoding="utf-8")
    entry = j.read("D-0001")

    out = narrative_text(entry.body)
    assert "MULTILINELINE1" in out
    assert "MULTILINELINE2" in out


def test_narrative_drops_an_indented_continuation_of_an_unfilled_field(tmp_path: Path):
    # The continuation rule is provenance-based, not indentation-based alone:
    # an indented line only survives when it follows a field the user
    # demonstrably filled in. A line under an unfilled placeholder is still
    # template scaffolding — the field had no value, so nothing beneath it
    # is an answer either.
    j = _journal(tmp_path)
    j.create("D-0001", title="t")
    path = tmp_path / "journals" / "D-0001.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "- **Hypothesis (one sentence):**",
        "- **Hypothesis (one sentence):**\n"
        "  UNFILLEDCONTINUATION should not be indexed",
    )
    path.write_text(text, encoding="utf-8")
    entry = j.read("D-0001")

    out = narrative_text(entry.body)
    assert "UNFILLEDCONTINUATION" not in out


def test_narrative_keeps_a_blockquoted_stage_note():
    # A blockquote is the natural markdown for pasting intel or a customer
    # report into a journal's stage area — that's human reasoning, not the
    # machine-generated Refine text or preamble boilerplate the `>` rule was
    # meant to catch (it was inherited verbatim from the old
    # `_clean_for_snippet`, which only ever shaped snippets). Dropping the
    # whole line is an unstated recall regression; only the marker should go.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: observe\n\n"
        "> BLOCKQUOTETOKEN customer reported unusual mshta activity\n"
    )
    out = narrative_text(body)
    assert "BLOCKQUOTETOKEN" in out


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
