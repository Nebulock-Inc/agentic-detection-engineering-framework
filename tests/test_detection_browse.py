"""Tests for ``adef detection list`` / ``show``."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.detection import detection as detection_cli


@pytest.fixture
def ws(tmp_path, monkeypatch):
    import adef.commands.detection as det

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    # Rich defaults to 80 columns off a terminal, which is narrow enough that
    # the title column is a few characters wide — so a filter test asserting a
    # title is present would fail on layout, for no reason of its own. The
    # layout tests below set their own width explicitly.
    monkeypatch.setattr(det.console, "width", 120)
    return ws


@pytest.fixture
def catalogued(ws, tmp_path):
    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "sigma.yml").write_text(
        textwrap.dedent(
            """\
            title: Sigma windows rule
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1218.005]
            """
        ),
        encoding="utf-8",
    )
    (repo / "hunt.conf").write_text(
        "[Broad hunt]\nsearch = index=thrunt CommandLine=* | stats count\n",
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0
    return repo


def test_list_shows_all(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" in result.output
    assert "2 detection(s)" in result.output


def test_list_filters(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list", "--platform", "windows"])
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output

    result = CliRunner().invoke(detection_cli, ["list", "--rule-format", "spl"])
    assert "Broad hunt" in result.output
    assert "Sigma windows rule" not in result.output

    result = CliRunner().invoke(detection_cli, ["list", "--needs-review"])
    assert "Broad hunt" in result.output          # raw SPL: platform unknown
    assert "Sigma windows rule" not in result.output


def test_list_report_json(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list", "--report", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data) == 2
    ids = {d["id"] for d in data}
    assert ids == {"D-0001", "D-0002"}
    sigma = next(d for d in data if d["format"] == "sigma")
    assert sigma["mitre"] == ["T1218.005"]
    assert sigma["platform"] == "windows"


def test_list_empty_workspace(ws):
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0
    assert "No detections match" in result.output


def test_list_truncates_long_title_to_one_line(ws, tmp_path, monkeypatch):
    """A long title ellipsizes so each row stays on one line."""
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    long_title = "Suspicious mshta child process " * 6  # ~186 chars, far past budget
    (repo / "windows" / "long.yml").write_text(
        textwrap.dedent(
            f"""\
            title: {long_title.strip()}
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1218.005]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 100)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    row = next(ln for ln in result.output.splitlines() if "D-0001" in ln)
    assert len(row) <= 100
    assert row.rstrip().endswith("…")  # title was cut, not wrapped


def test_list_columns_size_to_data_so_short_rows_keep_their_title(
    ws, tmp_path, monkeypatch
):
    """Columns take their own widest value, not fixed constants.

    The old layout padded `format` to 22 and `platform` to 15 regardless of
    content, so the fixed columns ate 82 of 100 chars and a 40-char title was
    ellipsized to ~18. With data-driven widths this corpus's columns are short
    (`windows`, `sigma`), so the title must survive INTACT — asserting identity,
    not merely that the row fits.
    """
    import adef.commands.detection as det

    title = "Rundll32 execution without arguments"  # 36 chars: fits new, not old
    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "r.yml").write_text(
        textwrap.dedent(
            f"""\
            title: {title}
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1218.011]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 100)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    row = next(ln for ln in result.output.splitlines() if "D-0001" in ln)
    assert title in row, f"title was truncated by fixed-width columns: {row!r}"
    assert "…" not in row
    # A header row names the columns (previously there was none at all).
    header = result.output.splitlines()[0]
    assert "TITLE" in header and "ATT&CK" in header and "PLATFORM" in header


def test_list_caps_one_outlier_column_so_it_cannot_starve_the_title(
    ws, tmp_path, monkeypatch
):
    """A pathological value is capped at _MAX_COL_WIDTH, not given the whole row."""
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    # 12 techniques -> an ATT&CK cell ~110 chars wide if left uncapped.
    tags = ", ".join(f"attack.t10{n:02d}" for n in range(55, 67))
    (repo / "windows" / "many.yml").write_text(
        textwrap.dedent(
            f"""\
            title: Multi mapped rule
            id: 13cc0c25-389f-4bf8-b48d-11878079f1cb
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [{tags}]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 100)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    row = next(ln for ln in result.output.splitlines() if "D-0001" in ln)
    assert len(row) <= 100, f"outlier column overflowed the terminal: {row!r}"
    # The cap bit: the cell is ellipsized rather than printed in full.
    assert "…" in row
    assert "Multi mapped rule" in row, "the title lost its space to the ATT&CK column"


def test_list_row_stays_one_line_when_the_title_budget_is_tiny(
    ws, tmp_path, monkeypatch
):
    """A row with almost no title budget keeps its flag, on ONE line.

    Two failures, one row. First, the title was printed in full once the budget
    got small, and Rich soft-wrapped the overflow onto a second line, splitting
    it mid-word and leaving a two-line row in the middle of the table (seen for
    real on the bundled demo at an 80-col width):

        D-0001  find  draft  multi-platform  spl  -  Broad thrunt hunt -
        deliberate schema-check demo ⚠ no_platform

    Second — and worse — whatever the row did spend its last characters on had
    to be the flag, not the title: trimmed from the right (which is where Rich
    trims, and where the flag sits) the row reads as a detection with nothing
    wrong with it. The title is recoverable via `detection show`; a review flag
    that silently vanished is not.
    """
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    repo.mkdir(parents=True)
    # Raw SPL .conf → platform can't be inferred, so the row carries a
    # `⚠ no_platform` flag, which is what eats the title's budget.
    title = "Broad thrunt hunt - deliberate schema-check demo"
    (repo / "hunt.conf").write_text(
        f"[{title}]\nsearch = index=thrunt CommandLine=* | stats count\n",
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    # 80 cols: the columns plus the flag leave single digits for the title, so
    # the whole row depends on the flag being budgeted first and on `no_wrap`.
    monkeypatch.setattr(det.console, "width", 80)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output

    rows = [ln for ln in result.output.splitlines() if "D-0001" in ln]
    assert len(rows) == 1, f"row was split across lines: {result.output!r}"
    assert "no_platform" in rows[0], (
        f"the review flag was trimmed to make room for the title: {rows[0]!r}"
    )
    assert "…" in rows[0], f"the title should be the thing that gave way: {rows[0]!r}"
    # The continuation would have landed on the line after the row.
    after = result.output.splitlines()
    idx = after.index(rows[0])
    assert "schema-check" not in after[idx + 1], (
        f"title wrapped onto the next line: {after[idx + 1]!r}"
    )


def test_a_title_with_a_line_break_still_renders_as_one_row(ws, tmp_path, monkeypatch):
    """A newline in the title is not soft wrapping, so `no_wrap` doesn't stop it.

    YAML's `title: |` is ordinary authoring, and `cell_len` scores `\\n` as zero
    cells — so the title never counts against the budget, Rich honours the break
    regardless of `no_wrap`, and the review flag lands on a second line with
    nothing beside it saying which detection it belongs to. That second line is
    the defect: the flag is the part of the row asking you to act.

    Width is deliberately generous (200) so nothing is near the trimming
    budget — this is about the break, not about fitting.

    A `logsource` with no product/service/category, so the record carries
    `no_platform` — a *structural* review reason, which is what puts a flag on
    the row at all. Two wrong fixtures on the way here, both worth naming:
    `no_mitre` is not structural (it's a queue to drain, reported in the
    summary line), so asserting on it tests a flag the product never prints;
    and removing `logsource` outright makes the file unrecognizable as Sigma,
    so nothing is catalogued and the row under test does not exist.
    """
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "multi.yml").write_text(
        textwrap.dedent(
            """\
            title: |
              Suspicious mshta
              child process
            logsource:
                definition: 'inherited from the pipeline'
            detection:
                condition: selection
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 200)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output

    rows = [ln for ln in result.output.splitlines() if "D-0001" in ln]
    assert len(rows) == 1, f"row was split across lines: {result.output!r}"
    # Both halves of the title on the row the ID is on — a trailing `child
    # process` anywhere else means the break survived.
    assert "Suspicious mshta child process" in rows[0], rows[0]
    assert "no_platform" in rows[0], (
        f"the review flag was pushed off the row: {rows[0]!r}"
    )
    assert "child process" not in result.output.replace(rows[0], ""), (
        f"title continued onto another line: {result.output!r}"
    )


def test_list_columns_align_when_a_hand_edited_value_has_wide_glyphs(
    ws, catalogued, monkeypatch
):
    """Column padding is measured in display cells, not characters.

    Every value ADEF puts in a column is ASCII by construction, but `mitre` is
    a list humans edit in the record YAML. One double-width glyph padded with
    `str.ljust` leaves the column a cell short, and every column to its right —
    including the title — shifts on that row alone.
    """
    import adef.commands.detection as det
    from adef.commands._render import cell_width

    record = next((ws / "catalog").rglob("D-*.yml"))
    data = yaml.safe_load(record.read_text(encoding="utf-8"))
    data["mitre"] = ["ロググ"]  # 3 glyphs, 6 cells — not 3
    record.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    monkeypatch.setattr(det.console, "width", 200)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output

    rows = [ln for ln in result.output.splitlines() if ln.strip().startswith("D-")]
    assert len(rows) == 2, result.output
    # Both titles must begin at the same cell column — that's what "the columns
    # line up" means, and it's the thing a character-counted pad breaks.
    offsets = {
        cell_width(ln[: ln.index(title)])
        for ln in rows
        for title in ("Sigma windows rule", "Broad hunt")
        if title in ln
    }
    assert len(offsets) == 1, f"columns went ragged across rows: {rows!r}"


def test_list_header_stays_on_one_line_too(ws, catalogued, monkeypatch):
    """The header is built from the same data-driven widths as the rows.

    So it overflows at exactly the widths the rows do — and left to Rich it
    wrapped, putting a lone `TITLE` on its own line above a table whose rows
    were all correctly fitted. Fixing the rows and not the header left the
    output looking broken at the width the fix was for.
    """
    import adef.commands.detection as det

    monkeypatch.setattr(det.console, "width", 50)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output

    header = next(ln for ln in result.output.splitlines() if "STAGE" in ln)
    after = result.output.splitlines()
    nxt = after[after.index(header) + 1]
    assert "TITLE" not in nxt, f"the header wrapped onto a second line: {nxt!r}"


def test_list_keeps_the_flag_when_the_columns_alone_overflow_the_terminal(
    ws, tmp_path, monkeypatch
):
    """Six columns at their ceiling are wider than a narrow terminal by themselves.

    Reserving the flag out of the *title* budget isn't enough in that case: the
    title is already cut to nothing and the row is still over width, so Rich
    clips it — from the right, where the flag is. The columns have to be fitted
    alongside the title, which is why both are passed to `fit` as one string.

    A detection mapped to several techniques fills the ATT&CK column to its
    20-char cap, which with a 40-column terminal is this exact case.
    """
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    repo.mkdir(parents=True)
    (repo / "hunt.conf").write_text(
        "[Broad thrunt hunt]\nsearch = index=thrunt CommandLine=* | stats count\n",
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 40)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output

    rows = [ln for ln in result.output.splitlines() if "D-0001" in ln]
    assert len(rows) == 1, f"row was split across lines: {result.output!r}"
    assert "no_platform" in rows[0], (
        f"the review flag was clipped off a row that never fit: {rows[0]!r}"
    )


def test_fit_with_no_room_left_yields_a_cut_marker_not_a_negative_slice():
    """A budget of zero or less must still mean "cut here", not a wrong answer.

    The columns are capped but not free — on a terminal narrow enough that they
    plus the flag exceed its width, the title budget goes *negative*, and
    `value[:width - 1]` on a negative width silently slices from the END and
    returns most of the title. The row then runs past the terminal. The clamp
    is what makes the degenerate case render a bare `…` instead.
    """
    from adef.commands._render import fit

    assert fit("Suspicious mshta child process", 0) == "…"
    assert fit("Suspicious mshta child process", -12) == "…"
    assert fit("abc", 3) == "abc"  # exactly fits — not cut
    assert fit("abcdef", 4) == "abc…"
    # Measured in terminal cells, not characters: each of these glyphs is two
    # columns wide, so four of them already fill an 8-cell budget. Counting
    # characters would call six of them a fit and print a row twice its budget.
    # (The space is Rich padding a 7-cell budget that only takes 3 glyphs — the
    # point is the total, which is 8 cells either way.)
    assert fit("ロググロググ", 8) == "ロググ …"
    assert fit("ロググ", 6) == "ロググ"  # exactly fits — not cut
    # Line breaks collapse to spaces before measuring, so `fit`'s result is
    # always one line — and the collapsed space is part of the budget, which is
    # why 30 cells (not 29, the `cell_len` of the raw string) is the exact fit.
    # `set_cell_size` would otherwise leave the newline mid-string and return a
    # "trimmed" row that still breaks. U+000B and U+2028 are line boundaries
    # too, which is why this goes through `splitlines` rather than `\n`.
    assert fit("Suspicious mshta\nchild process", 30) == "Suspicious mshta child process"
    assert fit("Suspicious mshta\r\nchild process", 12) == "Suspicious …"
    assert fit("a\x0bb c", 10) == "a b c"


def test_show_renders_record_and_journal(ws, catalogued):
    listing = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma_id = next(d["id"] for d in listing if d["format"] == "sigma")
    result = CliRunner().invoke(detection_cli, ["show", sigma_id])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "T1218.005" in result.output
    assert "Query" in result.output
    assert "Journal" in result.output  # paired skeleton journal exists


def test_show_unknown_id_fails(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["show", "D-9999"])
    assert result.exit_code != 0
    assert "not found" in result.output


def test_stage_advance_unknown_id_errors_cleanly(ws, catalogued):
    # A bad/missing detection id must be a clean click error, not a raw
    # JournalError traceback (parity with `show`/`tag-mitre`). Covers all four
    # generated stage-advance commands.
    for stage in ("observe", "refine", "govern", "evolve"):
        result = CliRunner().invoke(detection_cli, [stage, "D-9999"])
        assert result.exit_code != 0, f"{stage}: {result.output}"
        assert "not found" in result.output.lower(), f"{stage}: {result.output}"


def test_tag_mitre_unknown_id_message_is_clean(ws, catalogued):
    # Missing detection → a clean message, not the single-quote-wrapped KeyError repr.
    result = CliRunner().invoke(detection_cli, ["tag-mitre", "D-8888", "T1059"])
    assert result.exit_code != 0, result.output
    assert "D-8888 is not in the catalog" in result.output
    assert "'D-8888" not in result.output  # no stray leading quote


def test_new_rejects_empty_title(ws):
    result = CliRunner().invoke(detection_cli, ["new", ""])
    assert result.exit_code != 0, result.output
    assert "empty" in result.output.lower()


def test_list_filter_engine(ws, catalogued):
    # Sigma folds to engine `sigma`; the .conf SPL rule folds to `sql`.
    result = CliRunner().invoke(detection_cli, ["list", "--engine", "sigma"])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output


def test_list_filter_tactic_display_name(ws, catalogued):
    # Tactic is derived from the technique ID (T1218.005); resolve the real
    # display name from the shipped snapshot rather than hardcoding a guess.
    from adef.core.attack import attack_reference

    tactics = attack_reference().tactics_for("T1218.005")
    assert tactics, "expected the shipped ATT&CK snapshot to know T1218.005"
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", tactics[0]])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output  # raw SPL has no MITRE → no tactic


def test_list_filter_tactic_shortname(ws, catalogued):
    # The shortname form (lowercased/hyphenated display name) matches too.
    from adef.core.attack import attack_reference

    shortname = attack_reference().tactics_for("T1218.005")[0].lower().replace(" ", "-")
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", shortname])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output


def test_list_tactic_no_match(ws, catalogued):
    # `impact` is a real tactic with no coverage here → clean empty, not an error.
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", "impact"])
    assert result.exit_code == 0, result.output
    assert "No detections match" in result.output


def test_list_rejects_unknown_filter_values(ws, catalogued):
    # A typo in a closed-set filter must error, not silently look like zero coverage.
    for args, needle in (
        (["list", "--engine", "bogus"], "unknown engine"),
        (["list", "--status", "nope"], "unknown status"),
        (["list", "--stage", "nope"], "unknown stage"),
        (["list", "--tactic", "not-a-tactic"], "unknown att&ck tactic"),
    ):
        result = CliRunner().invoke(detection_cli, args)
        assert result.exit_code != 0, f"{args}: {result.output}"
        assert needle in result.output.lower(), f"{args}: {result.output}"


def test_list_json_includes_engine_and_tactics(ws, catalogued):
    data = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma = next(d for d in data if d["format"] == "sigma")
    assert sigma["engine"] == "sigma"
    assert sigma["tactics"]  # derived from T1218.005
    spl = next(d for d in data if d["format"] == "spl")
    assert spl["tactics"] == []  # no MITRE → no tactics


def test_show_includes_tactics(ws, catalogued):
    # show should surface the tactic derived from the technique ID (T1218.005).
    from adef.core.attack import attack_reference

    listing = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma_id = next(d["id"] for d in listing if d["format"] == "sigma")
    tactic = attack_reference().tactics_for("T1218.005")[0]
    result = CliRunner().invoke(detection_cli, ["show", sigma_id])
    assert result.exit_code == 0, result.output
    assert "tactics" in result.output
    assert tactic in result.output


def test_show_flags_recognized_unsupported(ws):
    # A recognized-but-unsupported record (external logic, empty query) should
    # explain itself via a `support` line instead of silently omitting Query.
    from adef.core.catalog import Catalog, CatalogRecord

    rec = CatalogRecord(
        id="D-0001",
        title="External-logic rule",
        rule_ref="panther/x.yml",
        original_path="/tmp/panther/x.yml",
        platform="cloud-aws",
        kind="atomic",
        engine="composite",
        format="panther",
        support="recognized_unsupported",
        review_reasons=["external_logic"],
        needs_review=True,
    )
    Catalog(ws).write(rec)
    result = CliRunner().invoke(detection_cli, ["show", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "support" in result.output
    assert "recognized_unsupported" in result.output


def test_detection_new_uses_shared_id_space(ws, catalogued):
    """`detection new` must allocate from catalog+journals, not journals alone —
    else a catalog record whose journal is gone gets clobbered by a reused ID
    """
    from adef.core.catalog import Catalog

    # Diverge: remove the highest journal so catalog index (D-0002) > journal index.
    (ws / "journals" / "D-0002.md").unlink()
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    result = CliRunner().invoke(detection_cli, ["new", "Brand new authored rule"])
    assert result.exit_code == 0, result.output
    # No catalog record was clobbered; the new journal took a fresh id (D-0003),
    # not the reused D-0002.
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before
    assert Catalog(ws).find_record("D-0002")[1]["title"] == "Sigma windows rule" \
        or Catalog(ws).find_record("D-0002")[1]["id"] == "D-0002"
    assert (ws / "journals" / "D-0003.md").exists()


def test_search_finds_by_record_and_journal(ws, catalogued):
    """`detection search` matches catalog metadata (mitre/platform) AND journal
    notes — the durable-memory search seam."""
    # The Sigma rule carries T1218.005 in its record; its journal is a skeleton.
    # Search finds it by the record field alone (which id it got isn't the point).
    r = CliRunner().invoke(detection_cli, ["search", "T1218.005"])
    assert r.exit_code == 0, r.output
    assert "Sigma windows rule" in r.output   # found by the record's MITRE field

    # A journal note is searchable too — use a nonsense token so only the note matches.
    CliRunner().invoke(detection_cli, ["observe", "D-0001", "--note", "zzbeaconzz marker"])
    r2 = CliRunner().invoke(detection_cli, ["search", "zzbeaconzz"])
    assert "D-0001" in r2.output

    # No match → clean message, exit 0.
    r3 = CliRunner().invoke(detection_cli, ["search", "nomatchxyzzy"])
    assert r3.exit_code == 0 and "No detections match" in r3.output


def test_stage_advance_mirrors_onto_catalog_record(tmp_path, monkeypatch):
    """Lifecycle lives in the journal, but `list --stage` and the INDEX filter
    on the record — advancing must mirror the stage there (a detection
    advanced to observe while its record stayed at find)."""
    import yaml
    from click.testing import CliRunner

    from adef.commands.detection import detection as detection_cli

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    runner = CliRunner()

    # Authored record + journal via detection new (journal-only would have no record).
    schema_dir = ws / "schema"
    schema_dir.mkdir()
    (schema_dir / "src.yml").write_text(
        yaml.safe_dump(
            {"schema_version": 2, "source": "src", "platform": "network",
             "query_language": "spl", "scope": {"index": "x"},
             "fields": [{"name": "f", "type": "string", "description": "",
                          "values": [], "aliases": [], "provenance": "declared"}]}
        ),
        encoding="utf-8",
    )
    r = runner.invoke(detection_cli, ["new", "T", "--source", "src", "--workspace", str(ws)])
    assert r.exit_code == 0, r.output

    r = runner.invoke(detection_cli, ["observe", "D-0001", "--workspace", str(ws), "--note", "n"])
    assert r.exit_code == 0, r.output

    rec = next((ws / "catalog").rglob("D-0001*.yml"))
    data = yaml.safe_load(rec.read_text(encoding="utf-8"))
    assert data["stage"] == "observe"
    assert data["updated"] >= data["created"]

    # the browse filter reads the record — it must see the new stage
    r = runner.invoke(
        detection_cli, ["list", "--stage", "observe", "--workspace", str(ws)]
    )
    assert "D-0001" in r.output


def test_list_renders_an_upstream_title_literally(ws, tmp_path, monkeypatch):
    """Same markup hazard as `adef catalog --dry-run`, same escape.

    `highlight=False` only stops Rich styling its *own* guesses (numbers,
    paths); it does nothing about markup the title itself contains.
    """
    import adef.commands.detection as det

    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "markup.yml").write_text(
        textwrap.dedent(
            """\
            title: Dump [bold red]LSASS[/] memory
            id: 4f1d9b2e-8c7a-4e55-9f31-0a2b6c8d4e71
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1003.001]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    monkeypatch.setattr(det.console, "width", 120)
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    row = next(ln for ln in result.output.splitlines() if "D-0001" in ln)
    assert "[bold red]LSASS[/]" in row, f"markup was consumed, not printed: {row!r}"


def test_list_resolves_tactics_from_the_workspace_it_was_pointed_at(tmp_path, monkeypatch):
    """`--tactic` *omits* rows, so the wrong snapshot loses detections silently.

    `attack_reference()` read `$ADEF_WORKSPACE` alone, so with `--workspace`
    pointing somewhere else the tactic filter resolved against the *shipped*
    technique universe: a detection mapped to a technique added in the release
    the user had just refreshed into their workspace simply did not appear, and
    the unknown-tactic error cited the shipped snapshot's version. The two
    paths disagreeing is the whole point of the fixture — every other test in
    this file sets both to the same directory, which is why none of them could
    reach this.
    """
    from adef.core.catalog import Catalog, CatalogRecord

    real = tmp_path / "real"
    (real / "journals").mkdir(parents=True)
    (real / "attack").mkdir(parents=True)
    (real / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-test",
                "tactics": {"zzz-tactic": "Zzz Tactic"},
                "techniques": {"T9999": {"name": "Planted", "tactics": ["zzz-tactic"]}},
            }
        ),
        encoding="utf-8",
    )
    cat = Catalog(real)
    cat.write(
        CatalogRecord(
            id="D-0001", title="Planted technique rule", rule_ref="r/d1.yml",
            original_path="/tmp/d1.yml", platform="windows", kind="atomic",
            engine="sigma", format="sigma", mitre=["T9999"],
        )
    )
    cat.rebuild_index()

    decoy = tmp_path / "decoy"
    (decoy / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(decoy))

    result = CliRunner().invoke(
        detection_cli, ["list", "--tactic", "Zzz Tactic", "--workspace", str(real)]
    )

    assert result.exit_code == 0, result.output
    assert "1 detection(s)" in result.output, result.output


def test_show_resolves_tactics_from_the_workspace_it_was_pointed_at(tmp_path, monkeypatch):
    """`show`'s derived tactics, the display-only half of the same defect.

    Added because a mutation proved there was no test that could reach it:
    reverting `attack_reference(ws)` to `attack_reference()` here left every
    existing `show` test green, since they all set `$ADEF_WORKSPACE` to the
    same directory they pass to `--workspace`.
    """
    from adef.core.catalog import Catalog, CatalogRecord

    real = tmp_path / "real"
    (real / "journals").mkdir(parents=True)
    (real / "attack").mkdir(parents=True)
    (real / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-test",
                "tactics": {"zzz-tactic": "Zzz Tactic"},
                "techniques": {"T9999": {"name": "Planted", "tactics": ["zzz-tactic"]}},
            }
        ),
        encoding="utf-8",
    )
    Catalog(real).write(
        CatalogRecord(
            id="D-0001", title="Planted technique rule", rule_ref="r/d1.yml",
            original_path="/tmp/d1.yml", platform="windows", kind="atomic",
            engine="sigma", format="sigma", mitre=["T9999"],
        )
    )

    decoy = tmp_path / "decoy"
    (decoy / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(decoy))

    result = CliRunner().invoke(
        detection_cli, ["show", "D-0001", "--workspace", str(real)]
    )

    assert result.exit_code == 0, result.output
    assert "Zzz Tactic" in result.output, result.output
