"""Reading detection health back out — the half that closed the tuning loop.

Before this, `adef ingest` wrote five document kinds into `health/` and
nothing read them: `TuneRecommenderAgent` told the user to run `adef ingest`
and then reported `metrics seen: {}` / `insufficient-data` on the very numbers
they had just ingested.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.core.health_docs import HealthDoc, HealthDocError, isoify
from adef.core.health_store import (
    detections_with_health,
    read_latest,
    store_health_doc,
    tuning_metrics,
)

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)


def _doc(**row) -> HealthDoc:
    """A one-row `metrics` document over a 7-day window."""
    return HealthDoc(
        kind="metrics",
        schema_version=1,
        captured_at="2026-10-06T09:00:00Z",
        environment="prod",
        window={"start": "2026-09-29T00:00:00Z", "end": "2026-10-06T00:00:00Z"},
        detections=[{"detection_id": "D-0042", **row}],
    )


# --------------------------------------------------------------------------- #
# read_latest
# --------------------------------------------------------------------------- #
def test_read_latest_returns_what_store_wrote(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_doc(signal_count=143), root, known_ids={"D-0042"})

    latest = read_latest(root, "D-0042")
    assert set(latest) == {"metrics"}
    assert latest["metrics"]["signal_count"] == 143
    # The envelope travels with the row — without `window` the weekly
    # normalization below has no denominator.
    assert latest["metrics"]["window"]["end"] == "2026-10-06T00:00:00Z"


def test_read_latest_is_empty_when_nothing_was_ingested(tmp_path: Path):
    """Absence of health is the normal state for a freshly catalogued rule,
    so it is `{}` and not an error."""
    assert read_latest(tmp_path / "health", "D-0042") == {}
    assert detections_with_health(tmp_path / "health") == []


def test_read_latest_refuses_an_id_that_would_escape_the_health_dir(tmp_path: Path):
    """`detection_id` becomes a path component, and this is a public function
    reached from a CLI argument — so shape is re-validated on the read side
    too, exactly as `store_health_doc` does on the write side.

    The payload is planted where the traversal would actually land
    (`health/latest/../secret.yml` is `health/secret.yml`), so if the guard
    goes the test reads a real file rather than just failing to raise.
    """
    root = tmp_path / "health"
    (root / "latest").mkdir(parents=True)
    (root / "secret.yml").write_text("metrics: {signal_count: 1}\n", encoding="utf-8")

    with pytest.raises(HealthDocError, match="D-XXXX"):
        read_latest(root, "../secret")
    # Absolute paths too: `Path("a") / "/etc/passwd"` is `/etc/passwd`.
    with pytest.raises(HealthDocError, match="D-XXXX"):
        read_latest(root, "/etc/passwd")


def test_read_latest_drops_a_hand_edited_non_mapping_kind(tmp_path: Path):
    """Every consumer calls `.get()` on what comes back, so a scalar under a
    kind key would be an AttributeError three call sites away."""
    root = tmp_path / "health"
    (root / "latest").mkdir(parents=True)
    (root / "latest" / "D-0042.yml").write_text(
        "metrics: 42\nperformance:\n  run_count: 7\n", encoding="utf-8"
    )
    assert read_latest(root, "D-0042") == {"performance": {"run_count": 7}}


def test_detections_with_health_lists_sorted_ids(tmp_path: Path):
    root = tmp_path / "health"
    for det_id in ("D-0100", "D-0007", "D-0042"):
        doc = _doc(signal_count=1)
        doc.detections = [{"detection_id": det_id, "signal_count": 1}]
        store_health_doc(doc, root, known_ids={det_id})
    assert detections_with_health(root) == ["D-0007", "D-0042", "D-0100"]


# --------------------------------------------------------------------------- #
# tuning_metrics — the counts→ratios adapter
# --------------------------------------------------------------------------- #
def test_fp_ratio_divides_by_what_was_adjudicated_not_every_signal(tmp_path: Path):
    """Unlabeled signals are not known false positives.

    240 signals, 236 FP, 2 TP, 2 unlabeled: dividing by `signal_count` gives
    98.3%, by the labeled total 99.2%. The second is the honest number — the
    first reports the detection as cleaner than the labelling supports, and it
    gets *worse* the less the team triages.
    """
    root = tmp_path / "health"
    store_health_doc(
        _doc(
            signal_count=240,
            true_positive_count=2,
            false_positive_count=236,
            unlabeled_count=2,
        ),
        root,
        known_ids={"D-0042"},
    )
    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert metrics["fp_ratio"] == pytest.approx(236 / 238)
    assert metrics["fp_ratio"] != pytest.approx(236 / 240)


def test_weekly_volume_is_normalized_by_the_declared_window(tmp_path: Path):
    """A 28-day capture of 240 signals is 60/week, not 240.

    The window is *required* on a `metrics` document precisely so this is
    computable; reporting the raw count would read a monthly capture as four
    times the traffic it describes, straight into a volume threshold.
    """
    root = tmp_path / "health"
    doc = _doc(signal_count=240)
    doc.window = {"start": "2026-09-08T00:00:00Z", "end": "2026-10-06T00:00:00Z"}
    store_health_doc(doc, root, known_ids={"D-0042"})

    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert metrics["weekly_signal_volume"] == pytest.approx(60.0)


def test_days_since_true_positive_is_computed_at_read_time(tmp_path: Path):
    """Documents store the absolute `last_true_positive_at`; a stored "days
    since" would be wrong the moment it was written."""
    root = tmp_path / "health"
    store_health_doc(
        _doc(signal_count=1, last_true_positive_at="2026-06-08T12:00:00Z"),
        root,
        known_ids={"D-0042"},
    )
    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert metrics["days_since_true_positive"] == pytest.approx(121.0)


def test_a_lowercase_z_offset_still_parses():
    """ISO-8601 permits `z`, and `fromisoformat` rejects it on *every* version
    ADEF supports — so this is the case that proves the hand-translation runs.

    The uppercase `Z` path is only load-bearing on 3.10 (`fromisoformat`
    accepts `Z` natively from 3.11), which means no mutation can turn it red
    on a 3.13 dev venv. CI's matrix includes 3.10, so it is covered there;
    lowercase is what is verifiable here.
    """
    assert tuning_metrics(
        {"metrics": {"last_true_positive_at": "2026-06-08T12:00:00z"}}, now=NOW
    )["days_since_true_positive"] == pytest.approx(121.0)


def test_a_naive_timestamp_is_read_as_utc():
    """Every documented example is UTC, and the alternative is refusing to
    compute staleness because a producer omitted an offset."""
    assert tuning_metrics(
        {"metrics": {"last_true_positive_at": "2026-06-08T12:00:00"}}, now=NOW
    )["days_since_true_positive"] == pytest.approx(121.0)


def test_an_unparseable_timestamp_omits_staleness(tmp_path: Path):
    """Not a crash, and not a fabricated 0 days — which would read as "a true
    positive landed today" and suppress the deprecation arms entirely."""
    assert tuning_metrics({"metrics": {"last_true_positive_at": "last Tuesday"}}) == {}


def test_absent_counts_omit_their_key_rather_than_reporting_zero(tmp_path: Path):
    """Both consumers decide "insufficient data" on key *presence*.

    A fabricated `0.0` would read as a measured zero — the difference between
    "this detection is silent" and "nobody has told us anything about it".
    So a document carrying only a signal count must yield exactly one key.
    """
    root = tmp_path / "health"
    store_health_doc(_doc(signal_count=12), root, known_ids={"D-0042"})

    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert set(metrics) == {"weekly_signal_volume", "window_days"}
    assert "fp_ratio" not in metrics
    assert "days_since_true_positive" not in metrics


def test_nothing_adjudicated_omits_fp_ratio_even_though_the_counts_are_there():
    """0 FP and 0 TP out of 300 signals means **nobody triaged**, not "clean".

    This is the one case the `labeled > 0` guard exists for, and it is a
    separate reachability path from the test above: there, `false_positive_count`
    is absent and the outer `is not None` guard stops first. Mutating either
    guard alone leaves both green, because each covers for the other — so
    without this test the inner one is a declared constraint with no test.
    """
    assert (
        tuning_metrics(
            {
                "metrics": {
                    "signal_count": 300,
                    "false_positive_count": 0,
                    "true_positive_count": 0,
                }
            },
            now=NOW,
        )
        == {"weekly_signal_volume": 300.0}
    )


def test_zero_false_positives_is_a_measurement_and_is_reported(tmp_path: Path):
    """The flip side of the test above: 0 FP out of 40 labeled is an fp_ratio
    of 0.0 that must be *present*, or a clean detection is indistinguishable
    from an unmeasured one."""
    root = tmp_path / "health"
    store_health_doc(
        _doc(signal_count=40, true_positive_count=40, false_positive_count=0),
        root,
        known_ids={"D-0042"},
    )
    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert metrics["fp_ratio"] == 0.0


def test_junk_counts_are_treated_as_absent_not_coerced_to_zero(tmp_path: Path):
    """Rows are deliberately not field-whitelisted at ingest, so a producer
    can put a string, a null or a list where a count belongs."""
    assert tuning_metrics({"metrics": {"signal_count": "n/a"}}, now=NOW) == {}
    assert tuning_metrics({"metrics": {"false_positive_count": None}}, now=NOW) == {}
    assert tuning_metrics({"metrics": {"signal_count": [1, 2]}}, now=NOW) == {}
    # `True` is an int in Python; a boolean count is a producer error, not 1.
    assert tuning_metrics({"metrics": {"signal_count": True}}, now=NOW) == {}


def test_an_unreadable_window_keeps_the_raw_count(tmp_path: Path):
    """Dropping the signal entirely would turn a malformed window into
    "insufficient data"; the volume thresholds are order-of-magnitude, so the
    un-normalized count is the more useful degradation."""
    assert tuning_metrics(
        {"metrics": {"signal_count": 99, "window": {"start": "nope", "end": "also-nope"}}},
        now=NOW,
    ) == {"weekly_signal_volume": 99.0}
    # Inverted window (end before start) → no usable span, same fallback.
    assert tuning_metrics(
        {
            "metrics": {
                "signal_count": 99,
                "window": {"start": "2026-10-06T00:00:00Z", "end": "2026-09-29T00:00:00Z"},
            }
        },
        now=NOW,
    ) == {"weekly_signal_volume": 99.0}


def test_other_kinds_do_not_contribute_tuning_metrics():
    """`performance` and `deployment_drift` are stored under the same detection
    key; only `metrics` feeds the tuning heuristic.

    The payloads deliberately *collide* with the metrics field names. Rows are
    not whitelisted at ingest, so a producer may well carry a signal count
    alongside its runtime numbers — and with a non-colliding fixture
    (`run_count`/`failure_count` only) this test passes whichever kind the
    code reads, which is how it was first written.
    """
    assert (
        tuning_metrics(
            {
                "performance": {
                    "run_count": 168,
                    "signal_count": 9999,
                    "false_positive_count": 9999,
                    "last_true_positive_at": "2020-01-01T00:00:00Z",
                }
            },
            now=NOW,
        )
        == {}
    )
    # And the other way round: `metrics` present, so a sibling kind must not
    # be able to overwrite or add to what it derived.
    assert tuning_metrics(
        {
            "metrics": {"signal_count": 7},
            "deployment_drift": {"signal_count": 9999, "false_positive_count": 9999},
        },
        now=NOW,
    ) == {"weekly_signal_volume": 7.0}


# --------------------------------------------------------------------------- #
# The YAML-native timestamp bug, found by running `adef ingest` for real
# --------------------------------------------------------------------------- #
def test_an_unquoted_yaml_timestamp_is_accepted(tmp_path: Path):
    """`yaml.safe_load` resolves an unquoted `2026-10-06T09:00:00Z` to a
    `datetime`, and every timestamp in this format's own documented examples
    is unquoted — so a correct document was refused with `captured_at:
    required non-empty string (ISO-8601)`, which reads as "you left it out".
    """
    from adef.core.health_docs import lint_health_doc, load_health_doc

    path = tmp_path / "health.yml"
    path.write_text(
        textwrap.dedent(
            """\
            kind: metrics
            schema_version: 1
            captured_at: 2026-10-06T09:00:00Z
            environment: prod
            window:
              start: 2026-09-29T00:00:00Z
              end: 2026-10-06T00:00:00Z
            detections:
              - detection_id: D-0042
                signal_count: 240
                false_positive_count: 236
                true_positive_count: 2
                last_true_positive_at: 2026-06-08T12:00:00Z
            """
        ),
        encoding="utf-8",
    )
    # The raw parse is what lint used to see, and it does NOT validate.
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert not isinstance(raw["captured_at"], str)
    assert lint_health_doc(raw), "fixture no longer reproduces the datetime parse"

    doc = load_health_doc(path)
    assert doc.captured_at.startswith("2026-10-06T09:00:00")

    # And the normalized timestamps still reach the staleness arithmetic.
    root = tmp_path / "health"
    store_health_doc(doc, root, known_ids={"D-0042"})
    metrics = tuning_metrics(read_latest(root, "D-0042"), now=NOW)
    assert metrics["days_since_true_positive"] == pytest.approx(121.0)
    assert metrics["weekly_signal_volume"] == pytest.approx(240.0)


def test_isoify_leaves_everything_else_alone():
    """It runs over the whole document, so it must not rewrite rule content."""
    payload = {"a": "2026-10-06", "b": [1, None, "x"], "c": {"d": 2.5}}
    assert isoify(payload) == payload


# --------------------------------------------------------------------------- #
# End to end: the failure this whole change existed to fix
# --------------------------------------------------------------------------- #
@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A workspace with one catalogued detection, D-0001."""
    from adef.commands.catalog import catalog

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "mshta.yml").write_text(
        textwrap.dedent(
            """\
            title: Suspicious mshta child process
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                selection:
                    Image|endswith: '\\mshta.exe'
                condition: selection
            tags: [attack.t1218.005]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog, [str(repo)]).exit_code == 0
    return ws


def _ingest(ws: Path, **row) -> None:
    from adef.commands.ingest import ingest

    doc = ws / "capture.yml"
    doc.write_text(
        yaml.safe_dump(
            {
                "kind": "metrics",
                "schema_version": 1,
                "captured_at": "2026-10-06T09:00:00Z",
                "environment": "prod",
                "window": {
                    "start": "2026-09-29T00:00:00Z",
                    "end": "2026-10-06T00:00:00Z",
                },
                "detections": [{"detection_id": "D-0001", **row}],
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(ingest, [str(doc)])
    assert result.exit_code == 0, result.output
    assert "1 matched" in result.output


def test_evolve_turns_ingested_counts_into_a_high_severity_tuning_call(workspace):
    """The regression this change exists for.

    Ingesting 240 weekly signals at a 99% FP ratio used to produce
    `metrics seen: {}` and `insufficient-data`, because nothing read
    `health/`. It must now reach `narrow-filter` at `high`, and the numbers
    must be in the journal so the call is auditable later.
    """
    from adef.commands.detection import detection

    _ingest(
        workspace,
        signal_count=240,
        true_positive_count=2,
        false_positive_count=236,
        last_true_positive_at="2026-06-08T12:00:00Z",
    )

    result = CliRunner().invoke(detection, ["evolve", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "narrow-filter" in result.output
    assert "high" in result.output
    assert "insufficient-data" not in result.output

    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert "### Evolve / Health" in journal
    assert "### Evolve / Tuning" in journal
    assert "### Evolve / Deprecation" in journal
    # Scoped per block: `narrow-filter` must come from Tuning and the derived
    # numbers from Health, or the test passes on whichever block happens to
    # mention them (see `_block`).
    assert "narrow-filter" in _block(journal, "Evolve / Tuning")
    assert "fp_ratio" in _block(journal, "Evolve / Health")
    # The deprecation agent saw the same metrics, so it has something to judge.
    assert "insufficient_data" not in journal


def _block(journal: str, heading: str) -> str:
    """One `### <heading>` section, up to the next heading.

    Assertions about a chain step have to be scoped to *that step's* block:
    the tuning and deprecation agents write their own "run `adef ingest`"
    rationale, so an unscoped `in journal` check passes on another block's
    text and says nothing about the one the test names. Caught by mutation —
    gutting the Health block's message left this test green.
    """
    assert f"### {heading}" in journal, f"no {heading!r} block in journal"
    after = journal.split(f"### {heading}", 1)[1]
    return after.split("\n### ", 1)[0]


def test_evolve_with_no_ingested_health_says_so_and_names_the_command(workspace):
    """The most common state. `insufficient-data` without the remedy sends the
    user to the docs to find out what ADEF wanted from them."""
    from adef.commands.detection import detection

    result = CliRunner().invoke(detection, ["evolve", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "insufficient-data" in result.output

    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    health_block = _block(journal, "Evolve / Health")
    assert "No detection health ingested" in health_block
    assert "adef ingest" in health_block
    assert "adef detection evolve" in health_block


def test_evolve_note_does_not_append_a_second_recommendation_set(workspace):
    """Same gating as the Refine chain, for the reason Refine learned it:
    `refine --note` was appending a fresh agent-block triplet every time."""
    from adef.commands.detection import detection

    _ingest(workspace, signal_count=240, false_positive_count=236, true_positive_count=2)
    CliRunner().invoke(detection, ["evolve", "D-0001"])

    result = CliRunner().invoke(detection, ["evolve", "D-0001", "--note", "narrowed"])
    assert result.exit_code == 0, result.output
    assert "chain skipped" in result.output

    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert journal.count("### Evolve / Tuning") == 1

    # `--chain` is the re-run door, and the one that matters here: tuning is
    # iterative and `adef ingest` brings fresh numbers between runs.
    rerun = CliRunner().invoke(detection, ["evolve", "D-0001", "--chain"])
    assert rerun.exit_code == 0, rerun.output
    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert journal.count("### Evolve / Tuning") == 2


def test_evolve_chain_does_not_abort_when_one_step_fails(workspace, monkeypatch):
    """Partial results are valuable — the Refine chain's rule, applied here."""
    import adef.agents.tune_recommender as tune_mod
    from adef.commands.detection import detection

    class Exploding:
        def run(self, *a, **kw):
            raise RuntimeError("synthetic tuning failure")

    monkeypatch.setattr(tune_mod, "TuneRecommenderAgent", Exploding)
    _ingest(workspace, signal_count=240, false_positive_count=236, true_positive_count=2)

    result = CliRunner().invoke(detection, ["evolve", "D-0001"])
    assert result.exit_code == 0, result.output
    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert "synthetic tuning failure" in journal
    # Health ran before it and Deprecation after it — neither was lost.
    assert "### Evolve / Health" in journal
    assert "### Evolve / Deprecation" in journal
    assert "verdict:** tune" in journal
    # Non-aborting is not the same as silent: the blown-up step is named on
    # stdout too. This used to print an unconditional green "chain complete",
    # and the only on-screen trace of the failure was a missing suggestion
    # block — which is also what `insufficient-data` looks like.
    assert "tuning failed" in result.output, result.output
    assert "synthetic tuning failure" in result.output
    assert "Evolve chain complete" not in result.output


# --------------------------------------------------------------------------- #
# `adef health show`
# --------------------------------------------------------------------------- #
def test_health_show_summary_keeps_the_numbers_at_a_narrow_width(workspace, monkeypatch):
    """The derived numbers are the whole point of the row, so they get the
    width first and the columns give way — same ordering as the trailing
    review flag in `adef detection list`, which Rich otherwise trims off the
    right."""
    import adef.commands.health as health_mod
    from adef.commands.health import health

    _ingest(
        workspace,
        signal_count=240,
        true_positive_count=2,
        false_positive_count=236,
        last_true_positive_at="2026-06-08T12:00:00Z",
    )
    for width in (80, 40):
        monkeypatch.setattr(health_mod.console, "width", width)
        result = CliRunner().invoke(health, ["show"])
        assert result.exit_code == 0, result.output
        rows = [ln for ln in result.output.splitlines() if "D-0001" in ln]
        assert len(rows) == 1, f"row split at {width} cols: {result.output!r}"
        assert "fp 99%" in rows[0], f"at {width} cols the numbers were trimmed: {rows[0]!r}"
        assert "240/wk" in rows[0], rows[0]


def test_health_show_detail_reports_what_evolve_will_see(workspace):
    from adef.commands.health import health

    _ingest(workspace, signal_count=240, false_positive_count=236, true_positive_count=2)
    result = CliRunner().invoke(health, ["show", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "fp_ratio" in result.output
    assert "evolve" in result.output  # points at the command that acts on it


def test_nothing_derivable_does_not_blame_a_count_that_is_present(workspace):
    """An FP count with no TP count derives nothing — but it *is* present.

    `fp_ratio`'s denominator is what was adjudicated, so one of the two counts
    alone yields no key, and with no `signal_count` and no
    `last_true_positive_at` the derived set comes out empty. The message used
    to list the three field names flat ("no `signal_count`,
    `false_positive_count` or `last_true_positive_at`"), which sends the user
    hunting for a `false_positive_count` that is sitting in the document.
    """
    from adef.commands.health import health

    _ingest(workspace, false_positive_count=236)
    result = CliRunner().invoke(health, ["show", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "Nothing derivable" in result.output, result.output
    assert "fp_ratio" not in result.output  # genuinely not derivable
    # The fix: the pairing is what's named, not the absence of the FP count.
    assert "true_positive_count" in result.output, result.output
    # Caps because the wording is shared with the journal, so it carries no
    # markup — `[bold]`/`**` would be wrong in one of the two surfaces.
    assert "BOTH" in result.output, result.output


def test_the_evolve_journal_gives_the_same_nothing_derivable_wording(workspace):
    """The second renderer of the explanation above — and the one that was stale.

    `adef health show` and the Evolve chain's Health block both have to say why
    nothing was derived. When the "blames a count that is present" wording was
    corrected, only `health show` was touched; the journal kept listing the
    three fields flat for several rounds, and nothing covered it. That is the
    "declared constraint with no test" shape exactly: the fix was asserted on
    one surface and silently absent from the other.

    Asserts the pairing clause reaches the *journal*, not just the console —
    same input as its twin (an FP count with no TP count), so the only thing
    this adds is which renderer is being read.
    """
    from adef.commands.detection import detection

    _ingest(workspace, false_positive_count=236)
    result = CliRunner().invoke(detection, ["evolve", "D-0001"])
    assert result.exit_code == 0, result.output

    journal = (workspace / "journals" / "D-0001.md").read_text(encoding="utf-8")
    health_block = journal.split("### Evolve / Health", 1)[1].split("###", 1)[0]
    assert "derived for tuning:** none" in health_block, health_block
    assert "BOTH" in health_block, health_block
    assert "true_positive_count" in health_block, health_block
    # Markup-free in both directions: a Rich tag would be literal here, and
    # `**` inside the sentence would collide with the bold label around it.
    assert "[yellow]" not in health_block, health_block


def test_health_show_json_is_machine_readable(workspace):
    import json

    from adef.commands.health import health

    _ingest(workspace, signal_count=240, false_positive_count=236, true_positive_count=2)
    result = CliRunner().invoke(health, ["show", "--report", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["detections"][0]["detection_id"] == "D-0001"
    assert payload["detections"][0]["metrics"]["fp_ratio"] == pytest.approx(236 / 238)


def test_health_show_with_no_stored_health_points_at_the_unmatched_count(workspace):
    """Ingest skips rows naming a detection the catalog does not have, so "no
    health here" and "my document went nowhere" are the same symptom — and the
    second is the one the user needs told."""
    from adef.commands.health import health

    result = CliRunner().invoke(health, ["show", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "unmatched" in result.output


def test_health_show_rejects_a_malformed_detection_id(workspace):
    """Exit 1, not a traceback — the guard is in the core, and the command has
    to turn it into a CLI error."""
    from adef.commands.health import health

    result = CliRunner().invoke(health, ["show", "D-99"])
    assert result.exit_code == 1
    assert "D-XXXX" in result.output


# --------------------------------------------------------------------------- #
# Review-pass fixes. Each of these shipped broken in the first cut of this
# feature and was found by a review pass, not by the tests above.
# --------------------------------------------------------------------------- #
def test_a_false_positive_count_with_no_true_positive_count_omits_fp_ratio():
    """`fp_ratio: 1.0` — "100% false positives" — about a number nobody supplied.

    Row contents are deliberately not whitelisted at ingest, so a producer
    reporting FPs without TPs is a *valid* document, not a malformed one.
    Defaulting the absent TP to zero in the denominator asserted a measurement
    nobody made — the same fabricated zero the rest of this function refuses to
    emit, just moved one line down.
    """
    out = tuning_metrics({"metrics": {"signal_count": 240, "false_positive_count": 236}}, now=NOW)
    assert "fp_ratio" not in out
    assert out == {"weekly_signal_volume": 240.0}


def test_a_true_positive_count_with_no_false_positive_count_omits_fp_ratio():
    """The mirror case: the outer guard has to require both, in both directions."""
    assert "fp_ratio" not in tuning_metrics(
        {"metrics": {"true_positive_count": 4}}, now=NOW
    )


def test_a_negative_count_is_treated_as_absent():
    """Nothing can have happened a negative number of times, and the derived
    values go straight into thresholds.

    `false_positive_count: -5` against 10 TPs yields a plausible-looking
    `fp_ratio: -1.0`, and a negative `weekly_signal_volume` reads as quieter
    than silence — under the volume floor every deprecation arm checks.
    """
    out = tuning_metrics(
        {"metrics": {"signal_count": -240, "false_positive_count": -5, "true_positive_count": 10}},
        now=NOW,
    )
    assert out == {}
    # The *other* count still survives: one bad field doesn't void the row.
    assert tuning_metrics(
        {"metrics": {"signal_count": -1, "false_positive_count": 2, "true_positive_count": 2}},
        now=NOW,
    ) == {"fp_ratio": 0.5}


def _source_doc(ws: Path, name: str = "wineventlog") -> Path:
    doc = ws / "sources.yml"
    doc.write_text(
        yaml.safe_dump(
            {
                "kind": "source_health",
                "schema_version": 1,
                "captured_at": "2026-10-06T09:00:00Z",
                "environment": "prod",
                "window": {
                    "start": "2026-09-29T00:00:00Z",
                    "end": "2026-10-06T00:00:00Z",
                },
                "sources": [{"name": name, "ingest_lag_seconds": 45, "host_count": 1200}],
            }
        ),
        encoding="utf-8",
    )
    return doc


def test_source_keyed_health_is_visible_in_the_summary(workspace):
    """Two of the five kinds are keyed by telemetry source, not by `D-XXXX`.

    `adef health show` listed only `latest/`, so a user whose first capture was
    `source_health` — an ordinary place to start, since it needs no detection
    ids — was told "No ingested health" about files ingest had just written.
    """
    from adef.commands.health import health
    from adef.commands.ingest import ingest

    assert CliRunner().invoke(ingest, [str(_source_doc(workspace))]).exit_code == 0
    result = CliRunner().invoke(health, ["show"])
    assert result.exit_code == 0, result.output
    assert "wineventlog" in result.output
    assert "No ingested health" not in result.output


def test_source_detail_shows_the_stored_payload(workspace):
    from adef.commands.health import health
    from adef.commands.ingest import ingest

    assert CliRunner().invoke(ingest, [str(_source_doc(workspace))]).exit_code == 0
    result = CliRunner().invoke(health, ["show", "--source", "wineventlog"])
    assert result.exit_code == 0, result.output
    assert "ingest_lag_seconds" in result.output
    assert "1200" in result.output
    # The heading runs with markup off (the name is producer-supplied), so it
    # has to carry its emphasis as `style=` — an inline `[bold]` tag renders
    # literally there. Found by running the command, not by the assertions
    # above, which were all satisfied by the broken output.
    assert "[bold]" not in result.output


def test_source_detail_on_an_unstored_source_lists_what_is_stored(workspace):
    from adef.commands.health import health
    from adef.commands.ingest import ingest

    assert CliRunner().invoke(ingest, [str(_source_doc(workspace))]).exit_code == 0
    result = CliRunner().invoke(health, ["show", "--source", "[sysmon]"])
    assert result.exit_code == 0, result.output
    # The requested name is echoed back verbatim — brackets and all. It is
    # producer-supplied text reaching a Rich print, same class of bug as the
    # eaten query brackets above.
    assert "No ingested health for source '[sysmon]'" in result.output
    assert "wineventlog" in result.output  # names what IS there


def test_a_source_name_that_would_escape_the_health_dir_is_refused(tmp_path):
    """Source names are free-form producer labels, so `read_source` joins
    unvalidated text into a path. Same guard as `read_latest`'s, different
    shape — there is no regex to apply to a free-form name."""
    from adef.core.health_store import read_source

    root = tmp_path / "health"
    (root / "sources").mkdir(parents=True)
    (root / "secret.yml").write_text("source_health: {host_count: 1}\n", encoding="utf-8")
    with pytest.raises(HealthDocError, match="filename"):
        read_source(root, "../secret")
    with pytest.raises(HealthDocError, match="filename"):
        read_source(root, "/etc/passwd")


def test_show_refuses_a_detection_and_a_source_at_once(workspace):
    from adef.commands.health import health

    result = CliRunner().invoke(health, ["show", "D-0001", "--source", "wineventlog"])
    assert result.exit_code != 0
    assert "not both" in result.output


def test_newest_capture_compares_instants_not_strings():
    """`2026-10-06T09:00:00+05:00` sorts above `2026-10-06T06:00:00Z`
    lexicographically and is three hours *earlier*.

    Offsets are producer-supplied, so a stack reporting in local time made the
    listing name the wrong document as the newest thing known about a
    detection — which is the entire meaning of that column.
    """
    from adef.commands.health import _newest_capture

    stored = {
        "metrics": {"captured_at": "2026-10-06T09:00:00+05:00"},  # 04:00Z
        "performance": {"captured_at": "2026-10-06T06:00:00Z"},
    }
    assert _newest_capture(stored) == "2026-10-06T06:00:00Z"


def test_newest_capture_ignores_an_unparseable_timestamp():
    """A producer string that isn't a timestamp must not win "newest" by
    sorting high — `zzz` beats every real ISO-8601 string lexicographically."""
    from adef.commands.health import _newest_capture

    assert (
        _newest_capture(
            {
                "metrics": {"captured_at": "zzz-not-a-date"},
                "performance": {"captured_at": "2026-10-06T06:00:00Z"},
            }
        )
        == "2026-10-06T06:00:00Z"
    )
    # Nothing parseable at all still returns something rather than crashing.
    assert _newest_capture({"metrics": {"captured_at": "zzz"}}) == "zzz"
    assert _newest_capture({"metrics": {}}) == ""


def test_a_stored_query_keeps_its_brackets_through_the_detail_view(workspace):
    """Rich reads `[...]` as markup and silently deletes what it doesn't know.

    A `deployed_query` is detection logic, and every query language ADEF
    handles is full of brackets — `regex: 'a[0-9]{3}'`, `[dbo].[events]`. The
    one place a user reads a query to check what is actually deployed is
    exactly where the characters were being eaten.
    """
    from adef.commands.health import health
    from adef.commands.ingest import ingest

    doc = workspace / "drift.yml"
    doc.write_text(
        yaml.safe_dump(
            {
                "kind": "deployment_drift",
                "schema_version": 1,
                "captured_at": "2026-10-06T09:00:00Z",
                "environment": "prod",
                "detections": [
                    {
                        "detection_id": "D-0001",
                        "deployed_query": "SELECT * FROM [dbo].[events] WHERE re='a[0-9]{3}'",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(ingest, [str(doc)]).exit_code == 0
    result = CliRunner().invoke(health, ["show", "D-0001"], terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "[dbo].[events]" in result.output
    assert "a[0-9]{3}" in result.output
