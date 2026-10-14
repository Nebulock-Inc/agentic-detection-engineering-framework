"""`adef health` — read back what `adef ingest` stored.

The counterpart to ingestion. Without a read command the five capture kinds
land in ``health/`` with no way to see them short of opening the YAML, and
"did my document actually land on the detection I meant?" has no answer.

A group rather than a bare command on purpose: ``show`` is the raw readback,
and a coverage-peer *report* (decaying / drifted /
telemetry gaps / never-fired / failing runs) is a different question over the
same files. It belongs beside this as ``adef health report``, not folded into
it behind flags.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.markup import escape

from adef.commands._render import cell_width as _cell_width
from adef.commands._render import fit as _fit
from adef.commands._render import pad as _pad
from adef.core.health_docs import HealthDocError
from adef.core.health_store import (
    NOTHING_DERIVABLE,
    detections_with_health,
    health_dir,
    parse_iso,
    read_latest,
    read_source,
    sources_with_health,
    tuning_metrics,
)

console = Console()

# Sorts an unparseable `captured_at` below every real one. A producer-supplied
# string that isn't a timestamp should not be able to win "newest".
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)

_WORKSPACE_OPTION = click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).",
)


@click.group()
def health() -> None:
    """Inspect ingested detection health."""


def _newest_capture(stored: dict[str, dict]) -> str:
    """The latest ``captured_at`` across kinds — "how stale is anything I know
    about this?", which is the question a listing answers.

    Ordered by parsed instant, not by string. Lexicographically
    ``2026-10-06T09:00:00+05:00`` sorts above the genuinely later
    ``2026-10-06T06:00:00Z``, so a string comparison names the wrong document
    as newest — and offsets are producer-supplied, so UTC isn't guaranteed.
    The raw text breaks ties so the pick stays deterministic.
    """
    captured = [
        str(payload["captured_at"])
        for payload in stored.values()
        if payload.get("captured_at")
    ]
    return max(captured, key=lambda text: (parse_iso(text) or _UNDATED, text), default="")


def _summary_row(det_id: str, latest: dict[str, dict]) -> dict[str, Any]:
    return {
        "detection_id": det_id,
        "kinds": sorted(latest),
        "captured_at": _newest_capture(latest),
        "metrics": tuning_metrics(latest),
    }


def _compact_health(metrics: dict[str, float]) -> str:
    """The derived metrics as a row-sized phrase: ``fp 99%  240/wk  121d``.

    Spelling the keys out (``fp_ratio=0.9916, weekly_signal_volume=240, …``)
    is 60-odd cells and does not fit beside the other columns on an 80-column
    terminal, so the one part of the row worth scanning was the part that got
    ellipsized away.
    """
    parts = []
    if "fp_ratio" in metrics:
        parts.append(f"fp {metrics['fp_ratio']:.0%}")
    if "weekly_signal_volume" in metrics:
        parts.append(f"{metrics['weekly_signal_volume']:,.0f}/wk")
    if "days_since_true_positive" in metrics:
        parts.append(f"{metrics['days_since_true_positive']:.0f}d since TP")
    return "  ".join(parts) or "—"


# Columns before the derived phrase. Narrow on purpose: the detail view
# (`adef health show D-XXXX`) is one command away, and the whole value of the
# listing is seeing the numbers side by side.
_SUMMARY_WIDTHS = (("ID", 8), ("CAPTURED", 10), ("KINDS", 24))


def _print_summary(rows: list[dict[str, Any]]) -> None:
    console.print(f"[bold]{len(rows)} detection(s) with ingested health[/bold]\n")

    def _line(values: list[str], tail: str) -> str:
        # The derived numbers get the width first and the columns give way,
        # same ordering (and same reason) as the trailing review flag in
        # `adef detection list`: the three columns are recoverable from the
        # detail view, and a row whose health phrase was trimmed off the right
        # is a row with nothing to say. Above ~50 cells the prefix always fits
        # whole, so the tail still lines up.
        cols = "  ".join(_pad(v, w) for v, (_, w) in zip(values, _SUMMARY_WIDTHS))
        return _fit(f"  {cols}  ", console.width - _cell_width(tail)) + tail

    console.print(
        _line([name for name, _ in _SUMMARY_WIDTHS], "HEALTH"),
        style="dim",
        highlight=False,
        no_wrap=True,
        overflow="ellipsis",
    )
    for row in rows:
        console.print(
            _line(
                [
                    row["detection_id"],
                    # Date only: staleness at day granularity is what a
                    # listing answers, and the full timestamp cost 10 cells
                    # that the derived numbers needed.
                    (row["captured_at"] or "—")[:10],
                    ", ".join(row["kinds"]),
                ],
                _compact_health(row["metrics"]),
            ),
            # `captured_at` is a producer-supplied string, so it reaches here
            # unvalidated — never read it as Rich markup.
            markup=False,
            highlight=False,
            no_wrap=True,
            overflow="ellipsis",
        )


def _print_sources(sources: dict[str, dict[str, dict]]) -> None:
    """The source-keyed half of the summary.

    ``source_health`` and ``field_observations`` are keyed by a free-form
    telemetry source name, not a ``D-XXXX``, so they never appear in the
    detection listing. Without this a user who ingested those two kinds — a
    perfectly ordinary first capture — was told "No ingested health".
    """
    console.print(f"\n[bold]{len(sources)} telemetry source(s) with ingested health[/bold]\n")
    for name in sorted(sources):
        stored = sources[name]
        console.print(
            _fit(
                f"  {_pad(name, 28)}  {(_newest_capture(stored) or '—')[:10]}  "
                f"{', '.join(sorted(stored))}",
                console.width,
            ),
            # Source names come from the producer's document, so never read
            # them as Rich markup.
            markup=False,
            highlight=False,
            no_wrap=True,
            overflow="ellipsis",
        )
    console.print(
        "\nInspect one with [bold]adef health show --source <name>[/bold]."
    )


def _print_kinds(stored: dict[str, dict]) -> None:
    for kind in sorted(stored):
        console.print(f"[cyan]{escape(str(kind))}[/cyan]")
        # Dumped rather than hand-rendered: row contents are deliberately not
        # whitelisted at ingest (a producer may carry extra context alongside
        # the documented fields), so there is no fixed field list to render.
        #
        # `markup=False`: a stored `deployed_query` is detection logic, and
        # Sigma/SQL/KQL are full of square brackets (`regex: 'a[0-9]{3}'`,
        # `[dbo].[events]`). Rich would read those as style tags and silently
        # delete them from the output — the one place a user is reading a query
        # to check what was deployed.
        console.print(
            yaml.safe_dump(stored[kind], sort_keys=True, default_flow_style=False).rstrip(),
            markup=False,
            highlight=False,
        )
        console.print()


@health.command("show")
@click.argument("detection_id", required=False)
@click.option(
    "--source",
    "source_name",
    default=None,
    help="Show stored health for a telemetry source instead of a detection.",
)
@_WORKSPACE_OPTION
@click.option(
    "--report",
    type=click.Choice(["json"]),
    default=None,
    help="Machine-readable output instead of the terminal rendering.",
)
def show(
    detection_id: str | None,
    source_name: str | None,
    workspace: Path | None,
    report: str | None,
) -> None:
    """Show ingested health — for DETECTION_ID, or a summary of everything stored.

    A separate `--source` rather than overloading DETECTION_ID: source names
    are free-form producer labels, so there is no shape to dispatch on without
    guessing which namespace the user meant.
    """
    root = health_dir(workspace)
    if detection_id and source_name:
        raise click.UsageError("Give either DETECTION_ID or --source, not both.")

    if source_name is not None:
        try:
            stored = read_source(root, source_name)
        except HealthDocError as exc:
            raise click.ClickException(str(exc)) from exc
        if report == "json":
            click.echo(
                json.dumps(
                    {"source": source_name, "latest": stored},
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
            )
            return
        if not stored:
            known = sources_with_health(root)
            hint = f" Stored sources: {', '.join(known)}." if known else ""
            # Both the requested name and the stored ones are producer-supplied.
            console.print(
                f"No ingested health for source {source_name!r}.{hint}", markup=False
            )
            return
        # `style=` rather than inline tags: the name is producer-supplied, so
        # this print runs with markup off and a `[bold]` tag would be rendered
        # literally instead of applied.
        console.print(
            f"{source_name} — ingested source health\n", style="bold", markup=False
        )
        _print_kinds(stored)
        return

    if detection_id is None:
        try:
            rows = [
                _summary_row(det_id, read_latest(root, det_id))
                for det_id in detections_with_health(root)
            ]
            sources = {name: read_source(root, name) for name in sources_with_health(root)}
        except HealthDocError as exc:
            raise click.ClickException(str(exc)) from exc
        if report == "json":
            click.echo(
                json.dumps(
                    {"detections": rows, "sources": sources},
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
            )
            return
        if not rows and not sources:
            console.print(
                f"No ingested health under {escape(str(root))}. Capture your platform's numbers "
                "into a health document and run [bold]adef ingest <document>[/bold]."
            )
            return
        if rows:
            _print_summary(rows)
        if sources:
            _print_sources(sources)
        return

    try:
        latest = read_latest(root, detection_id)
    except HealthDocError as exc:
        raise click.ClickException(str(exc)) from exc

    metrics = tuning_metrics(latest)
    if report == "json":
        click.echo(
            json.dumps(
                {"detection_id": detection_id, "latest": latest, "metrics": metrics},
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
        return

    if not latest:
        console.print(
            f"No ingested health for [bold]{detection_id}[/bold]. Note that ingest "
            "skips rows naming a detection the catalog does not have — re-run "
            "[bold]adef ingest[/bold] and check its unmatched count."
        )
        return

    console.print(f"[bold]{detection_id}[/bold] — ingested health\n")
    _print_kinds(latest)

    if metrics:
        console.print("[bold]derived for tuning[/bold]")
        for key, value in sorted(metrics.items()):
            console.print(f"  {escape(str(key))}: {value:.4g}")
        console.print(
            "\nRun [bold]adef detection evolve "
            f"{detection_id} --chain[/bold] to turn these into tuning and "
            "deprecation recommendations."
        )
    else:
        # Wording lives in `health_store` beside the rules it describes — the
        # Evolve chain's Health block prints the same explanation, and when this
        # one was corrected that one was missed.
        console.print(f"[yellow]Nothing derivable for tuning[/yellow] — {NOTHING_DERIVABLE}")


__all__ = ["health"]
