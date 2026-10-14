"""Workspace self-check — "is this thing actually wired up?".

Every piece of state ADEF depends on is a file in the workspace, and each
command only tells you about the part it needs: `adef detection list` is silent
about a stale INDEX, `adef coverage` is silent about an un-ingested schema, and
`adef detection evolve` says `insufficient-data` whether you never ingested
health or ingested it under a detection ID the catalog doesn't have. A user
with a half-wired workspace gets a plausible-looking empty answer from each
command separately and no way to see the cause.

Pure, like `core/coverage.py`: returns `Check` records and renders nothing, so
rendering and the exit code live in `commands/doctor.py` and a second caller
can reuse the model. The one import from `commands/` is a deferred read of
`install_skills.AGENT_DIRS` — the destinations that command computes, kept in
one place rather than re-spelled here.

Read-only by construction — nothing here creates a directory. `Catalog` is
only constructed once `catalog/` is known to exist, because its `__init__`
mkdirs, and `adef doctor` run in the wrong directory must not leave a workspace
skeleton behind.
"""

from __future__ import annotations

import shlex

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from adef.core.catalog import Catalog, catalog_dir
from adef.core.health_store import detections_with_health, sources_with_health
from adef.core.workspace import DEFAULT_WORKSPACE, config_path, resolve_workspace

Status = Literal["ok", "warn", "problem"]

#: Checks that gate the exit code. A `warn` is an un-wired *optional*
#: capability — no schemas declared, no health ingested — which is the normal
#: state of a workspace on day one and must not fail a CI gate someone wired
#: `adef doctor` into. A `problem` is state that makes another command lie:
#: a missing workspace, an unparseable record, a stale INDEX.
PROBLEM: Status = "problem"


@dataclass(frozen=True)
class Check:
    """One answered question about the workspace.

    ``fix`` is the literal command to run, not prose: the whole point of the
    command is that the user shouldn't have to go find out which of ADEF's
    seventeen subcommands repairs what they're looking at.
    """

    name: str
    status: Status
    detail: str
    fix: str = ""


_DIST = "agentic-detection-engineering-framework"


def editable_install() -> bool:
    """Was ADEF installed with `pip install -e` (PEP 610 `direct_url.json`)?"""
    import json
    from importlib.metadata import PackageNotFoundError, distribution

    try:
        raw = distribution(_DIST).read_text("direct_url.json")
    except PackageNotFoundError:
        return False
    try:
        return bool(raw and json.loads(raw).get("dir_info", {}).get("editable"))
    except (ValueError, AttributeError):
        return False


def mcp_install_hint() -> str:
    """How to add the `[mcp]` extra *to this install*. A clone's editable
    install must stay editable — the PyPI form would swap it for the wheel."""
    return 'pip install -e ".[mcp]"' if editable_install() else f"pip install '{_DIST}[mcp]'"


def mcp_installed() -> bool:
    """Is the `[mcp]` extra installed? Checks the import `adef/mcp/server.py`
    actually makes — the `mcp` SDK's bundled FastMCP, not the separate
    `fastmcp` PyPI package."""
    try:
        import mcp.server.fastmcp  # noqa: F401
    except ImportError:
        return False
    return True


def _skills_dirs() -> list[Path]:
    """Every place `adef install-skills` could have written, project then user.

    Mirrors the command's own destination arithmetic (`base / AGENT_DIRS[agent]
    / "skills"`, base being cwd or home) rather than guessing: a skill
    installed for Codex into `.agents/` is just as installed as one in
    `.claude/`, and reporting "none found" to someone who chose Codex would be
    worse than not checking at all.
    """
    from adef.commands.install_skills import AGENT_DIRS

    return [
        base / agent_dir / "skills"
        for base in (Path.cwd(), Path.home())
        # dict order would report `.agents` twice (codex and its chatgpt alias).
        for agent_dir in sorted(set(AGENT_DIRS.values()))
    ]


def _check_workspace(ws: Path) -> Check:
    if not ws.is_dir():
        return Check(
            "workspace",
            PROBLEM,
            f"nothing at {ws}",
            "adef init" if ws == DEFAULT_WORKSPACE else f"adef init {ws}",
        )
    # Not "does the dir exist" but "does it look scaffolded": `resolve_workspace`
    # falls back to the current directory, so a `adef doctor` in any random repo
    # resolves to a real, existing, entirely un-ADEF directory. Reporting that as
    # a healthy workspace is the one failure mode that makes every check below
    # meaningless.
    missing = [name for name in ("journals", "catalog") if not (ws / name).is_dir()]
    if missing:
        return Check(
            "workspace",
            PROBLEM,
            f"{ws} is missing {', '.join(f'{m}/' for m in missing)} — "
            "not an ADEF workspace",
            f"adef init {ws}",
        )
    # Named from `config_path`, not retyped: the file is `.adefconfig.yaml`
    # (leading dot), and the message said `adefconfig.yaml` — so a user who
    # followed it would `ls config/`, see nothing, and conclude the file was
    # missing when it was only hidden.
    cfg = config_path(ws)
    configured = "configured" if cfg.is_file() else f"no config/{cfg.name}"
    return Check("workspace", "ok", f"{ws} ({configured})")


def _check_catalog(ws: Path) -> tuple[Check, Catalog]:
    """Record count, plus the one `Catalog` the later checks share.

    Safe to construct here and nowhere earlier: `Catalog.__init__` mkdirs its
    directory, and `_check_workspace` has already made a missing `catalog/` a
    `problem` that stops `run_checks` — so by this line the directory exists
    and the constructor's mkdir is a no-op. That ordering is what keeps
    `adef doctor` from scaffolding a workspace into an unrelated directory.
    """
    cat_dir = catalog_dir(ws)
    catalog = Catalog(ws)
    records = list(catalog.iter_records())
    # `iter_records` swallows a record it cannot turn into data and moves on —
    # correct for every other consumer (one hand-edited record shouldn't blank a
    # whole listing) and invisible everywhere. Diffing the paths it yielded
    # against the files on disk is the only place that silence surfaces.
    parsed = {path for _, path, _ in records}
    unreadable = sorted(p for p in cat_dir.rglob("D-*.yml") if p not in parsed)
    if unreadable:
        # The files by name, not a `fix` command: there is no command that
        # repairs hand-broken YAML, and the one thing the user needs is which
        # file to open.
        shown = ", ".join(p.name for p in unreadable[:3])
        return (
            Check(
                "catalog",
                PROBLEM,
                f"{len(records)} record(s); {len(unreadable)} unreadable (not "
                f"parseable YAML), silently skipped by every command: {shown}"
                + ("…" if len(unreadable) > 3 else ""),
            ),
            catalog,
        )
    if not records:
        return (
            Check(
                "catalog",
                "warn",
                "catalog/ is empty — no detections to report on",
                "adef catalog /path/to/rules",
            ),
            catalog,
        )
    return Check("catalog", "ok", f"{len(records)} record(s)"), catalog


def _check_index(catalog: Catalog) -> Check:
    """Compare the stored INDEX against the one the records imply.

    An exact comparison, not an ID-set or mtime one, because the failure that
    matters leaves every filename untouched: edit a record's `mitre` (which is
    exactly what `adef detection tag-mitre` and a human both do) and
    `by_technique`/`by_tactic` go wrong while the detection list stays
    identical. `adef coverage` and `--tactic` read the INDEX, so they answer
    confidently from stale data.
    """
    index_path = catalog.directory / "INDEX.yml"
    if not index_path.is_file():
        # A freshly `adef init`ed workspace has no INDEX because it has no
        # records, and `adef init` is the one command that should never leave
        # you with a problem to fix. Only a *populated* catalog owes an INDEX.
        #
        # `iter_records`, not `build_index`: the question is only "are there
        # records", and building the index reads the ATT&CK snapshot to resolve
        # `by_tactic`. Asking the expensive question made this branch depend on
        # a file it has no use for — a corrupt snapshot turned a brand-new
        # empty workspace into a `problem`, which is the one thing the comment
        # above says must never happen.
        if next(catalog.iter_records(), None) is None:
            return Check("index", "ok", "no records yet, nothing to index")
        return Check("index", PROBLEM, "catalog/INDEX.yml is missing", "adef reindex")
    try:
        stored = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        return Check("index", PROBLEM, f"INDEX.yml unreadable ({exc})", "adef reindex")
    # Valid YAML that isn't a mapping — a hand-edited INDEX left as a list, or
    # truncated to a scalar. It reads cleanly, so the `except` above doesn't
    # see it, and then `.get` on a list raised `AttributeError` *through* the
    # command: `adef doctor` died with a traceback on precisely the broken
    # workspace it exists to report. An empty file (`stored is None`) is a
    # different thing and still goes down the staleness path, which names it.
    if stored is not None and not isinstance(stored, dict):
        return Check(
            "index",
            PROBLEM,
            f"INDEX.yml is not a mapping (got {type(stored).__name__})",
            "adef reindex",
        )
    # Guarded, and only here — this is the one part that genuinely needs the
    # expected INDEX built. `build_index` raised `JSONDecodeError` out of this
    # check on a truncated `attack/enterprise.json`, from one check *before*
    # `_check_attack`, the one that reports that file properly. Letting it
    # propagate is right for `adef reindex`, which would otherwise *write* an
    # INDEX with every tactic silently dropped; it is wrong here, where the
    # whole point is to survive the state being diagnosed.
    #
    # The message names the operation, not a cause, because the catch cannot
    # know the cause: `build_index` also groups by `engine`, `status` and
    # `data_source`, so a hand-edited `engine: [sigma]` raises an
    # unhashable-key `TypeError` with no ATT&CK involvement at all. (Message
    # paraphrased, not quoted: `# type:` opening a comment line is a type
    # comment to mypy.) Blaming the snapshot
    # printed `→ adef attack refresh` four lines above `att&ck ✓ ok` — a
    # self-contradicting report prescribing a command that cannot help.
    #
    # And no `fix` at all, the same call `_check_catalog` makes for a record no
    # command can parse: whatever stopped `build_index` here stops it inside
    # `adef reindex` too, so prescribing that would hand the user a command
    # that dies on the same exception. The exception text *is* the lead — it
    # names the snapshot or the unhashable value — and the stale branch below
    # still prescribes `adef reindex`, which works, because there the build
    # succeeded.
    try:
        expected = catalog.build_index()
    except Exception as exc:  # noqa: BLE001 — doctor must survive what it diagnoses
        return Check(
            "index",
            PROBLEM,
            f"cannot be verified — building the expected INDEX raised ({exc}); "
            "`adef reindex` fails on this too until the cause is fixed",
        )
    if stored != expected:
        differing = sorted(
            key
            for key in set(expected) | set(stored or {})
            if (stored or {}).get(key) != expected.get(key)
        )
        return Check(
            "index",
            PROBLEM,
            f"INDEX.yml is stale — differs in: {', '.join(differing)}",
            "adef reindex",
        )
    return Check("index", "ok", f"{len(expected.get('detections') or {})} detection(s) indexed")


def _check_journals(ws: Path, catalog: Catalog) -> Check:
    # Top level only: `Journal` reads and writes `journals/D-XXXX.md` and
    # nothing else, so a journal in a subdirectory is one no command can open.
    # It is still reserved in the ID space (`journals_max_index` recurses), so
    # flag it rather than count it as either paired or missing.
    journals = ws / "journals"
    journal_ids = {p.stem for p in journals.glob("D-*.md")}
    nested = sorted(p for p in journals.rglob("D-*.md") if p.parent != journals)
    movable = [p for p in nested if p.stem not in journal_ids]
    clashing = [p for p in nested if p.stem in journal_ids]
    record_ids = {det_id for det_id, _, _ in catalog.iter_records()}
    unpaired = sorted(record_ids - journal_ids - {p.stem for p in movable})

    def names(items: list[str]) -> str:
        return f"{', '.join(items[:5])}{'…' if len(items) > 5 else ''}"

    problems: list[str] = []
    fix = ""
    if movable:
        problems.append(
            f"{len(movable)} journal(s) in a subdirectory, which ADEF does not read "
            f"({names([str(p.relative_to(journals)) for p in movable])})"
        )
        # Absolute paths: doctor may be run from anywhere against the default
        # workspace. `-n` is belt and braces — clashes are excluded above.
        fix = f"mv -n {' '.join(shlex.quote(str(p)) for p in movable)} {shlex.quote(str(journals))}/"
    if clashing:
        problems.append(
            f"{len(clashing)} nested journal(s) duplicate a top-level one and need "
            f"merging by hand ({names([str(p.relative_to(journals)) for p in clashing])})"
        )
    if unpaired:
        problems.append(
            f"{len(unpaired)} record(s) have no journal ({names(unpaired)}) — the "
            "*why* for those detections has nowhere to live"
            + (" — then run `adef sync /path/to/rules`" if fix else "")
        )
        fix = fix or "adef sync /path/to/rules"
    if problems:
        return Check("journals", "warn", f"{len(journal_ids)} journal(s); " + "; ".join(problems), fix)
    return Check("journals", "ok", f"{len(journal_ids)} journal(s), all records paired")


def _check_schemas(ws: Path) -> Check:
    schemas = sorted(p.stem for p in (ws / "schema").glob("*.yml"))
    if not schemas:
        return Check(
            "schemas",
            "warn",
            "no declared data sources — `adef schema check` and cross-language "
            "field matching in Refine have nothing to canonicalize against",
            "adef schema ingest adef-sources.yml",
        )
    return Check("schemas", "ok", f"{len(schemas)} source(s): {', '.join(schemas[:6])}")


def _check_attack(ws: Path) -> Check:
    from adef.core.attack import SNAPSHOT_NAME, attack_reference

    snapshot = ws / "attack" / SNAPSHOT_NAME
    try:
        # `ws`, not the bare resolver: `attack_reference()` reads
        # `$ADEF_WORKSPACE` only, so `adef doctor --workspace /srv/ws` reported
        # the shipped snapshot's version and counts under a
        # "(workspace snapshot)" label. Every other check here answers about
        # `ws`; this one has to as well.
        #
        # Guarded for the same reason `_check_index` guards a non-mapping
        # `INDEX.yml`: `AttackReference.from_path` is a bare `json.loads`, and a
        # truncated `attack/enterprise.json` — what an interrupted `adef attack
        # refresh` leaves behind — crashed `adef doctor` with a JSON traceback.
        # This is the command you run *because* the workspace is broken.
        ref = attack_reference(ws)
    except Exception as exc:  # noqa: BLE001 — doctor must survive what it diagnoses
        # Named from what was actually read. The workspace copy wins when it
        # exists, so reporting its path unconditionally would, in the remote
        # case of a broken *shipped* snapshot, name a file that isn't there.
        where = snapshot if snapshot.is_file() else "the shipped ATT&CK snapshot"
        return Check(
            "att&ck",
            PROBLEM,
            f"{where} could not be read ({exc}) — technique validation and "
            "`by_tactic` resolution have no reference",
            "adef attack refresh",
        )
    origin = "workspace snapshot" if snapshot.is_file() else "shipped"
    # No `fix`: the shipped snapshot is a supported state, not a deficiency, and
    # a `→ adef attack refresh` next to a green tick reads as "you still have
    # work to do". `adef attack refresh` is discoverable from `adef attack info`.
    return Check(
        "att&ck",
        "ok",
        f"v{ref.attack_version} ({origin}), {len(ref.techniques)} technique(s)",
    )


def _check_review_queue(catalog: Catalog) -> Check:
    reasons: dict[str, int] = {}
    for _, _, data in catalog.iter_records():
        for reason in data.get("review_reasons") or []:
            reasons[reason] = reasons.get(reason, 0) + 1
    if not reasons:
        return Check("enrichment", "ok", "no records flagged for review")
    summary = ", ".join(f"{count}× {reason}" for reason, count in sorted(reasons.items()))
    return Check(
        "enrichment",
        "warn",
        f"{summary}",
        f"adef detection list --needs-review {sorted(reasons)[0]}",
    )


def _check_health(ws: Path) -> Check:
    root = ws / "health"
    dets, sources = detections_with_health(root), sources_with_health(root)
    if not dets and not sources:
        return Check(
            "health",
            "warn",
            "nothing ingested — Evolve reports `insufficient-data` until it has "
            "numbers to read",
            "adef ingest weekly-metrics.yml",
        )
    return Check(
        "health",
        "ok",
        f"{len(dets)} detection(s), {len(sources)} source(s) with captures",
    )


def _check_capabilities() -> list[Check]:
    mcp = Check(
        "mcp",
        "ok" if mcp_installed() else "warn",
        "MCP server available — run `adef-mcp`" if mcp_installed() else "not installed",
        "" if mcp_installed() else mcp_install_hint(),
    )
    return [mcp, _check_skills()]


def _check_skills() -> Check:
    """How many of ADEF's *own* skills are installed, and where.

    Named against the bundled set, not a count of whatever is in
    `.claude/skills/`: a developer's unrelated personal skills live in exactly
    the same directory, so counting directory entries reported "1 installed" to
    a workspace with zero ADEF skills — a green tick on the thing being
    checked. Only the intersection with the bundled skill set counts.
    """
    from adef.commands.install_skills import _bundled_plugin_dir

    try:
        bundled_dir = _bundled_plugin_dir() / "skills"
        bundled = {d.name for d in bundled_dir.iterdir() if (d / "SKILL.md").is_file()}
    except OSError:
        bundled = set()
    if not bundled:
        # Package-data now, so this means a damaged install, not a wheel user.
        return Check("skills", "warn", "cannot verify — no bundled skills to compare against")

    found = {d: bundled & {p.parent.name for p in d.glob("*/SKILL.md")} for d in _skills_dirs()}
    installed = sorted({name for names in found.values() for name in names})
    if not installed:
        return Check(
            "skills",
            "warn",
            f"0 of {len(bundled)} ADEF skills installed — they stay inactive until "
            "they're in an assistant's skills directory",
            "adef install-skills",
        )
    where = ", ".join(str(d) for d, names in found.items() if names)
    detail = f"{len(installed)} of {len(bundled)} ADEF skills in {where}"
    if len(installed) < len(bundled):
        return Check(
            "skills",
            "warn",
            f"{detail}; missing {', '.join(sorted(bundled - set(installed)))}",
            "adef install-skills --force",
        )
    return Check("skills", "ok", detail)


def run_checks(workspace: Path | None = None) -> list[Check]:
    """Every check, in the order a user would need to fix them.

    Stops after the workspace check when that one is a `problem`: every check
    below reads the workspace, so one missing directory would otherwise print
    nine failures for a single cause and bury the one line that says what to do.
    """
    ws = resolve_workspace(workspace)
    first = _check_workspace(ws)
    if first.status == PROBLEM:
        return [first]

    catalog_check, catalog = _check_catalog(ws)
    return [
        first,
        catalog_check,
        _check_index(catalog),
        _check_journals(ws, catalog),
        _check_schemas(ws),
        _check_attack(ws),
        _check_review_queue(catalog),
        _check_health(ws),
        *_check_capabilities(),
    ]


__all__ = ["Check", "PROBLEM", "Status", "editable_install", "mcp_install_hint", "mcp_installed", "run_checks"]
