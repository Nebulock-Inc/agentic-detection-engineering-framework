"""Per-detection markdown journal — the core memory primitive of ADEF.

A *journal* is a markdown file at ``<workspace>/journals/D-XXXX.md`` paired
with an upstream detection rule (or pending — Find stage may exist before a
rule is written). It carries YAML frontmatter for machine-readable state and
one ``## [<ISO-8601>] Stage: <stage>`` block per FORGE transition.

Hard invariant: ``Journal`` never opens or writes any path that resolves
under a ``detections/`` directory. A journal lives in the ADEF workspace;
upstream rules live in their own repository. The two are paired by
``rule_uuid`` in frontmatter.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

import yaml


FORGE_STAGES: tuple[str, ...] = ("find", "observe", "refine", "govern", "evolve")
"""The five FORGE lifecycle stages, in order."""


_DETECTION_ID_RE = re.compile(r"^D-(\d{4,})$")
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)

GENERATED_MARKER = "<!-- adef:generated -->"

# Closes a span opened by GENERATED_MARKER (10188 follow-up items 1 and 2).
# Marking where a generated block *starts* and inferring where it *ends* from
# surrounding structure (the next `### ` heading, the next stage transition, a
# blank line) is wrong whenever the content between the two contains something
# that looks structural — content controls that structure. The close marker
# states the extent instead of inferring it, so nothing between the two
# markers can perturb it, no matter what it looks like.
GENERATED_END_MARKER = "<!-- /adef:generated -->"

# The first timestamped stage block ends the static template preamble.
# `narrative_text` filters the preamble and the stage area by different
# rules — see `_preamble_narrative_lines` for why fill-state alone isn't
# enough there. Moved here from memory.py: the journal module owns its own
# format, and leaving block structure in the search layer is what made
# "which blocks are machine output?" hard to answer.
_STAGE_BLOCK_RE = re.compile(r"^## \[.+?\] Stage:", re.MULTILINE)

# A `### ` sub-block inside a stage block (Refine results land here), OR the
# next `## [ts] Stage:` transition — either one ends the current piece. Just
# `### ` was not enough: a generated block would otherwise "extend" past the
# next stage transition and swallow it (and whatever a human wrote under it)
# into the same piece, which `_is_generated_block` would then drop whole
# (Major finding, 10188 follow-up). This only changes where a piece ends —
# `_is_generated_block` still decides which pieces are generated.
#
# This inference is still exactly as fallible as ever — it is exercised only
# on text `_strip_closed_generated_spans` left alone, i.e. an opening marker
# with no matching close (a journal already on disk from before
# GENERATED_END_MARKER existed). A closed span never reaches this regex at
# all: it is removed wholesale, structure and all, before this runs.
_SUB_BLOCK_RE = re.compile(r"^(?:### |## \[.+?\] Stage:)", re.MULTILINE)

# A fence marker line (opening or closing, ``` or ~~~). Toggled pairwise by
# `_fenced_spans` below — no nesting, no info-string awareness, just enough to
# know when a `### `/`## [ts] Stage:` match is text *inside* a fence rather
# than a real sub-block boundary (10188 follow-up item 1, original mitigation:
# a traceback written inside a fence by `run_refine_chain`'s generic-failure
# branch can contain a line starting with `### `, which used to split the
# generated block it belonged to — the tail then carried neither the marker
# nor the legacy prefix, and got indexed). Superseded as the real fix by
# GENERATED_END_MARKER above; kept as the unclosed-marker fallback path only.
_FENCE_MARK_RE = re.compile(r"^(?:```|~~~)", re.MULTILINE)


# Either marker, as a whole line. Walked in document order below so an open
# can only ever be paired with the *next* marker line — a close pairs it, but
# another open supersedes it (leaves it behind, unpaired) rather than letting
# a `.*?` scan leapfrog an intervening unclosed open straight to some later
# close that was never its match (CodeRabbit review, 10188 follow-up: a
# journal with an old unclosed marker followed later by a properly-closed new
# block — the ordinary shape of an existing journal right after this fix
# ships — must not have the closed block's close marker pair with the old
# open and elide everything between, human content included).
_GENERATED_MARKER_LINE_RE = re.compile(
    r"^(?:(?P<open>" + re.escape(GENERATED_MARKER) + r")|(?P<close>"
    + re.escape(GENERATED_END_MARKER) + r"))\n?",
    re.MULTILINE,
)


def _heading_line_start_before(text: str, pos: int) -> Optional[int]:
    """If the line immediately before ``pos`` (no blank line, no gap) is a
    bare ``### `` heading line, return that line's start offset; else
    ``None``.

    "Immediately before" is deliberately strict — contiguous lines only, `\\n`
    to `\\n`. `append_block` writes its heading and the `GENERATED_MARKER`
    line as consecutive lines with nothing between them, so this matches
    exactly the heading a closed span's own block introduced, never a heading
    that merely happens to sit somewhere earlier in the same stage block.
    """
    if pos == 0 or text[pos - 1] != "\n":
        return None
    line_start = text.rfind("\n", 0, pos - 1) + 1
    line = text[line_start:pos]
    if line.startswith("### "):
        return line_start
    return None


def _strip_closed_generated_spans(text: str) -> str:
    """Remove every explicitly-closed generated span from ``text`` wholesale,
    before any structure-inferring rule below ever sees it (10188 follow-up
    items 1 and 2), *and* the ``### `` heading immediately introducing it, if
    any (Major finding, 10188 follow-up).

    Everything from an opening ``GENERATED_MARKER`` line to its matching
    ``GENERATED_END_MARKER`` line is opaque here — a heading-shaped line, a
    blank line, a fake stage transition, a fence, anything the content
    happens to contain is removed along with it, because the extent is
    stated by the markers, not inferred from what sits between them.

    The heading line a `### `-block marker follows (e.g. `### Refine / X
    (ts)`) is removed too, but ONLY when it sits directly on the line above
    the opening marker with nothing between them — the exact shape
    `append_block` writes. Leaving it standing was the original design (it
    carries no content of its own, and `narrative_text`'s heading-line rule
    already keeps it out of the index on its own) — but leaving it standing
    also leaves it matching `_is_generated_block`'s legacy `### Refine / `
    prefix check once the span between the markers is gone, which then drops
    the *entire* piece — heading plus whatever human text shares it with no
    heading of its own (e.g. hand-edited prose appended after the span). This
    check is deliberately narrow: it removes only the one heading that
    directly introduced this span, never a heading that merely precedes it
    somewhere earlier in the same stage block — that would start discarding
    human sub-block headings, the opposite failure.

    Pairing is a single left-to-right walk, not "nearest close anywhere
    later": an open is tracked until either a close pairs it (span removed)
    or another open is seen first, which replaces it as the tracked
    (unpaired) open — so a close can only ever match the open immediately
    before it, never one separated by an intervening open.

    An opening marker with **no** matching close anywhere later in the text
    is left untouched — that is a journal already on disk from before this
    marker existed, and the older structure-inferring rules elsewhere in this
    module (the fenced-aware piece split feeding `_is_generated_block`, and
    the blank-line/heading-scoped generated-note handling in
    `narrative_text`) still apply to it unchanged, so it keeps excluding
    exactly as it does today.
    """
    out: list[str] = []
    last = 0
    open_start: Optional[int] = None
    for m in _GENERATED_MARKER_LINE_RE.finditer(text):
        if m.group("open") is not None:
            open_start = m.start()
        elif open_start is not None:
            span_start = open_start
            heading_start = _heading_line_start_before(text, span_start)
            if heading_start is not None and heading_start >= last:
                span_start = heading_start
            out.append(text[last:span_start])
            last = m.end()
            open_start = None
        # else: a close with no open currently tracked — writers never emit
        # one, ignore defensively rather than error on a hand-edited file.
    out.append(text[last:])
    return "".join(out)


def _fenced_spans(text: str) -> list[tuple[int, int]]:
    """Byte ranges of fenced code blocks in ``text``, open/close by line order."""
    spans: list[tuple[int, int]] = []
    open_at: Optional[int] = None
    for m in _FENCE_MARK_RE.finditer(text):
        if open_at is None:
            open_at = m.start()
        else:
            spans.append((open_at, m.end()))
            open_at = None
    if open_at is not None:
        spans.append((open_at, len(text)))  # unclosed fence: rest of text is fenced
    return spans


def _inside_any(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)

# Journals written before GENERATED_MARKER existed carry no marker. This
# prefix identifies them. Permanent fallback, not a migration step.
_LEGACY_GENERATED_HEADING = "### Refine / "

# A template fill-in line: `- **Field:** value`. Matched against a single
# already-stripped line so it can be checked in the same per-line pass as
# every other filter in narrative_text.
_FIELD_LINE_RE = re.compile(r"^-\s+\*\*[^*]+:\*\*\s*(.*)$")

# `catalog`/`sync` housekeeping notes written before GENERATED_MARKER existed
# carry no marker (10188 follow-up finding 1). Same migration gap
# `_LEGACY_GENERATED_HEADING` closes for `### `-blocks — a permanent legacy
# fallback, not a migration step — just never carried across to these
# `## [ts] Stage:`-block notes (`Journal.create`/`advance_stage`'s `note`).
#
# Matched as exact whole lines (`re.match` anchored `^...$` against the
# already-stripped line), not substrings: the deleted
# `"Catalogued from" in line and "adef" in line` filter dropped a human
# sentence for merely containing those substrings, and that over-reach is
# deliberately not reinstated. One pattern per writer message shape, read
# from the actual call sites rather than guessed:
#   - adef/commands/catalog.py: f"Catalogued from {rec.rule_ref} by `adef catalog`."
#   - adef/commands/sync.py (NEW):      f"Catalogued from {rec.rule_ref} by `adef sync`."
#   - adef/commands/sync.py (repair):   "Journal missing for this record — re-created by `adef sync`."
#   - adef/commands/sync.py (ORPHANED): "Source rule gone — orphaned by `adef sync`."
#   - adef/commands/sync.py (MODIFIED): f"Source changed (hash {hash8}); derived fields refreshed by `adef sync`."
_LEGACY_HOUSEKEEPING_LINE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Catalogued from .+ by `adef (?:catalog|sync)`\.$"),
    re.compile(r"^Journal missing for this record — re-created by `adef sync`\.$"),
    re.compile(r"^Source rule gone — orphaned by `adef sync`\.$"),
    re.compile(
        r"^Source changed \(hash [0-9a-f]+\); derived fields refreshed by `adef sync`\.$"
    ),
)


def _is_legacy_housekeeping_line(line: str) -> bool:
    """True for a pre-marker `catalog`/`sync` housekeeping note, matched
    exactly against the known writer message shapes — never by substring."""
    return any(p.match(line) is not None for p in _LEGACY_HOUSEKEEPING_LINE_RES)


def _is_generated_block(block: str) -> bool:
    """True when this piece is a machine-written ``### `` sub-block — Refine
    chain output via ``append_block(generated=True)``, or the permanent
    legacy-heading fallback — dropped whole, by provenance.

    Deliberately narrower than "marker anywhere in the piece": restricted to
    ``### ``-headed pieces because `append_block` always mints a fresh piece
    per call, so a marker inside one can never share space with unrelated
    content. A ``## [ts] Stage: ...`` piece is different — it accumulates
    notes across repeated `advance_stage` calls, human and machine mixed — so
    it is never whole-block-dropped here; an individual generated note inside
    one is instead excluded by the line-scoped marker handling in
    `narrative_text` (10188 follow-up item 2).
    """
    if block.startswith(_LEGACY_GENERATED_HEADING):
        return True
    return block.startswith("### ") and GENERATED_MARKER in block


def _is_unfilled_field_line(line: str) -> bool:
    """True for a template placeholder (`- **Field:**`) with nothing typed
    after the colon. The same line with a value filled in is reasoning a
    human wrote, not scaffolding."""
    m = _FIELD_LINE_RE.match(line)
    return m is not None and not m.group(1).strip()


def _filled_field_line_or_none(line: str) -> Optional[str]:
    """The line itself if it's a `- **Field:** value` line with a value,
    else ``None``."""
    m = _FIELD_LINE_RE.match(line)
    if m is not None and m.group(1).strip():
        return line
    return None


def _preamble_narrative_lines(preamble: str) -> list[str]:
    """The preamble (everything before the first timestamped stage block) is
    the template's own fill-in section — `Journal.create` writes it once,
    verbatim, before any stage block exists. Unlike the stage area, it is
    *whitelisted*, not blacklisted: keep ONLY a filled `- **Field:** value`
    line, plus any indented continuation of one (see below). Everything else
    there — plain-prose section descriptions ("Tune, deprecate, replace.
    Detections never finish — they iterate."), headings, blockquotes,
    unfilled placeholders — is template boilerplate, byte-identical in every
    journal ADEF has ever created (including the skeleton journal
    `adef catalog` pairs with every catalogued rule), so a filter that lets
    any of it through makes every detection in a workspace look alike on the
    template's own words (r2 review, Important). A position-only rule would
    silently drop a filled field just because it lives above the first stage
    block; a fill-state-only rule (r1's mistake) lets the unstructured prose
    through. Only intersecting both catches exactly the boilerplate and
    nothing else.

    A filled field's value can wrap: hand-editing the markdown is the ONLY
    way ADEF provides to fill a preamble field (no CLI command writes one),
    and `docs/detection-home.md` tells users to edit the workspace as plain
    markdown directly, so a multi-sentence answer that wraps onto an indented
    continuation line is ordinary usage, not an edge case (r3 review,
    Important). A continuation line is kept only while it (a) is indented —
    the template's own section prose sits at column 0, so this alone rules
    out the free-paragraph-under-a-heading case, which is deliberately
    **not** covered here (see `narrative_text`'s docstring) — and (b)
    directly follows a *filled* field line or another kept continuation, with
    no blank line breaking the chain. A continuation of an *unfilled* field
    is still dropped: the field had no value, so indented text under it is
    template scaffolding, not an answer, regardless of indentation.

    Note: reasoning in the preamble is indexed only when it is written in the
    template's `- **Field:** value` grammar (plus a wrapped continuation of
    one). A free-text paragraph typed under a `## Find`-style heading is
    textually indistinguishable from the template's own static prose, so it
    is not recognized — there is no reliable way to tell the two apart by
    content alone, which is the whole reason this filters by structure
    instead (r3 review).
    """
    lines: list[str] = []
    continuing = False  # mid-chain: the previous non-blank line was kept
    for raw_line in preamble.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continuing = False
            continue
        kept = _filled_field_line_or_none(stripped)
        if kept is not None:
            lines.append(kept)
            continuing = True
            continue
        is_indented = raw_line != raw_line.lstrip()
        if continuing and is_indented:
            lines.append(stripped)
            continue
        continuing = False
    return lines


def narrative_text(body: str) -> str:
    """The human-authored prose in a journal body, for indexing.

    Drops: the static template preamble (position-based — see
    `_preamble_narrative_lines`, which whitelists only its filled
    `- **Field:** value` lines and drops everything else there, plain prose
    included), unfilled placeholders and other scaffolding within the stage
    area, every machine-generated sub-block, and every machine-generated note
    (both primarily by provenance — the `GENERATED_MARKER`, never by
    content). What remains is reasoning a person or an agent wrote
    deliberately — the only journal content that can be evidence without
    feeding retrieval its own output.

    Provenance is the only thing that excludes machine text going forward; a
    human writing about `adef catalog` in their own reasoning is indexed like
    anything else they write. The former `"Catalogued from" in line and
    "adef" in line` filter, removed in the 10188 follow-up, is deliberately
    NOT reinstated — it dropped a human line just for containing those
    substrings.

    One narrow exception: `_is_legacy_housekeeping_line` excludes the exact
    (whole-line, not substring) text of `catalog`/`sync`'s housekeeping notes
    for journals already on disk from before `GENERATED_MARKER` existed —
    those notes carry no marker to filter by provenance. This is the same
    permanent migration fallback `_LEGACY_GENERATED_HEADING` provides for
    `### `-blocks, carried across to these `## [ts] Stage:`-block notes. It
    is anchored to the known writer message shapes exactly, so it cannot
    reintroduce the deleted filter's over-reach.

    The preamble and the stage area are filtered differently on purpose.
    `Journal.create` writes the preamble once, verbatim from the shipped
    template, before the Find block is ever appended — so a user who fills in
    `- **Baseline of normal:** ...` there (the normal way to answer the
    template's own prompts) must not have that answer silently excluded (r1
    review), but the section's plain-prose descriptions must never reach the
    index either, because they are byte-identical in every journal ADEF has
    ever created (r2 review). The stage area has no such guaranteed
    boilerplate — a stage block is appended once, per transition, with
    whatever a human (or an agent, for a non-generated sub-block) actually
    wrote — so it keeps the permissive rule: drop known scaffolding (headings,
    the echoed title, generated sub-blocks and generated notes by provenance)
    and strip the leading `>` marker from a blockquoted line rather than
    dropping it — a blockquote is the natural
    markdown for pasting intel or a customer report into a journal, and that
    is exactly the "why" ADEF exists to retain — keep everything else.

    Preamble reasoning is indexed only when written in the template's own
    `- **Field:** value` grammar (plus a wrapped continuation of one, r3
    review): a free-text paragraph typed under a `## Find`-style heading
    instead is textually indistinguishable from the template's own static
    prose that this function exists to drop, so there is no reliable,
    content-only way to tell the two apart — filtering by structure is the
    honest resolution, not a documentation gap to code around.
    """
    body = _strip_closed_generated_spans(body)
    m = _STAGE_BLOCK_RE.search(body)
    preamble = body[: m.start()] if m else body
    stage_area = body[m.start():] if m else ""

    # Split the stage area into pieces at every `### ` sub-block AND every
    # `## [ts] Stage:` transition, keeping any text before the first boundary
    # (that is stage-block prose, which is human by definition). Breaking on
    # stage transitions too means a generated piece ends at the next stage,
    # never swallowing it.
    pieces: list[str] = []
    last = 0
    fences = _fenced_spans(stage_area)
    for match in _SUB_BLOCK_RE.finditer(stage_area):
        if _inside_any(match.start(), fences):
            # Not a real boundary — text inside a fenced code block, not a
            # `### `/`## [ts] Stage:` heading (10188 follow-up item 1).
            continue
        pieces.append(stage_area[last:match.start()])
        last = match.start()
    pieces.append(stage_area[last:])

    kept = [p for p in pieces if not _is_generated_block(p)]

    lines: list[str] = _preamble_narrative_lines(preamble)
    in_generated_note = False
    for line in "".join(kept).splitlines():
        stripped = line.strip()
        if not stripped:
            in_generated_note = False
            continue
        if stripped.startswith("#"):
            in_generated_note = False
            continue
        if stripped == GENERATED_MARKER:
            # A marker seen here has no matching GENERATED_END_MARKER —
            # `_strip_closed_generated_spans` already removed every closed
            # span, markers and all, before this loop ever ran. This is the
            # unclosed-marker fallback for a journal already on disk from
            # before the close marker existed: scopes to just the note that
            # follows, not the whole stage block — a `## [ts] Stage:` piece
            # can hold both a generated note (sync/catalog housekeeping) and
            # human content appended by a later `advance_stage` call — ending
            # at the next blank line or heading, same as it always has.
            in_generated_note = True
            continue
        if in_generated_note:
            continue
        if stripped.startswith(">"):
            # Blockquote is markdown shape, not machine provenance — strip the
            # marker and keep the text (a human pasting intel or a customer
            # report is exactly the "why" this index exists to retain).
            stripped = stripped.lstrip(">").strip()
            if not stripped:
                continue
        if stripped.startswith("**Title:**"):
            continue
        if _is_unfilled_field_line(stripped):
            continue
        if _is_legacy_housekeeping_line(stripped):
            continue
        lines.append(stripped)
    return "\n".join(lines)


class JournalError(RuntimeError):
    """Base error for journal operations."""


class HardInvariantViolation(JournalError):
    """Raised if a journal path would resolve inside a rule ``detections/`` tree."""


@dataclass(frozen=True)
class StageAdvanceResult:
    """Outcome of ``Journal.advance_stage``."""

    detection_id: str
    stage: str
    was_idempotent: bool
    timestamp: str


def _now_iso() -> str:
    """Return current time as an ISO-8601 string with second precision and TZ."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _atomic_write(target: Path, content: str) -> None:
    """Write ``content`` to ``target`` via a temp file + rename (POSIX atomic)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".adef-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _check_not_under_detections(path: Path) -> None:
    """Raise if ``path`` resolves anywhere under a rule ``detections/`` tree.

    ADEF journals live in the workspace ``journals/`` directory. Any path that
    sits inside an upstream rule repository (whose convention is a top-level
    ``detections/`` directory) is read-only for ADEF — the journal layer must
    never write there.
    """
    parts = path.resolve().parts
    if "detections" in parts:
        raise HardInvariantViolation(
            f"adef.core.journal refused to touch {path} — paths under any "
            "rule 'detections/' directory are read-only for ADEF."
        )


def workspace_journals_dir(workspace: Optional[Path], create: bool = True) -> Path:
    """Resolve the journals directory for ``workspace``.

    Delegates workspace resolution to the canonical ``resolve_workspace`` (one
    resolver for every command — ISA 2026-07-22) so ``adef catalog .`` and
    ``adef detection list`` in the same dir never disagree about *which*
    workspace they mean.

    ``create=True`` (default, for write paths) ensures ``journals/`` exists;
    **read paths must pass ``create=False``** so listing/showing never silently
    scaffolds ``~/work/adef-workspace`` as a side effect.
    """
    from adef.core.workspace import resolve_workspace

    ws = resolve_workspace(workspace)
    journals = ws / "journals"
    if create:
        journals.mkdir(parents=True, exist_ok=True)
    return journals


def next_detection_id(journals_dir: Path) -> str:
    """Return ``D-<next>`` where ``<next>`` is one greater than the max existing index."""
    max_idx = 0
    for child in journals_dir.glob("D-*.md"):
        m = _DETECTION_ID_RE.match(child.stem)
        if m:
            max_idx = max(max_idx, int(m.group(1)))
    return f"D-{max_idx + 1:04d}"


def _load_template_text() -> str:
    """Return the package-data DETECTION_FORGE.md template as a string."""
    return (
        resources.files("adef.data.templates")
        .joinpath("DETECTION_FORGE.md")
        .read_text(encoding="utf-8")
    )


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split markdown ``text`` into (frontmatter dict, body string)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    fm = yaml.safe_load(m.group(1)) or {}
    body = text[m.end() :]
    return fm, body


def _join_frontmatter(fm: dict, body: str) -> str:
    """Re-serialize ``fm`` + ``body`` into a frontmatter+markdown document."""
    head = yaml.safe_dump(fm, sort_keys=False).strip()
    return f"---\n{head}\n---\n{body}" if not body.startswith("\n") else f"---\n{head}\n---{body}"


@dataclass
class JournalEntry:
    """In-memory representation of a single journal."""

    path: Path
    frontmatter: dict
    body: str

    @property
    def detection_id(self) -> str:
        return str(self.frontmatter.get("id", self.path.stem))

    @property
    def current_stage(self) -> str:
        return str(self.frontmatter.get("current_stage", "find"))

    @property
    def rule_uuid(self) -> str:
        return str(self.frontmatter.get("rule_uuid", "") or "")


# Resolved paths already warned about for malformed frontmatter (10188
# follow-up item 4). `build_corpus` re-runs `iter_entries()` on every search
# and every refine, in processes that can live a long time (the MCP server) —
# without this, one bad journal warns to stderr forever. Bounded by the number
# of malformed files in the workspace, process-lifetime, module-level by
# design (mirrors the plugin-discovery failure log, which also never resets).
_WARNED_MALFORMED: set[Path] = set()


class Journal:
    """File-system-backed CRUD for ``D-XXXX.md`` journal files.

    Each ``Journal`` instance is bound to a journals directory. Operations on
    individual detections take their id; the class never holds per-detection
    state across calls.
    """

    def __init__(self, journals_dir: Path) -> None:
        _check_not_under_detections(journals_dir)
        self._dir = journals_dir.expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, detection_id: str) -> Path:
        # Every journal read/write routes through here: reject anything that
        # isn't an ADEF-minted id so a hand-edited record id ("../x", an
        # absolute path) can never become a path outside journals/.
        if not _DETECTION_ID_RE.fullmatch(detection_id):
            raise JournalError(f"Invalid detection id {detection_id!r} (expected D-XXXX).")
        candidate = self._dir / f"{detection_id}.md"
        _check_not_under_detections(candidate)
        return candidate

    def create(
        self,
        detection_id: str,
        title: str,
        owner: str = "",
        rule_uuid: str = "",
        note: str = "",
        generated: bool = False,
    ) -> JournalEntry:
        """Create a new journal at the Find stage. Returns the populated entry.

        Pass ``generated=True`` when ``note`` is machine-written derived
        restatement (e.g. `catalog`/`sync`'s "Catalogued from …" housekeeping)
        — mirrors `append_block`/`advance_stage`. Marks only the note, not the
        stage block: `**Title:**` is unaffected either way, it is already
        dropped by its own rule in `narrative_text`.
        """
        path = self._path_for(detection_id)
        if path.exists():
            raise JournalError(f"Journal {path} already exists.")

        template = _load_template_text()
        fm_template, body_template = _split_frontmatter(template)
        ts = _now_iso()
        fm = {
            **fm_template,
            "id": detection_id,
            "title": title,
            "status": "draft",
            "current_stage": "find",
            "owner": owner,
            "rule_uuid": rule_uuid,
            "created": ts,
            "updated": ts,
        }
        # Lean Find block, consistent with the other stages — the Find guidance
        # lives in the template's `## Find` fill-in section, not re-printed here.
        marker = f"{GENERATED_MARKER}\n" if (generated and note) else ""
        closer = f"{GENERATED_END_MARKER}\n" if (generated and note) else ""
        find_block = (
            f"\n## [{ts}] Stage: find\n\n"
            f"**Title:** {title}\n\n"
            + (f"{marker}{note}\n{closer}" if note else "")
        )
        text = _join_frontmatter(fm, body_template.rstrip() + "\n" + find_block)
        _atomic_write(path, text)
        return JournalEntry(path=path, frontmatter=fm, body=body_template + find_block)

    def read(self, detection_id: str) -> JournalEntry:
        """Read an existing journal."""
        path = self._path_for(detection_id)
        if not path.exists():
            raise JournalError(f"Journal {path} not found.")
        text = path.read_text(encoding="utf-8")
        fm, body = _split_frontmatter(text)
        return JournalEntry(path=path, frontmatter=fm, body=body)

    def advance_stage(
        self,
        detection_id: str,
        stage: str,
        note: str = "",
        generated: bool = False,
    ) -> StageAdvanceResult:
        """Advance the journal to ``stage``, append a stage block, return outcome.

        Idempotent: re-advancing to the same stage emits a stderr warning and
        does not append a duplicate block (a note, if given, is still added as
        a sub-block within the existing stage).

        Pass ``generated=True`` when ``note`` is machine-written derived
        restatement (e.g. `sync`'s "Source rule gone"/"Source changed…"
        housekeeping) — mirrors `append_block`. The marker scopes to just this
        note, not the whole stage block: a `## [ts] Stage:` block accumulates
        notes across repeated calls, human and machine mixed, so a later
        human note appended here is unaffected.
        """
        if stage not in FORGE_STAGES:
            raise JournalError(f"Unknown stage {stage!r}. Expected one of {FORGE_STAGES}.")

        entry = self.read(detection_id)
        ts = _now_iso()
        was_idempotent = entry.current_stage == stage
        marker = f"{GENERATED_MARKER}\n" if (generated and note) else ""
        closer = f"{GENERATED_END_MARKER}\n" if (generated and note) else ""

        if was_idempotent:
            print(
                f"[adef.journal] {detection_id} already at stage {stage}; "
                f"appending note only.",
                file=sys.stderr,
            )
            new_body = entry.body
            if note:
                new_body = entry.body.rstrip() + f"\n\n{marker}_Note ({ts}):_ {note}\n{closer}"
        else:
            # A lean transition record: timestamp + note. The FORGE guidance
            # (what to capture at each stage) lives once in the template's
            # fill-in sections — re-printing the prompt prose in every block
            # duplicated it and buried the actual notes (ISA 2026-07-22).
            block = (
                f"\n## [{ts}] Stage: {stage}\n\n"
                + (f"{marker}{note}\n{closer}" if note else "_(no note)_\n")
            )
            new_body = entry.body.rstrip() + "\n" + block

        new_fm = {
            **entry.frontmatter,
            "current_stage": stage,
            "updated": ts,
        }
        _atomic_write(entry.path, _join_frontmatter(new_fm, new_body))
        return StageAdvanceResult(
            detection_id=detection_id,
            stage=stage,
            was_idempotent=was_idempotent,
            timestamp=ts,
        )

    def append_block(
        self, detection_id: str, heading: str, body: str, generated: bool = False
    ) -> None:
        """Append an arbitrary ``### heading``-level block under the current stage.

        Used by orchestration (Refine chain) to record agent results. Pass
        ``generated=True`` for machine-written blocks: the block stays in the
        file and stays visible to readers, but retrieval excludes it, so a
        Refine result can never feed back into the scoring that produced it.
        """
        entry = self.read(detection_id)
        ts = _now_iso()
        marker = f"{GENERATED_MARKER}\n" if generated else ""
        closer = f"\n{GENERATED_END_MARKER}\n" if generated else ""
        block = f"\n### {heading} ({ts})\n{marker}\n{body.strip()}\n{closer}"
        new_fm = {**entry.frontmatter, "updated": ts}
        _atomic_write(entry.path, _join_frontmatter(new_fm, entry.body.rstrip() + "\n" + block))

    def iter_entries(self) -> Iterable[JournalEntry]:
        """Yield every journal in the directory.

        A journal this process cannot read as a valid entry is skipped
        (reported to stderr once per resolved path per process — see
        `_WARNED_MALFORMED` below), not raised — a corpus-wide reader
        (`build_corpus`) must not let one bad file take down every other
        detection. This is a class of failure, not one exception: bad YAML
        (`yaml.YAMLError`), a non-UTF-8 file (`UnicodeDecodeError`), an
        unreadable file (`OSError`), and frontmatter that parses to something
        other than a mapping — e.g. a YAML list — all count. Mirrors
        `Catalog.iter_records`' tolerance of a bad catalog YAML.

        Frontmatter with no usable ``id`` also counts (10188 follow-up item
        3): every journal ADEF itself ever writes gets one from `create`, so a
        file without one — e.g. a stray file with no frontmatter at all — is
        malformed, not a detection, and must not enter the corpus under its
        filename via `JournalEntry.detection_id`'s `path.stem` fallback. That
        fallback itself is untouched — other callers may rely on it — this
        only decides corpus membership.
        """
        for child in sorted(self._dir.glob("D-*.md")):
            try:
                text = child.read_text(encoding="utf-8")
                fm, body = _split_frontmatter(text)
                if not isinstance(fm, dict):
                    raise ValueError(f"frontmatter is a {type(fm).__name__}, not a mapping")
                if not fm.get("id"):
                    raise ValueError("frontmatter has no 'id'")
            except (yaml.YAMLError, UnicodeDecodeError, OSError, ValueError) as exc:
                resolved = child.resolve()
                if resolved not in _WARNED_MALFORMED:
                    _WARNED_MALFORMED.add(resolved)
                    print(
                        f"[adef.journal] skipping {child} — malformed frontmatter: {exc}",
                        file=sys.stderr,
                    )
                continue
            yield JournalEntry(path=child, frontmatter=fm, body=body)

    def find_by_rule_uuid(self, rule_uuid: str) -> Optional[JournalEntry]:
        """Return the journal paired with ``rule_uuid``, or ``None``."""
        if not rule_uuid:
            return None
        for entry in self.iter_entries():
            if entry.rule_uuid == rule_uuid:
                return entry
        return None

    def max_detection_index(self) -> int:
        """Return the highest existing D-XXXX index, or 0."""
        max_idx = 0
        for child in self._dir.glob("D-*.md"):
            m = _DETECTION_ID_RE.match(child.stem)
            if m:
                max_idx = max(max_idx, int(m.group(1)))
        return max_idx


__all__ = [
    "FORGE_STAGES",
    "GENERATED_MARKER",
    "GENERATED_END_MARKER",
    "Journal",
    "JournalEntry",
    "JournalError",
    "HardInvariantViolation",
    "StageAdvanceResult",
    "narrative_text",
    "next_detection_id",
    "workspace_journals_dir",
]
