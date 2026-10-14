"""One version, declared in four files that cannot derive it from each other.

`pyproject.toml` is what the wheel carries, `adef/__init__.py` is what
`adef --version` prints, the plugin manifest is what `/plugin` lists, and
`CHANGELOG.md`'s top heading is what a human reads to find out what shipped.
Nothing computes one from another — CLAUDE.md just says they must agree, which
is the shape `.claude/rules/verify-tests-fail.md` calls out: a declared
constraint with no test is indistinguishable from an undeclared one. The
manifest proves the point. It sat at `0.1.0` through the whole 1.0.0 release
because no check compared it to anything.

`publish.yml` also refuses a tag that disagrees with `pyproject.toml`, but that
fires at release time, on one of the three, after the drift has already shipped
to a branch.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # 3.10 — `tomli` is in the `dev` extra so this guard runs on every CI leg
    import tomli as tomllib

import adef

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_PLUGIN_JSON = _ROOT / "adef" / "data" / "claude-plugin" / ".claude-plugin" / "plugin.json"
_PUBLISH_YML = _ROOT / ".github" / "workflows" / "publish.yml"
_CHANGELOG = _ROOT / "CHANGELOG.md"

# The whole extraction publish.yml runs, `sed` included. Checking only the
# `grep` half would let the `sed` be rewritten under a test still claiming to
# model it — and the `sed` is where the interesting disagreement lives.
_PUBLISH_EXTRACT = (
    "grep '^version = ' pyproject.toml | sed 's/version = \"\\(.*\\)\"/\\1/'"
)


def test_pyproject_and_dunder_version_agree() -> None:
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert declared == adef.__version__, (
        f"pyproject.toml says {declared}, adef/__init__.py says {adef.__version__} — "
        "bump both; nothing derives one from the other"
    )


def test_publish_workflow_reads_the_line_this_test_reads() -> None:
    """The workflow greps `^version = `; parsing TOML here would not catch
    a rewrite that moves the version off a line that grep can find — the two
    checks would then disagree about which string is the version.

    So read the workflow too. Modelling its command without checking the
    command is still there leaves this test asserting about a pipeline nobody
    runs any more, and passing while the release gate reads something else.

    The `$` anchor is load-bearing. The workflow's `sed` does NOT anchor its
    trailing quote, so for the TOML-legal line `version = "2.0.0"  # bump me`
    it sets `PACKAGE_VERSION='2.0.0  # bump me'` and the release fails against
    the tag — while an unanchored `[^"]+` here captures a tidy `'2.0.0'` and
    stays green. That is exactly the "two checks disagree about which string
    is the version" case this test exists to close, so the pattern has to
    reject any trailing content rather than step over it.
    """
    workflow = _PUBLISH_YML.read_text(encoding="utf-8")
    assert _PUBLISH_EXTRACT in workflow, (
        f"publish.yml no longer extracts the version with `{_PUBLISH_EXTRACT}` — "
        "the regex in this test models that pipeline, so update both together or "
        "this test guards a gate that no longer exists"
    )
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    grepped = re.findall(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    assert grepped == [adef.__version__], (
        f"`{_PUBLISH_EXTRACT}` yields {grepped}; publish.yml compares exactly this "
        f"against the git tag, and it must be [{adef.__version__!r}] on a line with "
        "nothing after the closing quote"
    )


def test_plugin_manifest_version_agrees() -> None:
    manifest = json.loads(_PLUGIN_JSON.read_text(encoding="utf-8"))
    assert manifest["version"] == adef.__version__, (
        f"{_PLUGIN_JSON.name} says {manifest['version']}, the package is "
        f"{adef.__version__} — the marketplace install would advertise the wrong one"
    )


def test_changelog_documents_this_version() -> None:
    """The fourth site, and the one a human actually reads.

    Both halves matter. A missing heading means the released version has no
    entry at all; a heading with no matching link reference renders on GitHub
    as the literal text `[2.0.0]`, which is how a bare `## [Unreleased]` rename
    leaves things if only one of the two edits gets made.
    """
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    released = [
        v for v in re.findall(r"^## \[([^\]]+)\]", changelog, re.MULTILINE) if v != "Unreleased"
    ]
    assert released[:1] == [adef.__version__], (
        f"CHANGELOG.md's newest released heading is {released[:1]}, the package is "
        f"{adef.__version__} — a release with no entry, or an entry never renamed "
        "from [Unreleased]"
    )
    assert re.search(rf"^\[{re.escape(adef.__version__)}\]: \S", changelog, re.MULTILINE), (
        f"CHANGELOG.md has a `## [{adef.__version__}]` heading with no "
        f"`[{adef.__version__}]:` link definition — GitHub renders that heading as "
        "literal brackets"
    )
