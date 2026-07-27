"""Build-time generator for the ATT&CK reference snapshot.

**Dev-time only — NOT imported at runtime and NOT a runtime dependency.**
Fetches MITRE's official Enterprise ATT&CK STIX 2.1 bundle and distils it to
the compact ``enterprise.json`` shipped as package data. The runtime side
(`adef/core/attack.py`) only ever reads that JSON — it never fetches or parses
STIX. `adef attack refresh` shells out to this module to regenerate on demand.

Run directly to refresh the shipped snapshot::

    python -m adef.data.attack._generate            # writes ./enterprise.json
    python -m adef.data.attack._generate --out /tmp/enterprise.json

Uses only the stdlib (urllib + json) so it never pulls a dependency in — the
STIX bundle is a stable public file in mitre-attack/attack-stix-data.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# The shape the runtime layer expects. Bump when the runtime reader changes.
SNAPSHOT_VERSION = 1

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            eid: str | None = ref.get("external_id")
            return eid
    return None


def build_snapshot(bundle: dict[str, Any]) -> dict[str, Any]:
    """Distil a STIX bundle to the compact reference snapshot."""
    objects = bundle.get("objects", [])
    by_stix_id = {o["id"]: o for o in objects if "id" in o}

    # tactic shortname -> display name
    tactics: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "x-mitre-tactic":
            shortname = o.get("x_mitre_shortname")
            if shortname:
                tactics[shortname] = o.get("name", shortname)

    # revoked technique STIX id -> replacement external id
    superseded: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            tgt = by_stix_id.get(o.get("target_ref", ""))
            if tgt:
                repl = _external_id(tgt)
                if repl:
                    superseded[o.get("source_ref", "")] = repl

    techniques: dict[str, dict[str, Any]] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        tid = _external_id(o)
        if not tid or not _TECHNIQUE_ID_RE.match(tid):
            continue
        tactic_shortnames = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
        ]
        parent = tid.split(".")[0] if "." in tid else None
        entry: dict[str, Any] = {
            "name": o.get("name", ""),
            "tactics": tactic_shortnames,
        }
        if parent:
            entry["parent"] = parent
        if o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        if o.get("revoked"):
            entry["revoked"] = True
            repl = superseded.get(o["id"])
            if repl:
                entry["superseded_by"] = repl
        techniques[tid] = entry

    # ATT&CK release version, from the collection object.
    attack_version = ""
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            attack_version = o.get("x_mitre_version", "")
            break

    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "attack_version": attack_version,
        "source": STIX_URL,
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def fetch_bundle(url: str = STIX_URL, timeout: int = 120) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
        bundle: dict[str, Any] = json.load(resp)
        return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the ATT&CK reference snapshot.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).with_name("enterprise.json"),
        help="Output path (default: the shipped enterprise.json next to this script).",
    )
    parser.add_argument("--url", default=STIX_URL, help="STIX bundle URL.")
    args = parser.parse_args(argv)

    bundle = fetch_bundle(args.url)
    snapshot = build_snapshot(bundle)
    args.out.write_text(json.dumps(snapshot, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.out} — ATT&CK {snapshot['attack_version']}, "
        f"{len(snapshot['techniques'])} techniques, {len(snapshot['tactics'])} tactics.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
