"""HypothesisFromIntelAgent — turn intel (URL or text) into a draft Find/Observe block.

For v0.1.0 this agent is intentionally **content-extraction-light**: it
returns a structured stub the human/LLM-driven analyst then fills out. We do
not bundle our own LLM client — if a caller has the optional ``litellm`` /
``anthropic`` / ``openai`` extra installed and configured, they can post-
process the stub. The shape is what matters; the framework owns the journal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class HypothesisDraft:
    """A draft Find/Observe block for a new detection."""

    hypothesis: str
    intel_sources: list[str]
    candidate_data_sources: list[str]
    candidate_mitre: list[str]


_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_techniques(text: str) -> list[str]:
    """Pull MITRE technique IDs (e.g. T1059, T1059.001) from arbitrary text."""
    seen: list[str] = []
    for match in _TECHNIQUE_RE.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


class HypothesisFromIntelAgent:
    """Generate a draft hypothesis block from a CTI URL or pasted text."""

    def run(self, intel_url_or_text: str) -> HypothesisDraft:
        intel_sources: list[str] = []
        text = intel_url_or_text

        parsed = urlparse(intel_url_or_text)
        if parsed.scheme in ("http", "https"):
            intel_sources.append(intel_url_or_text)
            # In v0.1.0 we deliberately don't fetch — the framework stays
            # network-free. A caller's MCP context or LLM workflow handles
            # fetching and re-runs us with the body text.
            text = intel_url_or_text

        mitre = _extract_techniques(text)

        # Heuristic candidate data sources — mirrored from PEAK telemetry guides.
        lowered = text.lower()
        candidate_data_sources: list[str] = []
        if any(k in lowered for k in ("powershell", "wmic", "cmd.exe", "process")):
            candidate_data_sources.append("EDR / process_create")
        if any(k in lowered for k in ("login", "logon", "iam", "okta", "entra", "session")):
            candidate_data_sources.append("Identity / authentication logs")
        if any(k in lowered for k in ("s3", "bucket", "ec2", "iam role", "cloudtrail", "azure", "gcp")):
            candidate_data_sources.append("Cloud control plane / CloudTrail-like")
        if any(k in lowered for k in ("dns", "http", "tls", "beacon", "c2")):
            candidate_data_sources.append("Network / DNS / proxy")

        hypothesis = (
            "Adversary behavior described in the intel will manifest in "
            f"{', '.join(candidate_data_sources) or 'one or more data sources (TBD)'} "
            "as a deviation from baseline that survives the four-engine constraint."
        )

        return HypothesisDraft(
            hypothesis=hypothesis,
            intel_sources=intel_sources,
            candidate_data_sources=candidate_data_sources,
            candidate_mitre=mitre,
        )


__all__ = ["HypothesisDraft", "HypothesisFromIntelAgent"]
