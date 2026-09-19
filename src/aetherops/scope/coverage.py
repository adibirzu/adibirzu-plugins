"""MITRE coverage tracker for purple pairs.

Analysis only. Counts covered / partial / gap rows from already-paired
findings. Does not invent technique IDs and does not write detections
that hide, bypass, or evade.
"""

from __future__ import annotations

import re
from typing import Any

from aetherops.types import Observation

TECHNIQUE_RE = re.compile(r"^(?:AML\.)?T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ALLOWED_COVERAGE = frozenset({"covered", "partial", "gap", "detect-not-do", "denied"})


def normalize_technique(value: str | None) -> str:
    text = (value or "").strip()
    if not text or text.lower() == "unknown":
        return "unknown"
    if TECHNIQUE_RE.match(text):
        return text.upper()
    return "unknown"


def coverage_word(value: str | None) -> str:
    word = (value or "gap").strip().lower()
    return word if word in ALLOWED_COVERAGE else "gap"


def _pair_key(item: dict[str, Any]) -> tuple[str, str, str]:
    asset = str(item.get("asset") or item.get("target") or "").strip().lower()
    observation = str(item.get("observation") or item.get("red") or "").strip().lower()
    technique = normalize_technique(str(item.get("technique") or item.get("attck") or ""))
    return asset, observation, technique


def pair_covers_finding(finding: dict[str, Any], pair: dict[str, Any]) -> bool:
    """A pair covers a finding when observation matches, or asset+technique match."""
    f_asset, f_obs, f_tech = _pair_key(finding)
    p_asset, p_obs, p_tech = _pair_key(pair)
    if f_obs and p_obs and f_obs == p_obs:
        return True
    return bool(
        f_asset and p_asset and f_asset == p_asset and f_tech != "unknown" and f_tech == p_tech
    )


def unpaired_findings(
    findings: list[dict[str, Any]],
    pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    for finding in findings:
        if not any(pair_covers_finding(finding, pair) for pair in pairs):
            missing.append(finding)
    return missing


def build_coverage_matrix(
    pairs: list[dict[str, Any]],
    *,
    extra_rows: list[dict[str, Any]] | None = None,
) -> Observation:
    """Roll purple pairs (and optional attack-path rows) into a coverage matrix."""
    rows: list[dict[str, Any]] = []
    for item in list(pairs) + list(extra_rows or []):
        tech = normalize_technique(str(item.get("technique") or item.get("attck") or ""))
        cov = coverage_word(str(item.get("coverage") or "gap"))
        rows.append(
            {
                "technique": tech,
                "coverage": cov,
                "detection": str(item.get("detection") or item.get("detection_name") or "").strip(),
                "control": str(item.get("control") or item.get("purple") or "").strip(),
            }
        )

    counts: dict[str, int] = {word: 0 for word in sorted(ALLOWED_COVERAGE)}
    by_technique: dict[str, dict[str, int]] = {}
    for row in rows:
        counts[row["coverage"]] = counts.get(row["coverage"], 0) + 1
        bucket = by_technique.setdefault(row["technique"], {})
        bucket[row["coverage"]] = bucket.get(row["coverage"], 0) + 1

    gap_count = counts.get("gap", 0) + counts.get("denied", 0)
    return Observation(
        status="success",
        summary=f"Coverage matrix: {len(rows)} row(s), {gap_count} gap/denied.",
        data={
            "rows": rows,
            "counts": counts,
            "by_technique": by_technique,
            "executed": False,
        },
        next_actions=[
            "Hand gap rows to detection-engineering",
            "Do not add evasion or cloud Sigma",
        ],
    )
