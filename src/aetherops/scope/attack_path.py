"""In-scope attack-path reasoning (analysis only).

A hop is a planned or observed edge between two identities already in
the signed scope. Out-of-scope laterals and permanent-deny techniques
fail closed. This module does not execute, scan, or generate payloads.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, field_validator

from aetherops.scope.gate import normalize_target, target_in_scope
from aetherops.scope.verbs import contains_payload_shape, is_permanent_deny
from aetherops.types import Engagement, Observation

Coverage = Literal["planned", "potential-evidence", "verified-evidence", "denied", "detect-not-do"]

DENIED_TECHNIQUES = frozenset(
    {
        "T1485",
        "T1486",
        "T1489",
        "T1490",
        "T1499",
        "T1048",
        "T1071",
        "T1505.003",
    }
)

DETECT_NOT_DO = frozenset(
    {
        "T1190",
        "T1525",
        "T1609",
        "T1587",
        "T1588",
        "T1021",
        "T1059",
    }
)


class AttackHop(BaseModel):
    from_asset: str
    to_asset: str
    technique: str
    coverage: Coverage = "planned"
    note: str = ""

    @field_validator("from_asset", "to_asset", "technique")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = (value or "").strip()
        if not text:
            raise ValueError("hop field is empty")
        return text


def _halt(summary: str, hint: str, hops: list[dict[str, Any]] | None = None) -> Observation:
    return Observation(
        status="error",
        summary=summary,
        root_cause_hint=hint,
        stop_condition="SCOPE DENIED. Do not retry out-of-scope or denied hops.",
        data={"scope_refused": True, "hops": hops or []},
        next_actions=["Stay inside the signed lab", "Map remaining in-scope hops only"],
    )


def assess_attack_path(
    hops: list[dict[str, Any]] | list[AttackHop],
    engagement: Engagement,
) -> Observation:
    """Validate a chain of hops against the signed lab. Analysis only."""
    if not hops:
        return _halt("SCOPE DENIED: empty attack path", "A path needs at least one in-scope hop.")

    parsed: list[AttackHop] = []
    for raw in hops:
        try:
            parsed.append(raw if isinstance(raw, AttackHop) else AttackHop.model_validate(raw))
        except (TypeError, ValueError) as exc:
            return _halt("SCOPE DENIED: malformed hop", f"Hop failed validation: {exc}")

    rows: list[dict[str, Any]] = []
    for hop in parsed:
        src = normalize_target(hop.from_asset)
        dst = normalize_target(hop.to_asset)
        tech = hop.technique.strip().upper()
        if contains_payload_shape(hop.note) or is_permanent_deny(hop.note):
            return _halt("Denied: hop note is payload-shaped or permanently denied", hop.note)
        if not src or not target_in_scope(src, engagement):
            return _halt(
                "SCOPE DENIED: hop source is out of scope",
                f"from_asset={hop.from_asset}",
            )
        if not dst or not target_in_scope(dst, engagement):
            return _halt(
                "SCOPE DENIED: hop destination is out of scope",
                f"to_asset={hop.to_asset}",
            )
        coverage: Coverage = hop.coverage
        if tech in DENIED_TECHNIQUES or is_permanent_deny(tech):
            coverage = "denied"
            return _halt(
                f"SCOPE DENIED: technique {tech} is permanently denied",
                "Impact/exfil/C2 techniques are detect-not-do, never a next hop.",
                hops=rows,
            )
        if tech in DETECT_NOT_DO and coverage not in {"denied", "detect-not-do"}:
            coverage = "detect-not-do"
        rows.append(
            {
                "from": src,
                "to": dst,
                "technique": tech,
                "coverage": coverage,
            }
        )

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["coverage"]] = counts.get(row["coverage"], 0) + 1

    return Observation(
        status="success",
        summary=f"In-scope attack path ({len(rows)} hop(s)); analysis only.",
        data={
            "hops": rows,
            "coverage": counts,
            "executed": False,
        },
        next_actions=[
            "Hand each hop to mitre-mapping",
            "purple-feedback on any potential-evidence hop",
            "Do not execute the path",
        ],
    )
