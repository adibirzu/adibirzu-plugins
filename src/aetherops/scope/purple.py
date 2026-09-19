"""Purple-team pairing: one red observation → one blue detection + control.

Analysis only. Inverse of evasion — never writes hide/bypass steps.
"""

from __future__ import annotations

from typing import Any

from aetherops.scope.coverage import normalize_technique, unpaired_findings
from aetherops.scope.verbs import contains_payload_shape
from aetherops.types import Observation

EVASION_SHAPES = (
    "how to hide",
    "how the attacker would hide",
    "disable defender",
    "bypass edr",
    "evade detection",
    "uninstall av",
    "kill epp",
    "blind the soc",
)


def _blob(*parts: str) -> str:
    return " ".join(p or "" for p in parts).lower()


def assess_purple_pair(
    *,
    observation: str,
    detection_name: str,
    data_source: str,
    logic: str,
    control: str,
    technique: str = "unknown",
    coverage: str = "gap",
) -> Observation:
    """Require a complete defensive pair. Refuse evasion or payload text."""
    required = {
        "observation": observation,
        "detection_name": detection_name,
        "data_source": data_source,
        "logic": logic,
        "control": control,
    }
    missing = [key for key, value in required.items() if not (value or "").strip()]
    if missing:
        return Observation(
            status="error",
            summary=f"REFUSE {missing[0]}",
            root_cause_hint=f"Purple pair missing {', '.join(missing)}.",
            stop_condition="Do not ship a red finding without a blue detection and purple control.",
            data={"missing": missing},
        )

    joined = _blob(observation, detection_name, logic, control)
    if contains_payload_shape(joined) or any(shape in joined for shape in EVASION_SHAPES):
        return Observation(
            status="error",
            summary="REFUSE evasion",
            root_cause_hint="Purple pair contained evasion or payload-shaped text.",
            stop_condition="Inverse of evasion. Rewrite as a detection in words.",
            data={"scope_refused": True},
        )

    allowed_coverage = {"covered", "partial", "gap"}
    cov = (coverage or "gap").strip().lower()
    if cov not in allowed_coverage:
        cov = "gap"

    tech = normalize_technique(technique)
    return Observation(
        status="success",
        summary=f"Purple pair ready ({cov}) for {tech}.",
        data={
            "observation": observation.strip(),
            "detection": detection_name.strip(),
            "data_source": data_source.strip(),
            "logic": logic.strip(),
            "control": control.strip(),
            "technique": tech,
            "coverage": cov,
            "evasion": False,
        },
        next_actions=[
            "Hand the pair to evidence-report",
            "Do not add Sigma that needs a cloud lookup",
        ],
    )


def require_pairs_before_report(
    findings: list[dict[str, Any]],
    pairs: list[dict[str, Any]],
) -> Observation:
    """Hard gate: every red finding needs a blue detection + purple control."""
    if not findings:
        return Observation(
            status="success",
            summary="No red findings; report skeleton is allowed.",
            data={"missing": [], "report_ready": True},
        )
    valid_pairs: list[dict[str, Any]] = []
    for p in pairs:
        res = pair_from_card(p)
        if res.status == "success":
            valid_pairs.append(res.data)
    missing = unpaired_findings(findings, valid_pairs)
    if missing:
        return Observation(
            status="error",
            summary="REFUSE purple: red finding missing purple pair.",
            root_cause_hint="Force blue-detection + purple control before the customer report.",
            stop_condition="Do not ship a red finding without a blue detection and purple control.",
            data={"missing": missing, "report_ready": False, "scope_refused": True},
            next_actions=["Run purple-feedback on each missing finding"],
        )
    return Observation(
        status="success",
        summary=f"Purple pairs complete for {len(findings)} finding(s).",
        data={"missing": [], "report_ready": True, "count": len(findings)},
    )


def pair_from_card(card: dict[str, Any]) -> Observation:
    return assess_purple_pair(
        observation=str(card.get("observation") or card.get("red") or ""),
        detection_name=str(card.get("detection_name") or card.get("detection") or ""),
        data_source=str(card.get("data_source") or card.get("source") or ""),
        logic=str(card.get("logic") or ""),
        control=str(card.get("control") or card.get("purple") or ""),
        technique=str(card.get("technique") or card.get("attck") or "unknown"),
        coverage=str(card.get("coverage") or "gap"),
    )
