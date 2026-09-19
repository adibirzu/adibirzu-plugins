"""End-to-end assessment packs: recon → enumerate → report-ready.

Each stage is re-authorized. Out-of-scope targets fail closed on the
first step. Live verbs are planned through the MCP catalog and are not
executed. A pack is report-ready only when every Potential finding has
a purple pair (blue detection + control).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from aetherops.adapters.mcp import plan_mcp_call
from aetherops.plan.stages import can_live
from aetherops.scope.attack_path import assess_attack_path
from aetherops.scope.coverage import build_coverage_matrix, unpaired_findings
from aetherops.scope.gate import load_engagement_or_deny, target_in_scope
from aetherops.scope.purple import assess_purple_pair
from aetherops.scope.step import authorize_step, should_halt
from aetherops.types import Engagement, Observation

PackName = Literal["web", "infra", "k8s", "estate", "ai-estate"]

PACK_STEPS: dict[str, list[dict[str, Any]]] = {
    "web": [
        {"adapter": "hexstrike", "verb": "health", "live": False, "technique": "T1595"},
        {"adapter": "hexstrike", "verb": "inventory", "live": False, "technique": "T1595"},
        {"adapter": "hexstrike", "verb": "nmap_scan", "live": True, "technique": "T1046"},
        {"adapter": "hexstrike", "verb": "nuclei_scan", "live": True, "technique": "T1595.002"},
        {"adapter": "whw", "verb": "coverage", "live": False, "technique": "T1595"},
    ],
    "infra": [
        {"adapter": "hexstrike", "verb": "health", "live": False, "technique": "T1595"},
        {"adapter": "hexstrike", "verb": "inventory", "live": False, "technique": "T1046"},
        {"adapter": "hexstrike", "verb": "nmap_scan", "live": True, "technique": "T1046"},
        {"adapter": "nessus", "verb": "inventory", "live": False, "technique": "T1595.002"},
        {"adapter": "hexstrike", "verb": "trivy_scan", "live": True, "technique": "T1595.002"},
    ],
    "k8s": [
        {"adapter": "hexstrike", "verb": "health", "live": False, "technique": "T1613"},
        {"adapter": "hexstrike", "verb": "inventory", "live": False, "technique": "T1613"},
        {"adapter": "hexstrike", "verb": "checkov_iac_scan", "live": True, "technique": "T1613"},
        {"adapter": "hexstrike", "verb": "trivy_scan", "live": True, "technique": "T1195.001"},
    ],
    "estate": [
        {"adapter": "estate", "verb": "inventory", "live": False, "technique": "AML.T0040"},
        {"adapter": "estate", "verb": "sbom", "live": False, "technique": "T1195"},
        {"adapter": "estate", "verb": "remit", "live": False, "technique": "AML.T0040"},
        {"adapter": "estate", "verb": "scan", "live": True, "technique": "AML.T0024"},
        {"adapter": "estate", "verb": "robustness", "live": True, "technique": "AML.T0051"},
    ],
    "ai-estate": [
        {"adapter": "estate", "verb": "inventory", "live": False, "technique": "AML.T0040"},
        {"adapter": "estate", "verb": "sbom", "live": False, "technique": "T1195"},
        {"adapter": "estate", "verb": "remit", "live": False, "technique": "AML.T0040"},
        {"adapter": "estate", "verb": "scan", "live": True, "technique": "AML.T0024"},
        {"adapter": "estate", "verb": "robustness", "live": True, "technique": "AML.T0051"},
    ],
}


def _halt(obs: Observation, *, stages: list[dict[str, Any]]) -> Observation:
    data = dict(obs.data or {})
    data.update({"scope_refused": True, "executed": False, "stages": stages, "pack_complete": False})
    return obs.model_copy(update={"data": data, "status": "error"})


def run_pack(
    name: str,
    *,
    engagement: Engagement,
    target: str | None,
    live: bool = False,
    airgap: bool = True,
    pairs: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    scanner_runner: Callable[[str, str, dict[str, Any] | None], Any] | None = None,
) -> Observation:
    """Run one web/infra/k8s/estate pack as a gated orchestration pipeline."""
    pack = (name or "").strip().lower()
    if pack in {"inventory", "health"}:
        return Observation(
            status="success",
            summary="Assessment packs: web, infra, k8s, estate (orchestration only).",
            data={"packs": sorted(PACK_STEPS), "executed": False},
            next_actions=["Pass pack web|infra|k8s|estate and an in-scope target"],
        )
    if pack not in PACK_STEPS:
        return Observation(
            status="error",
            summary="SCOPE DENIED: unknown assessment pack.",
            stop_condition="Use pack web, infra, k8s, or estate only.",
            data={"scope_refused": True, "executed": False},
        )

    stages: list[dict[str, Any]] = []
    if not target:
        return _halt(
            Observation(
                status="error",
                summary="SCOPE DENIED: pack requires an explicit in-scope target.",
                stop_condition="SCOPE DENIED. Do not retry without a signed lab identity.",
            ),
            stages=stages,
        )
    if not target_in_scope(target, engagement):
        return _halt(
            Observation(
                status="error",
                summary="SCOPE DENIED: Target is out of engagement scope.",
                root_cause_hint="Pack target is outside scope_hosts/scope_cidrs or listed out_of_scope.",
                stop_condition="SCOPE DENIED. Do not retry out-of-scope targets.",
                data={"target": target},
            ),
            stages=stages,
        )

    for step in PACK_STEPS[pack]:
        step_live = bool(live and step["live"])
        gated = authorize_step(
            name=step["adapter"],
            verb=step["verb"],
            target=target,
            live=step_live,
            engagement=engagement,
            airgap=airgap,
        )
        if gated:
            stages.append(
                {
                    "adapter": step["adapter"],
                    "verb": step["verb"],
                    "live": step_live,
                    "status": gated.status,
                    "summary": gated.summary,
                    "executed": False,
                }
            )
            return _halt(gated, stages=stages)

        if step["adapter"] == "estate":
            from aetherops.adapters.estate import run_estate_adapter

            planned = run_estate_adapter(
                verb=step["verb"],
                target=target,
                live=step_live,
                engagement=engagement,
            )
        elif step["adapter"] == "whw":
            from aetherops.adapters.whw import run_whw_adapter

            planned = run_whw_adapter(
                step["verb"],
                engagement=engagement,
                live=False,
            )
        elif step_live and can_live(engagement) and step["adapter"] in {"hexstrike", "nessus"}:
            if scanner_runner is None:
                from aetherops.harness.observation import warn

                planned = warn(
                    "STOP live-unwired: no scanner transport (Lane 1 does not run live scanners).",
                    stop_condition="Do not invent scanner results. Inject a scanner_runner in tests; Lane 2 supplies live scanners.",
                    data={
                        "adapter": step["adapter"],
                        "verb": step["verb"],
                        "target": target,
                        "executed": False,
                    },
                )
            else:
                from aetherops.adapters.scanners import execute_live_scanner
                from aetherops.config import Settings

                planned = execute_live_scanner(
                    adapter=step["adapter"],
                    verb=step["verb"],
                    target=target,
                    engagement=engagement,
                    vault_dir=Settings().vault_dir,
                    airgap=airgap,
                    runner=scanner_runner,
                )
        else:
            planned = plan_mcp_call(
                verb=step["verb"],
                engagement=engagement,
                target=target,
                live=step_live,
                airgap=airgap,
                nessus=step["adapter"] == "nessus",
            )
        stages.append(
            {
                "adapter": step["adapter"],
                "verb": step["verb"],
                "live": step_live,
                "status": planned.status,
                "summary": planned.summary,
                "executed": bool(step_live and can_live(engagement) and (planned.data or {}).get("executed")),
                "technique": step["technique"],
            }
        )
        if should_halt(planned) and planned.status == "error":
            return _halt(planned, stages=stages)

    path = assess_attack_path(
        [
            {
                "from_asset": target,
                "to_asset": target,
                "technique": PACK_STEPS[pack][-1]["technique"],
                "coverage": "planned",
                "note": f"{pack} pack self-hop (analysis only)",
            }
        ],
        engagement,
    )
    if path.status == "error":
        return _halt(path, stages=stages)

    supplied_pairs = list(pairs or [])
    ready_pairs: list[dict[str, Any]] = []
    for card in supplied_pairs:
        paired = assess_purple_pair(
            observation=str(card.get("observation") or card.get("red") or ""),
            detection_name=str(card.get("detection_name") or card.get("detection") or ""),
            data_source=str(card.get("data_source") or card.get("source") or ""),
            logic=str(card.get("logic") or ""),
            control=str(card.get("control") or card.get("purple") or ""),
            technique=str(card.get("technique") or card.get("attck") or "unknown"),
            coverage=str(card.get("coverage") or "gap"),
        )
        if paired.status != "success":
            return _halt(paired, stages=stages)
        ready_pairs.append(paired.data)

    recorded_findings = list(findings or [])
    missing = unpaired_findings(recorded_findings, ready_pairs) if recorded_findings else []
    matrix = build_coverage_matrix(ready_pairs, extra_rows=path.data.get("hops") or [])
    report_ready = bool(recorded_findings) and not missing
    if recorded_findings and missing:
        return Observation(
            status="error",
            summary="REFUSE report: red finding missing purple pair.",
            stop_condition="Do not ship a red finding without a blue detection and purple control.",
            data={
                "pack": pack,
                "target": target,
                "stages": stages,
                "attack_path": path.data,
                "coverage": matrix.data,
                "missing_pairs": missing,
                "report_ready": False,
                "executed": False,
                "scope_refused": True,
            },
        )

    return Observation(
        status="success",
        summary=(
            f"{pack} pack planned against in-scope target; "
            + ("report-ready." if report_ready else "purple pair required before report.")
        ),
        data={
            "pack": pack,
            "target": target,
            "stages": stages,
            "attack_path": path.data,
            "coverage": matrix.data,
            "pairs": ready_pairs,
            "findings": recorded_findings,
            "report_ready": report_ready,
            "executed": False,
            "live_requested": live,
        },
        next_actions=[
            "Do not invent scanner results",
            "Pair every Potential finding via purple-feedback",
            "Hand report-ready cards to evidence-report",
        ],
    )


def run_pack_from_file(
    name: str,
    *,
    engagement_file,
    target: str | None,
    live: bool = False,
    airgap: bool = True,
    pairs: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> Observation:
    engagement, load_err = load_engagement_or_deny(engagement_file)
    if load_err or engagement is None:
        return load_err or Observation(
            status="error",
            summary="SCOPE DENIED: engagement file unreadable.",
            stop_condition="SCOPE DENIED. Do not retry without a readable signed engagement.",
            data={"scope_refused": True, "executed": False},
        )
    return run_pack(
        name,
        engagement=engagement,
        target=target,
        live=live,
        airgap=airgap,
        pairs=pairs,
        findings=findings,
    )
