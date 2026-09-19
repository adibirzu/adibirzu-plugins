"""Deterministic attack-surface completeness checklist.

Analysis only. Does not scan, SSH, or mark findings Verified. Unsigned
engagements STOP without claiming coverage. No port map is a gap, not clean.
"""

from __future__ import annotations

from typing import Any

from aetherops.plan.stages import can_live, is_signed, next_stage, window_active
from aetherops.scope.coverage import unpaired_findings
from aetherops.scope.gate import target_in_scope
from aetherops.types import Engagement, Observation

HTTP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 3000, 8888})
K8S_PORTS = frozenset({6443, 10250, 2379, 10255, 10257, 10259})


def _ports(vault_index: dict[str, Any] | None) -> list[int]:
    idx = vault_index or {}
    raw = idx.get("ports") or []
    ports: list[int] = []
    for item in raw:
        try:
            ports.append(int(item))
        except (TypeError, ValueError):
            continue
    for finding in idx.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for port in finding.get("ports") or []:
            try:
                ports.append(int(port))
            except (TypeError, ValueError):
                continue
    return sorted(set(ports))


def _pack_ran(vault_index: dict[str, Any] | None, verb: str) -> bool:
    idx = vault_index or {}
    if verb in (idx.get("completed_stages") or []):
        return True
    for finding in idx.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        adapter = str(finding.get("adapter") or "").strip().lower()
        action = str(finding.get("verb") or "").strip().lower()
        if adapter == "pack" and action == verb:
            return True
        if adapter == "offsec" and verb == "web" and action in {"owasp_scan"}:
            return True
        if adapter == "offsec" and verb == "k8s" and action in {"k8s_scan"}:
            return True
    return False


def check_completeness(
    engagement: Engagement,
    vault_index: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    *,
    today: str | None = None,
) -> Observation:
    """Return covered / gap / n/a rows. Never claims clean without a port map."""
    rows: list[dict[str, str]] = []
    idx = vault_index or {}

    signed = is_signed(engagement) and window_active(engagement, today=today)
    if not signed:
        rows.append({"check": "engagement", "status": "gap", "note": "unsigned or inactive"})
        return Observation(
            status="warning",
            summary="Completeness STOP: unsigned or inactive engagement cannot claim coverage.",
            data={
                "complete": False,
                "drive_plan": False,
                "next": "STOP",
                "rows": rows,
                "executed": False,
            },
            stop_condition="STOP. Do not invent coverage for an unsigned engagement.",
        )

    target = None
    for host in engagement.scope_hosts or []:
        text = str(host).strip()
        if text and target_in_scope(text, engagement):
            target = text
            break
    if not target:
        rows.append({"check": "in-scope-host", "status": "gap", "note": "no in-scope host"})
        return Observation(
            status="warning",
            summary="Completeness STOP: no in-scope host.",
            data={
                "complete": False,
                "drive_plan": False,
                "next": "STOP",
                "rows": rows,
                "executed": False,
            },
            stop_condition="STOP. Planner does not invent targets.",
        )
    rows.append({"check": "engagement", "status": "covered", "note": target})

    ports = _ports(idx)
    if not ports:
        rows.append({"check": "port-map", "status": "gap", "note": "no recon port map"})
        nxt = next_stage(engagement, inventory, idx, today=today)
        drive = (nxt.data or {}).get("next") not in {None, "STOP"}
        return Observation(
            status="warning",
            summary="Completeness gap: no port map; not a clean negative.",
            data={
                "complete": False,
                "drive_plan": drive,
                "next": (nxt.data or {}).get("next") or "STOP",
                "rows": rows,
                "ports": ports,
                "executed": False,
            },
        )
    rows.append({"check": "port-map", "status": "covered", "note": f"{len(ports)} port(s)"})

    unnamed = [p for p in ports if p and not _service_named(idx, p)]
    if unnamed:
        rows.append(
            {
                "check": "service-names",
                "status": "gap",
                "note": "open ports without service names: " + ",".join(str(p) for p in unnamed),
            }
        )
    else:
        rows.append({"check": "service-names", "status": "covered", "note": "named or unknown-service"})

    http = sorted(HTTP_PORTS.intersection(ports))
    if http:
        status = "covered" if _pack_ran(idx, "web") else "gap"
        rows.append({"check": "pack-web", "status": status, "note": ",".join(str(p) for p in http)})
    else:
        rows.append({"check": "pack-web", "status": "n/a", "note": "no HTTP(S) ports"})

    k8s = sorted(K8S_PORTS.intersection(ports))
    if k8s:
        status = "covered" if _pack_ran(idx, "k8s") else "gap"
        rows.append({"check": "pack-k8s", "status": status, "note": ",".join(str(p) for p in k8s)})
    else:
        rows.append({"check": "pack-k8s", "status": "n/a", "note": "no Kubernetes ports"})

    findings = [f for f in (idx.get("findings") or []) if isinstance(f, dict)]
    pairs = [p for p in (idx.get("purple_pairs") or []) if isinstance(p, dict)]
    missing = unpaired_findings(findings, pairs) if findings else []
    if missing:
        rows.append({"check": "purple-pairs", "status": "gap", "note": f"{len(missing)} unpaired"})
    elif findings:
        rows.append({"check": "purple-pairs", "status": "covered", "note": "paired"})
    else:
        rows.append({"check": "purple-pairs", "status": "n/a", "note": "no findings yet"})

    gap = any(row["status"] == "gap" for row in rows)
    nxt = next_stage(engagement, inventory, idx, today=today)
    nxt_name = (nxt.data or {}).get("next") or "STOP"
    complete = (not gap) and nxt_name == "STOP"
    drive = (not complete) and nxt_name != "STOP" and can_live(engagement, today=today)
    return Observation(
        status="success" if complete else "warning",
        summary=(
            "Completeness STOP: checklist covered or n/a."
            if complete
            else f"Completeness incomplete; next={nxt_name}."
        ),
        data={
            "complete": complete,
            "drive_plan": drive or (not complete and nxt_name != "STOP"),
            "next": "STOP" if complete else nxt_name,
            "rows": rows,
            "ports": ports,
            "executed": False,
        },
    )


def _service_named(vault_index: dict[str, Any], port: int) -> bool:
    for finding in vault_index.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for svc in finding.get("services") or []:
            if not isinstance(svc, dict):
                continue
            try:
                if int(svc.get("port")) == port:
                    name = str(svc.get("service") or svc.get("name") or "").strip()
                    return bool(name)
            except (TypeError, ValueError):
                continue
    return False


def should_drive_plan(
    engagement: Engagement,
    vault_index: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    *,
    today: str | None = None,
) -> bool:
    """True when the loop should inject plan.next instead of ending the turn."""
    obs = check_completeness(engagement, vault_index, inventory, today=today)
    return bool((obs.data or {}).get("drive_plan"))
