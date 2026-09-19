"""Port/service → next assessment pack. Analysis only. No sqlmap/metasploit hops."""

from __future__ import annotations

from typing import Any

from aetherops.scope.completeness import HTTP_PORTS, K8S_PORTS
from aetherops.types import Observation

_AI_HINTS = ("/v1", "ollama", "mcp", "11434", "chat/completions")


def next_packs_from_ports(
    ports: list[int] | None,
    *,
    services: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Return pack verbs to run for the observed surface. Never exploit verbs."""
    found: list[str] = []
    portset = {int(p) for p in (ports or [])}
    if portset:
        found.append("infra")
    if portset & HTTP_PORTS:
        found.append("web")
    if portset & K8S_PORTS:
        found.append("k8s")
    blob = " ".join(
        str(svc.get("service") or svc.get("name") or svc.get("version") or "")
        for svc in (services or [])
        if isinstance(svc, dict)
    ).lower()
    if any(hint in blob for hint in _AI_HINTS):
        found.append("estate")
    return found


def correlate_observation(data: dict[str, Any] | None) -> Observation:
    payload = data or {}
    ports = [int(p) for p in (payload.get("ports") or []) if str(p).isdigit() or isinstance(p, int)]
    services = [s for s in (payload.get("services") or []) if isinstance(s, dict)]
    packs = next_packs_from_ports(ports, services=services)
    return Observation(
        status="success",
        summary=f"Correlate: {len(packs)} pack(s) from {len(ports)} port(s).",
        data={
            "ports": ports,
            "packs": packs,
            "executed": False,
            "sqlmap": False,
            "metasploit": False,
        },
        next_actions=["Run pack verbs through authorize_step", "Do not hop to sqlmap or metasploit"],
    )
