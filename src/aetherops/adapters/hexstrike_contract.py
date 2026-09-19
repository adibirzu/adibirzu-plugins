"""HexStrike-enhanced HTTP verb → Flask route map (PRD-E).

AetherOps MCP verbs such as ``nmap_scan`` post ``/api/tools/nmap`` on
hexstrike-ai-enhanced / HexForge. Guessing ``/api/tools/{verb}`` misses the
engine. Routes not in this table stay unreachable even if Flask serves them.
"""

from __future__ import annotations

from typing import Any

# Live POST map only. OSINT (amass/subfinder) and ffuf stay off this table.
HEXSTRIKE_VERB_ROUTES: dict[str, str] = {
    "nmap_scan": "/api/tools/nmap",
    "nuclei_scan": "/api/tools/nuclei",
    "trivy_scan": "/api/tools/trivy",
    "checkov_iac_scan": "/api/tools/checkov",
    "prowler_scan": "/api/tools/prowler",
}

# Honest inventory names that must not become live POSTs.
HEXSTRIKE_INVENTORY_ROUTES: dict[str, str] = {
    **HEXSTRIKE_VERB_ROUTES,
    "gobuster_scan": "/api/tools/gobuster",
    "nikto_scan": "/api/tools/nikto",
    "httpx_probe": "/api/tools/httpx",
    "katana_crawl": "/api/tools/katana",
}

# Binary name from GET /health tools_status → AetherOps verb.
HEXSTRIKE_TOOL_TO_VERB: dict[str, str] = {
    path.rsplit("/", 1)[-1]: verb for verb, path in HEXSTRIKE_INVENTORY_ROUTES.items()
}

FORBIDDEN_HEXSTRIKE_PATHS: tuple[str, ...] = (
    "/api/command",
    "/api/payloads/generate",
    "/api/ai/generate_payload",
    "/api/v2/evolution/execute",
    "/api/tools/sqlmap",
    "/api/tools/metasploit",
    "/api/tools/msfvenom",
)


def hexstrike_route_for(verb: str) -> str | None:
    """Return the Flask path for an allowlisted verb, or None if unmapped."""
    action = (verb or "").strip().lower()
    route = HEXSTRIKE_VERB_ROUTES.get(action)
    if route is None or route in FORBIDDEN_HEXSTRIKE_PATHS:
        return None
    return route


def verbs_from_tools_status(tools_status: Any) -> list[str]:
    """Map HexStrike ``tools_status`` booleans onto AetherOps verbs.

    Unknown or denied binaries never become verbs.
    """
    if not isinstance(tools_status, dict):
        return []
    verbs: list[str] = []
    for raw_name, present in tools_status.items():
        if not present:
            continue
        stem = str(raw_name).strip().lower().rsplit("/", 1)[-1]
        verb = HEXSTRIKE_TOOL_TO_VERB.get(stem)
        if verb:
            verbs.append(verb)
    return sorted(dict.fromkeys(verbs))


def verbs_from_health_payload(payload: Any) -> list[str] | None:
    """Map ``GET /health`` JSON onto verbs.

    Returns a list (possibly empty) when ``tools_status`` is a dict.
    Returns None when that field is missing or unusable so callers may
    fall back to a catalog GET.
    """
    if not isinstance(payload, dict) or "tools_status" not in payload:
        return None
    status = payload.get("tools_status")
    if not isinstance(status, dict):
        return None
    return verbs_from_tools_status(status)
