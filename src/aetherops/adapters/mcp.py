"""MCP catalog + gated call planner for allowlisted assessment tools.

Orchestration only. This module never fires nmap/nuclei/trivy/checkov/
prowler/Nessus packets and never opens an SSH session. A live dispatch
requires an injected transport (tests) and still goes through authorize().
Permanent deny and extra/payload args stay fail-closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from aetherops.config import ROOT
from aetherops.mcp.router import load_mcp_config
from aetherops.scope.gate import authorize, load_engagement_or_deny
from aetherops.scope.verbs import (
    DENY_SUBSTRINGS,
    extra_arg_keys,
    is_exploit_dev,
    is_permanent_deny,
    is_readonly_verb,
)
from aetherops.types import Engagement, Observation

ALLOWLISTED_VERBS = frozenset(
    {
        "health",
        "inventory",
        "nmap_scan",
        "nuclei_scan",
        "trivy_scan",
        "checkov_iac_scan",
        "prowler_scan",
        "amass_scan",
        "subfinder_scan",
        "gobuster_scan",
        "nikto_scan",
    }
)

# Nessus live scan stays unwired; inventory is the only honest verb.
NESSUS_VERBS = frozenset({"inventory"})

VERB_TO_SERVER = {
    "health": "hexstrike-lab",
    "inventory": "hexstrike-lab",
    "nmap_scan": "hexstrike-lab",
    "nuclei_scan": "hexstrike-lab",
    "trivy_scan": "hexstrike-lab",
    "checkov_iac_scan": "kubernetes-lab",
    "prowler_scan": "hexstrike-lab",
    "amass_scan": "hexstrike-lab",
    "subfinder_scan": "hexstrike-lab",
    "gobuster_scan": "hexstrike-lab",
    "nikto_scan": "hexstrike-lab",
}

DEFAULT_MCP_FILE = ROOT / "configs" / "mcp.example.json"


class McpTransport(Protocol):
    def __call__(self, plan: dict[str, Any]) -> Observation: ...


def mcp_config_path(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    local = ROOT / "configs" / "mcp.json"
    if local.is_file():
        return local
    return DEFAULT_MCP_FILE


def load_mcp_catalog(path: Path | None = None) -> dict[str, Any]:
    cfg = load_mcp_config(mcp_config_path(path))
    servers = {}
    for name, server in cfg.mcp_servers.items():
        if name.startswith("_") or server.disabled:
            continue
        cleaned = {
            k: v
            for k, v in server.model_dump(by_alias=True).items()
            if not str(k).startswith("_") and v is not None
        }
        servers[name] = cleaned
    return {
        "path": str(mcp_config_path(path)),
        "servers": servers,
        "allowlisted_verbs": sorted(ALLOWLISTED_VERBS),
    }


def inventory_mcp(path: Path | None = None) -> Observation:
    catalog = load_mcp_catalog(path)
    return Observation(
        status="success",
        summary=f"{len(catalog['servers'])} MCP server(s) catalogued (orchestration only).",
        data={
            **catalog,
            "executed": False,
            "egress": False,
        },
        next_actions=[
            "Copy configs/mcp.example.json to gitignored configs/mcp.json for lab hosts",
            "Drive allowlisted verbs through plan_mcp_call; do not add exploit servers",
        ],
    )


def _adapter_for_verb(verb: str, *, nessus: bool = False) -> str:
    if nessus or verb.startswith("nessus"):
        return "nessus"
    return "hexstrike"


def _allowlisted(verb: str, *, nessus: bool = False) -> bool:
    action = (verb or "").strip().lower()
    if nessus or action.startswith("nessus"):
        return action in NESSUS_VERBS or action.endswith(".inventory")
    return action in ALLOWLISTED_VERBS


def plan_mcp_call(
    *,
    verb: str,
    engagement: Engagement,
    target: str | None = None,
    live: bool = False,
    airgap: bool = True,
    arguments: dict[str, Any] | None = None,
    catalog_path: Path | None = None,
    nessus: bool = False,
) -> Observation:
    """Authorize and describe one allowlisted MCP call. Never executes it."""
    action = (verb or "").strip().lower()
    adapter = _adapter_for_verb(action, nessus=nessus)
    tool = f"{adapter}.{action}"

    extra = extra_arg_keys(arguments)
    if extra:
        return Observation(
            status="error",
            summary="Denied: unexpected tool arguments (fail closed).",
            root_cause_hint=f"Unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments. Advertised keys only.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )
    if is_permanent_deny(tool) or is_permanent_deny(action) or any(
        tok in tool for tok in DENY_SUBSTRINGS
    ):
        return Observation(
            status="error",
            summary="Denied: exploit/payload/exfil verbs are not available.",
            stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
            data={"scope_refused": True, "tool": tool, "executed": False},
        )
    if is_exploit_dev(tool) or is_exploit_dev(action):
        return Observation(
            status="error",
            summary="Denied: exploit/payload/exfil verbs are not available.",
            stop_condition="Do not retry exploit-dev verbs. They require a signed flag and Phase 5.",
            data={"scope_refused": True, "tool": tool, "executed": False},
        )
    if not _allowlisted(action, nessus=nessus or adapter == "nessus"):
        return Observation(
            status="error",
            summary="Denied: verb is not on the MCP allowlist.",
            root_cause_hint=f"{action} is not an allowlisted assessment verb.",
            stop_condition="Use health/inventory/nmap_scan/nuclei_scan/trivy_scan/checkov_iac_scan/prowler_scan/amass_scan/subfinder_scan/gobuster_scan/nikto_scan only.",
            data={"scope_refused": True, "verb": action, "executed": False},
        )

    blocked = authorize(
        tool=tool,
        verb=action,
        target=target,
        engagement=engagement,
        airgap=airgap,
        internet_required=False,
        live=live,
        arguments=arguments,
    )
    if blocked:
        data = dict(blocked.data or {})
        data.update({"scope_refused": True, "executed": False, "egress": False})
        return blocked.model_copy(update={"data": data})

    catalog = load_mcp_catalog(catalog_path)
    server_name = "hexstrike-lab" if adapter == "nessus" else VERB_TO_SERVER.get(action, "hexstrike-lab")
    server = (catalog.get("servers") or {}).get(server_name) or {}
    plan = {
        "adapter": adapter,
        "verb": action,
        "target": target,
        "live": live,
        "server": server_name,
        "command": server.get("command"),
        "allowlisted": True,
        "executed": False,
        "egress": False,
        "readonly": is_readonly_verb(action),
    }
    if live and adapter == "nessus" and action != "inventory":
        return Observation(
            status="error",
            summary="STOP live-unwired: Nessus live scan is not implemented.",
            stop_condition="STOP live-unwired. Inventory only for lab Nessus.",
            data={**plan, "scope_refused": True},
        )
    if live and not is_readonly_verb(action):
        return Observation(
            status="warning",
            summary=f"ORCHESTRATED {adapter}.{action} (not dispatched).",
            root_cause_hint="MCP planner produced a gated call spec. No packets were sent.",
            stop_condition="STOP live-dispatch-unwired. Inject a test transport to simulate dispatch only.",
            data=plan,
            next_actions=[
                "Keep the call behind the scope gate",
                "Do not invent scanner results",
                "Pair any later observation with purple-feedback",
            ],
        )
    return Observation(
        status="success",
        summary=f"MCP plan ready for {adapter}.{action} (not live).",
        data=plan,
        next_actions=["Inventory first", "Do not self-escalate to live"],
    )


def dispatch_mcp_call(plan: dict[str, Any], transport: McpTransport | None = None) -> Observation:
    """Optional dispatch hook. Default: refuse to send packets."""
    verb = str((plan or {}).get("verb") or "")
    adapter = str((plan or {}).get("adapter") or "hexstrike")
    tool = f"{adapter}.{verb}"
    if is_permanent_deny(tool) or is_exploit_dev(tool) or not _allowlisted(verb, nessus=adapter == "nessus"):
        return Observation(
            status="error",
            summary="Denied: exploit/payload/exfil verbs are not available.",
            stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
            data={"scope_refused": True, "executed": False},
        )
    if transport is None:
        return Observation(
            status="warning",
            summary="STOP live-dispatch-unwired: no MCP transport configured.",
            stop_condition="STOP live-dispatch-unwired. Orchestration only.",
            data={**(plan or {}), "executed": False, "egress": False},
        )
    result = transport(plan)
    data = dict(result.data or {})
    data.setdefault("executed", False)
    data.setdefault("egress", False)
    return result.model_copy(update={"data": data})


def plan_from_settings(
    *,
    verb: str,
    target: str | None,
    live: bool,
    engagement_file: Path,
    airgap: bool = True,
    arguments: dict[str, Any] | None = None,
    catalog_path: Path | None = None,
    nessus: bool = False,
) -> Observation:
    engagement, load_err = load_engagement_or_deny(engagement_file)
    if load_err or engagement is None:
        return load_err or Observation(
            status="error",
            summary="SCOPE DENIED: engagement file unreadable.",
            stop_condition="SCOPE DENIED. Do not retry without a readable signed engagement.",
            data={"scope_refused": True, "executed": False},
        )
    return plan_mcp_call(
        verb=verb,
        engagement=engagement,
        target=target,
        live=live,
        airgap=airgap,
        arguments=arguments,
        catalog_path=catalog_path,
        nessus=nessus,
    )
