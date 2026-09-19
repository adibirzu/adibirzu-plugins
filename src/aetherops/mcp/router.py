"""Scoped multi-MCP capability router and honest inventory.

Provides the governance plane between security MCP servers and the model.
Intersects advertised tools with adapter allowlists and deny lists
(allow ∩ advertised ∩ not-denied), fails closed on missing/timed-out
servers, and logs audit traces to a gitignored vault path when an
engagement is loaded.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

from aetherops.adapters.hexstrike_contract import verbs_from_health_payload
from aetherops.airlock.egress import EgressDenied, EgressSession
from aetherops.config import ROOT, Settings
from aetherops.harness.observation import ok, warn
from aetherops.scope.verbs import (
    DENY_SUBSTRINGS,
    is_exploit_dev,
    is_permanent_deny,
)
from aetherops.types import Engagement, Observation


class McpServerConfig(BaseModel):
    """Configuration for a single MCP server."""

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    transport: str | None = None
    disabled: bool = False
    comment: str | list[str] | None = Field(default=None, alias="_comment")


class McpConfigFile(BaseModel):
    """Schema for configs/mcp.json or configs/mcp.example.json."""

    comment: str | list[str] | None = Field(default=None, alias="_comment")
    mcp_servers: dict[str, McpServerConfig] = Field(default_factory=dict, alias="mcpServers")


def expand_env_vars(val: str, environ: Mapping[str, str] | None = None) -> str:
    """Expand ${VAR:-default}, ${VAR}, and $VAR in configuration strings."""
    env = os.environ if environ is None else environ

    def _replace_braced(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default_val = match.group(2)
        v = env.get(var_name)
        if v is not None and v != "":
            return v
        return default_val if default_val is not None else ""

    def _replace_simple(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return env.get(var_name, "")

    res = re.sub(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}", _replace_braced, str(val))
    res = re.sub(r"\$([A-Za-z0-9_]+)", _replace_simple, res)
    return res


def _expand_obj(obj: Any, environ: Mapping[str, str] | None = None) -> Any:
    if isinstance(obj, str):
        return expand_env_vars(obj, environ)
    if isinstance(obj, list):
        return [_expand_obj(item, environ) for item in obj]
    if isinstance(obj, dict):
        return {k: _expand_obj(v, environ) for k, v in obj.items()}
    return obj


def load_mcp_config(
    path: Path | None = None, environ: Mapping[str, str] | None = None
) -> McpConfigFile:
    """Load and parse an MCP config file with environment variable expansion."""
    target_path = path or (ROOT / "configs" / "mcp.json")
    if not target_path.is_file():
        target_path = ROOT / "configs" / "mcp.example.json"
    if not target_path.is_file():
        return McpConfigFile()
    raw = json.loads(target_path.read_text(encoding="utf-8"))
    expanded = _expand_obj(raw, environ)
    return McpConfigFile.model_validate(expanded)


def filter_advertised_tools(
    advertised: Iterable[str | dict[str, Any]],
    allowlist: Iterable[str],
    adapter_name: str = "hexstrike",
    deny_patterns: Iterable[str] | None = None,
) -> list[str]:
    """Compute the filtered toolset: allow ∩ advertised ∩ not-denied.

    Permanently denied and exploit-dev verbs are stripped even if advertised
    by the server or listed in an allowlist.
    """
    allow = {str(a).strip().lower() for a in allowlist}
    deny_list = tuple(deny_patterns or ()) + DENY_SUBSTRINGS
    filtered: list[str] = []

    for item in advertised:
        if isinstance(item, dict):
            raw_name = str(item.get("name", "")).strip()
        else:
            raw_name = str(item).strip()
        if not raw_name:
            continue
        name = raw_name.lower()
        # Handle dotted prefix if present
        prefix = f"{adapter_name.lower()}."
        stem = name.removeprefix(prefix)
        full_tool = f"{adapter_name.lower()}.{stem}"

        # 1. Must be on the adapter's allowlist
        if stem not in allow and full_tool not in allow and name not in allow:
            continue

        # 2. Must not be permanently denied
        if is_permanent_deny(stem) or is_permanent_deny(full_tool) or is_permanent_deny(name):
            continue

        # 3. Must not be exploit-dev
        if is_exploit_dev(stem) or is_exploit_dev(full_tool) or is_exploit_dev(name):
            continue

        # 4. Must not match any deny pattern or substring
        if any(tok in stem or tok in full_tool or tok in name for tok in deny_list):
            continue

        filtered.append(stem)

    # Return unique, sorted list
    return sorted(dict.fromkeys(filtered))


def write_audit_log(
    vault_dir: Path,
    engagement: Engagement | None,
    *,
    tool: str,
    verb: str,
    target: str | None = None,
    live: bool = False,
    arguments: dict[str, Any] | None = None,
    allowed: bool = False,
    status: str = "error",
    summary: str = "",
    root_cause_hint: str | None = None,
    stop_condition: str | None = None,
) -> None:
    """Write an audit record to gitignored vault/audit.jsonl when an engagement is loaded."""
    if engagement is None:
        return
    try:
        vault_dir.mkdir(parents=True, exist_ok=True)
        audit_file = vault_dir / "audit.jsonl"
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "engagement_id": engagement.engagement_id,
            "tool": tool,
            "verb": verb,
            "target": target,
            "live": live,
            "allowed": allowed,
            "status": status,
            "summary": summary,
            "root_cause_hint": root_cause_hint,
            "stop_condition": stop_condition,
            "arguments": arguments,
        }
        with audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except (OSError, TypeError, ValueError):
        # Audit failures must not crash the gate
        pass


class McpServerUnavailableError(Exception):
    """Raised when an MCP server is unreachable or timed out."""


class McpRouter:
    """Capability router for scoped MCP server interaction."""

    def __init__(
        self,
        settings: Settings,
        http_client: httpx.Client | None = None,
        tool_fetcher: Callable[[str], list[str]] | None = None,
        presence_checker: Callable[[str], bool] | None = None,
        scanner_runner: Callable[[str, str, dict[str, Any] | None], Any] | None = None,
    ):
        self.settings = settings
        self._http_client = http_client
        self._tool_fetcher = tool_fetcher
        self._presence_checker = presence_checker
        self.scanner_runner = scanner_runner
        self._config: McpConfigFile | None = None

    @property
    def config(self) -> McpConfigFile:
        if self._config is None:
            self._config = load_mcp_config(self.settings.mcp_file)
        return self._config

    def list_servers(self) -> list[str]:
        return [
            name
            for name, s in self.config.mcp_servers.items()
            if not s.disabled and not name.startswith("_")
        ]

    def get_server_config(self, server_name: str) -> McpServerConfig | None:
        return self.config.mcp_servers.get(server_name)

    def is_server_present(self, server_name: str = "hexstrike-lab", timeout: float = 1.0) -> bool:
        """Check if an MCP server is reachable within timeout."""
        if self._presence_checker is not None:
            try:
                return bool(self._presence_checker(server_name))
            except (OSError, ValueError, TypeError, McpServerUnavailableError):
                return False

        if server_name in {"tempest", "tempest-lab"}:
            path = self.settings.tempest_path
            return bool(path) and Path(path).exists()

        if server_name in {"hexstrike", "hexstrike-lab"}:
            url = self.settings.get_hexstrike_url().rstrip("/") + "/health"
            try:
                with EgressSession(timeout=timeout, client=self._http_client) as client:
                    resp = client.get(url)
                return resp.status_code == 200
            except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError):
                return False

        server = self.get_server_config(server_name)
        if server and server.url:
            try:
                url = server.url.rstrip("/") + "/health"
                with EgressSession(timeout=timeout, client=self._http_client) as client:
                    resp = client.get(url)
                return resp.status_code == 200
            except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError):
                return False
        return server is not None

    def fetch_advertised_tools(
        self, server_name: str = "hexstrike-lab", timeout: float = 2.0
    ) -> list[str]:
        """Fetch advertised tools from an MCP server."""
        if self._tool_fetcher is not None:
            try:
                return self._tool_fetcher(server_name)
            except Exception as exc:
                raise McpServerUnavailableError(f"Server {server_name} error: {exc}") from exc

        if server_name in {"hexstrike", "hexstrike-lab"}:
            base_url = self.settings.get_hexstrike_url().rstrip("/")
            last_err: Exception | None = None
            try:
                with EgressSession(timeout=timeout, client=self._http_client) as client:
                    health = client.get(base_url + "/health")
                if health.status_code == 200:
                    payload = health.json()
                    mapped = verbs_from_health_payload(payload)
                    if mapped is not None:
                        return mapped
            except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError) as exc:
                last_err = exc
            endpoints = ["/api/tools", "/tools", "/mcp/tools"]
            for ep in endpoints:
                url = base_url + ep
                try:
                    with EgressSession(timeout=timeout, client=self._http_client) as client:
                        resp = client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict):
                            raw_tools = data.get("tools") or data.get("result", {}).get("tools", [])
                        elif isinstance(data, list):
                            raw_tools = data
                        else:
                            raw_tools = []
                        return [
                            t.get("name", "") if isinstance(t, dict) else str(t)
                            for t in raw_tools
                            if t
                        ]
                except (EgressDenied, httpx.HTTPError, OSError, ValueError) as exc:
                    last_err = exc
                    continue
            raise McpServerUnavailableError(
                f"HexStrike MCP server at {base_url} unreachable or timed out: {last_err}"
            )

        raise McpServerUnavailableError(f"No tool discovery implemented for {server_name}")

    def inventory_hexstrike(
        self,
        allowlist: Iterable[str],
        deny_patterns: Iterable[str] | None = None,
        timeout: float = 2.0,
    ) -> Observation:
        """Query HexStrike MCP and return an honest inventory of filtered tools."""
        try:
            advertised = self.fetch_advertised_tools("hexstrike-lab", timeout=timeout)
        except McpServerUnavailableError as exc:
            local = self.settings.hexstrike_path
            hint = (
                f"Local tree present at {local}"
                if local and Path(local).exists()
                else "No local HexStrike path"
            )
            return warn(
                f"HexStrike MCP unreachable ({exc}). {hint}.",
                root_cause_hint="Start hexstrike_server.py on 127.0.0.1:8888 or stay inventory-only.",
                retry="Start the local HexStrike server, then retry inventory/health.",
                stop_condition="Do not fall back to a remote 172.16.x host on an air-gapped engagement.",
                data={"present": False, "executed": False},
            )

        filtered = filter_advertised_tools(
            advertised, allowlist, adapter_name="hexstrike", deny_patterns=deny_patterns
        )
        return ok(
            f"HexStrike MCP inventory: {len(filtered)} tool(s) available ({len(advertised)} advertised, {len(advertised) - len(filtered)} filtered).",
            data={
                "present": True,
                "tools": filtered,
                "advertised_count": len(advertised),
                "filtered_count": len(filtered),
                "denied_count": len(advertised) - len(filtered),
                "executed": False,
            },
            next_actions=[
                "Drive allowlisted verbs through plan_mcp_call; do not add exploit servers"
            ],
        )

    def inventory_tempest(
        self,
        allowlist: Iterable[str] | None = None,
        deny_patterns: Iterable[str] | None = None,
        timeout: float = 2.0,
    ) -> Observation:
        """Planning-only inventory of the adjacent tree. Path probe, no remote host."""
        from aetherops.adapters.tempest import (
            DENIED_ARCHETYPES,
            PLANNING_INTERFACE,
            adjacent_tree_present,
            filter_tempest_tools,
        )

        if not adjacent_tree_present(self.settings.tempest_path):
            return warn(
                "T3MP3ST tree not configured or not detectable.",
                root_cause_hint="Set AETHEROPS_TEMPEST_PATH to the adjacent local tree, or stay inventory-only.",
                retry="Configure the local path, then retry inventory.",
                stop_condition="STOP. Missing adjacent tree. Do not fall back to a remote host.",
                data={"present": False, "executed": False, "adapter": "tempest", "tools": []},
            )

        allow = list(allowlist) if allowlist is not None else list(PLANNING_INTERFACE)
        if self._tool_fetcher is not None:
            try:
                advertised = self.fetch_advertised_tools("tempest-lab", timeout=timeout)
            except McpServerUnavailableError as exc:
                return warn(
                    f"T3MP3ST planning surface unreachable ({exc}).",
                    root_cause_hint="Adjacent tree path is set but the injected inventory source failed.",
                    retry="Fix the local inventory source, then retry.",
                    stop_condition="STOP. Do not fall back to a remote host.",
                    data={"present": False, "executed": False, "adapter": "tempest", "tools": []},
                )
        else:
            advertised = list(PLANNING_INTERFACE)

        extra_deny = tuple(deny_patterns or ()) + tuple(DENIED_ARCHETYPES)
        filtered = filter_tempest_tools(advertised, allowlist=allow, deny_patterns=extra_deny)
        return ok(
            f"T3MP3ST planning inventory: {len(filtered)} verb(s) available "
            f"({len(advertised)} advertised, {len(advertised) - len(filtered)} filtered).",
            data={
                "present": True,
                "adapter": "tempest",
                "tools": filtered,
                "advertised_count": len(advertised),
                "filtered_count": len(filtered),
                "denied_count": len(advertised) - len(filtered),
                "executed": False,
            },
            next_actions=["Drive inventory / mission_plan through the scope gate"],
        )

    def get_mcp_sbom(
        self,
        adapter_allowlists: Mapping[str, Iterable[str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate a Software Bill of Materials (SBOM) for configured MCP servers.

        Produces an audited catalog of servers with their allowlisted verbs,
        air-gap / internet requirement status, and live presence.
        """
        allow_map: dict[str, list[str]] = {
            "hexstrike-lab": [
                "health",
                "inventory",
                "nmap_scan",
                "nuclei_scan",
                "trivy_scan",
                "checkov_iac_scan",
                "prowler_scan",
            ],
            "hexstrike": [
                "health",
                "inventory",
                "nmap_scan",
                "nuclei_scan",
                "trivy_scan",
                "checkov_iac_scan",
                "prowler_scan",
            ],
            "nessus-lab": ["inventory"],
            "nessus": ["inventory"],
            "kubernetes-lab": ["checkov_iac_scan"],
            "tempest-lab": ["health", "inventory", "mission_plan"],
            "tempest": ["health", "inventory", "mission_plan"],
        }
        if adapter_allowlists:
            for k, v in adapter_allowlists.items():
                allow_map[k] = list(v)

        sbom: list[dict[str, Any]] = []
        for name, server in self.config.mcp_servers.items():
            if name.startswith("_") or server.disabled:
                continue
            present = self.is_server_present(name)
            server_allows = allow_map.get(
                name,
                allow_map.get(
                    name.replace("-lab", ""),
                    ["inventory", "health"],
                ),
            )
            # Filter allowlist to guarantee no deny verbs
            clean_allow = filter_advertised_tools(
                server_allows,
                allowlist=server_allows,
                adapter_name=name,
                deny_patterns=self.settings.adapters_file.exists() and [] or None,
            ) if server_allows else ["inventory"]

            # Internet required: false by default for local/ssh/loopback transports
            url = (server.url or "").lower()
            cmd = (server.command or "").lower()
            is_net = bool(
                ("http://" not in url and "https://" in url and "localhost" not in url and "127.0.0.1" not in url)
                or (cmd and cmd not in {"ssh", "python", "python3", "node", "npx", "docker", "uvx"})
            )

            sbom.append(
                {
                    "name": name,
                    "allow": clean_allow,
                    "verb_allow": clean_allow,
                    "internet_required": is_net,
                    "present": present,
                    "transport": server.transport or (
                        "http" if server.url else ("ssh" if server.command == "ssh" else "stdio")
                    ),
                    "command": server.command,
                    "url": server.url,
                }
            )
        return sbom

    def inventory_sbom(
        self,
        adapter_allowlists: Mapping[str, Iterable[str]] | None = None,
    ) -> Observation:
        """Return an Observation containing the MCP supply chain SBOM."""
        sbom = self.get_mcp_sbom(adapter_allowlists=adapter_allowlists)
        present_count = sum(1 for s in sbom if s.get("present", False))
        return ok(
            f"MCP SBOM: {len(sbom)} server(s) registered ({present_count} present, {len(sbom) - present_count} absent).",
            data={
                "sbom": sbom,
                "servers": [s["name"] for s in sbom],
                "present_count": present_count,
                "total_count": len(sbom),
                "executed": False,
            },
            next_actions=[
                "Inspect allowlisted verbs per MCP server",
                "Verify internet_required is False on air-gapped hosts",
            ],
        )

    def audit(
        self,
        engagement: Engagement | None,
        *,
        tool: str,
        verb: str,
        target: str | None = None,
        live: bool = False,
        arguments: dict[str, Any] | None = None,
        allowed: bool = False,
        status: str = "error",
        summary: str = "",
        root_cause_hint: str | None = None,
        stop_condition: str | None = None,
    ) -> None:
        """Record audit event to vault."""
        write_audit_log(
            self.settings.vault_dir,
            engagement,
            tool=tool,
            verb=verb,
            target=target,
            live=live,
            arguments=arguments,
            allowed=allowed,
            status=status,
            summary=summary,
            root_cause_hint=root_cause_hint,
            stop_condition=stop_condition,
        )


def generate_mcp_sbom(
    config_path: Path | None = None,
    settings: Settings | None = None,
    router: McpRouter | None = None,
) -> list[dict[str, Any]]:
    """Helper to generate MCP SBOM from config path or settings."""
    if router is not None:
        return router.get_mcp_sbom()
    active_settings = settings or Settings()
    if config_path is not None:
        active_settings.mcp_file = config_path
    return McpRouter(active_settings).get_mcp_sbom()
