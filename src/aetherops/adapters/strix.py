"""Strix integration boundary.

Strix is a locally installed, autonomous security-testing CLI.  AetherOps
therefore exposes inventory and an exact, non-executing handoff only.  The
operator must independently run the displayed command after the normal signed
engagement and scope gates; this adapter never installs Strix, starts Docker,
or launches a scan.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from shutil import which

from typing import Any

from aetherops.config import ROOT
from aetherops.harness.observation import err, ok, warn
from aetherops.types import Observation


ExecutableFinder = Callable[[str], str | None]


def resolve_strix_mcp_path(mcp_config: Path) -> Path:
    """Pin MCP config to an absolute path (repo-relative when not absolute)."""
    path = Path(mcp_config).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def load_strix_mcp_servers(mcp_config: Path) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Parse the explicit Strix MCP file. Empty list is the safe default."""
    path = resolve_strix_mcp_path(mcp_config)
    if not path.is_file():
        return None, "Strix MCP config is missing; refusing to construct a scan command."
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "Strix MCP config is not valid JSON; refusing to construct a scan command."
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        return None, "Strix MCP config must be a JSON array of server objects."
    return raw, None


def strix_inventory(
    *,
    executable_finder: ExecutableFinder | None = None,
    mcp_config: Path,
) -> Observation:
    """Report local Strix and its explicit per-run MCP configuration."""
    finder = executable_finder or which
    executable = finder("strix") or None
    path = resolve_strix_mcp_path(mcp_config)
    servers, problem = load_strix_mcp_servers(path)
    data = {
        "present": executable is not None,
        "executable": executable,
        "mcp_config": str(path),
        "mcp_config_present": path.is_file(),
        "mcp_valid": problem is None,
        "server_count": len(servers or []),
        "executed": False,
    }
    if executable is None:
        return warn(
            "Strix CLI is not installed; no scan was attempted.",
            data=data,
            next_actions=[
                "Install Strix deliberately in the approved Kali/lab runtime, then rerun inventory.",
                "Review the explicit Strix MCP config before every run.",
            ],
        )
    return ok(
        "Strix CLI is locally available; scan execution remains operator-gated.",
        data=data,
        next_actions=["Create a signed engagement, then review a strix scan plan."],
    )


def strix_scan_plan(
    *,
    target: str,
    mcp_config: Path,
    executable_finder: ExecutableFinder | None = None,
) -> Observation:
    """Build, but never execute, the smallest bounded Strix CLI invocation."""
    path = resolve_strix_mcp_path(mcp_config)
    cleaned = (target or "").strip()
    if not cleaned:
        return err(
            "Strix plan requires an explicit in-scope target.",
            data={"executed": False, "mcp_config": str(path)},
            stop_condition="Do not construct a targetless autonomous scan.",
        )
    servers, problem = load_strix_mcp_servers(path)
    if problem:
        return err(
            problem,
            data={"executed": False, "mcp_config": str(path)},
            stop_condition="Review and create an explicit per-run MCP config before a Strix handoff.",
        )
    finder = executable_finder or which
    executable = finder("strix") or None
    if executable is None:
        return warn(
            "Strix CLI is not installed; scan plan cannot be handed off.",
            data={
                "executed": False,
                "target": cleaned,
                "mcp_config": str(path),
                "server_count": len(servers or []),
            },
            next_actions=["Install Strix deliberately in the approved Kali/lab runtime, then rerun inventory."],
        )
    command = [
        executable,
        "--non-interactive",
        "--scan-mode",
        "quick",
        "--target",
        cleaned,
        "--mcp-config",
        str(path),
    ]
    return ok(
        "Strix quick-scan command planned; it was not executed.",
        data={
            "executed": False,
            "target": cleaned,
            "mcp_config": str(path),
            "server_count": len(servers or []),
            "command": command,
        },
        next_actions=["Use only after a signed engagement confirms this exact target and MCP configuration."],
    )
