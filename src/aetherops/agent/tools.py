"""Tool schema advertised to the local model. Read-only first; no exploit verbs."""

from __future__ import annotations

from aetherops.types import ToolCall

ADAPTER_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_adapter",
            "description": (
                "Run an allowlisted local adapter. Read-only verbs: health, inventory, next, gap. "
                "Stage planner: name=plan verb=next (readonly; next stage or STOP). "
                "Landscape: name=landscape verb=inventory|gap|map (StationX AI-tool catalog). "
                "Completeness: name=completeness verb=check. "
                "WebHackersWeapons techniques: name=whw verb=coverage|next|weapons (readonly, no LLM). "
                "Gated exploit/payload names: name=whw verb=draft with weapon=<id> on signed L3 (words only). "
                "Assessment packs: name=pack verb=web|infra|k8s|estate with an in-scope target. "
                "Estate MCP/skill scanners: name=estate verb=mcp_scan|skill_scan|checklist "
                "with path= under the workspace (never vault/). Missing local CLI → STOP. "
                "Offsec scanners: name=offsec verb=port_scan|owasp_scan|mcp_scan|... (passive only). "
                "MCP planner: name=mcp verb=inventory or an allowlisted scan verb. "
                "Estate extensions: name=estate verb=guardrails|modelscan (run-or-STOP, local only). "
                "Do not call exploit, payload, C2, or exfil verbs — they are denied. "
                "Do not pass extra arguments (payload, cmd, lhost, script). "
                "Library playbooks: name=library verb=search|show|load with query= or skill=. "
                "Frontmatter scan first; never dump the full catalog. Dual-use load without "
                "signed allow_exploit_dev returns SCOPE DENIED. library.run is never live. "
                "Prompt-hacking catalog: name=prompt_hacking verb=search|show|load with query= or skill=. "
                "Citation frontmatter only; dual-use jailbreak-body load without signed "
                "allow_exploit_dev returns SCOPE DENIED. prompt_hacking.run is never live. "
                "HackAgent citation catalog: name=ha_catalog verb=search|show|load with query= or skill=. "
                "Technique/risk/dataset names only; dual-use unsigned load returns SCOPE DENIED. "
                "ha_catalog.run is never live. "
                "Live scanners require a signed engagement, allow_live_tools, "
                "autonomy_level >= 1, and an explicit in-scope target — except "
                "estate mcp_scan/skill_scan, which are scoped by path= instead. "
                "Exploit-dev verbs are hidden unless the loaded engagement sets allow_exploit_dev."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Adapter name such as hexstrike, tempest, or garak",
                    },
                    "verb": {
                        "type": "string",
                        "description": "Allowlisted verb such as health or inventory",
                    },
                    "target": {
                        "type": "string",
                        "description": "Optional in-scope host or IP. Omit for health/inventory.",
                    },
                    "live": {
                        "type": "boolean",
                        "description": "True only after a signed engagement. Default false.",
                    },
                    "query": {
                        "type": "string",
                        "description": "Frontmatter or SlowMist checklist search when name=library, prompt_hacking, ha_catalog, or estate checklist.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Local mcp.json or skill directory for estate.mcp_scan/skill_scan. Never vault/.",
                    },
                    "skill": {
                        "type": "string",
                        "description": "Library skill or citation id (prompt_hacking / ha_catalog) when verb=show|load|run.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max frontmatter hits when name=prompt_hacking or name=ha_catalog verb=search.",
                    },
                },
                "required": ["name", "verb"],
            },
        },
    }
]


def adapter_tools_for_engagement(allow_exploit_dev: bool = False) -> list[dict]:
    """Same schema; exploit-dev stays unadvertised unless the engagement flag is on."""
    tools = list(ADAPTER_TOOLS)
    if allow_exploit_dev:
        return tools
    return tools


def resolve_tool_call(tc: ToolCall) -> tuple[str, str, str | None, bool]:
    """Map a model tool call to (adapter, verb, target, live)."""
    raw_name = (tc.name or "").strip()
    args = tc.arguments or {}
    if raw_name == "run_adapter" or raw_name.endswith(".run_adapter"):
        name = str(args.get("name") or args.get("adapter") or "")
        verb = str(args.get("verb") or "inventory")
    elif "." in raw_name:
        name, verb = raw_name.split(".", 1)
    else:
        name = raw_name
        verb = str(args.get("verb") or "inventory")
    target = args.get("target") or args.get("host") or args.get("ip")
    live = bool(args.get("live") or False)
    return name, verb, str(target) if target else None, live
