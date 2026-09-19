"""AI-agent estate & LLM supply-chain assessment adapter (CP-6).

Provides the first-class scoped domain joining pentest + AI security + agent-IAM:
- Composes garak, pyrit, agentic_radar, praxen, promptmap as run-or-STOP.
- Enforces local Ollama only (no cloud AI judges, no prompt exfiltration).
- Produces MCP supply-chain SBOM with allowlisted verbs and air-gap verification.
- Re-authorizes all actions and fails closed on out-of-scope targets or missing tools.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from pathlib import Path
from shutil import which
from typing import Any

from aetherops.adapters.mcp_skill_scan import (
    DEFENSIVE_VERBS,
    get_defensive_scanners_status,
    run_defensive_scan,
)
from aetherops.config import ROOT, Settings
from aetherops.harness.observation import err, ok
from aetherops.mcp.router import McpRouter
from aetherops.scope.gate import target_in_scope
from aetherops.scope.verbs import extra_arg_keys
from aetherops.types import Engagement, Observation

COMPOSED_AI_TOOLS = {
    "garak": {
        "kind": "local_cli",
        "command": "garak",
        "side": "red",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Generative AI vulnerability & prompt injection evaluation vs local Ollama /v1",
        "atlas": "AML.T0051, AML.T0054",
    },
    "pyrit": {
        "kind": "python",
        "package": "pyrit",
        "side": "red",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Python Risk Identification Tool for AI security risk analysis",
        "atlas": "AML.T0051, AML.T0054, AML.T0040",
    },
    "agentic_radar": {
        "kind": "local_cli",
        "command": "agentic-radar",
        "alt_command": "agentic_radar",
        "package": "agentic_radar",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Static scan of agent workflows, prompt boundaries, and excessive agency",
        "atlas": "AML.T0024, AML.T0040",
    },
    "praxen": {
        "kind": "local_cli",
        "command": "praxen",
        "package": "praxen",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Worker remit vs implementation (RAISE agent-IAM verification)",
        "atlas": "AML.T0040, AML.T0024",
    },
    "promptmap": {
        "kind": "local_cli",
        "command": "promptmap",
        "package": "promptmap",
        "side": "red",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Prompt-injection attack surface mapping vs in-scope local model",
        "atlas": "AML.T0051",
    },
}

# These tools cover the explicitly catalogued AI-estate gaps.  Keep them
# separate from the established CP-6 set so inventory remains honest: their
# absence must stop a live guardrail or model-file scan rather than silently
# downgrading to another tool.
EXTENSION_AI_TOOLS = {
    "llm_guard": {
        "kind": "python",
        "command": "llm-guard",
        "package": "llm_guard",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Local prompt and response guardrail evaluation.",
        "atlas": "AML.T0051",
    },
    "nemo_guardrails": {
        "kind": "python",
        "command": "nemoguardrails",
        "package": "nemoguardrails",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Local policy guardrail evaluation for model interactions.",
        "atlas": "AML.T0051",
    },
    "modelscan": {
        "kind": "local_cli",
        "command": "modelscan",
        "package": "modelscan",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Local model-file supply-chain scanning.",
        "atlas": "AML.T0010",
    },
}

FORBIDDEN_CLOUD_PATTERNS = (
    "openai.com",
    "anthropic.com",
    "googleapis.com",
    "azure.com",
    "bedrock",
    "claude.ai",
    "cohere.ai",
    "api.deepseek.com",
    "promptfoo.app",
    "promptfoo.dev",
    "promptfoo.ai",
)

LOCAL_TARGET_PATTERNS = (
    r"^https?://(?:127\.0\.0\.1|localhost)(?::\d+)?(?:/.*)?$",
    r"^(?:127\.0\.0\.1|localhost)(?::\d+)?$",
    r"^127\.",
)


def _tool_is_present(meta: dict[str, Any]) -> bool:
    """Return whether an explicitly catalogued local tool is available."""
    cmd = meta.get("command")
    if cmd and which(cmd) is not None:
        return True
    alt_cmd = meta.get("alt_command")
    if alt_cmd and which(alt_cmd) is not None:
        return True
    pkg = meta.get("package")
    if pkg:
        try:
            return importlib.util.find_spec(pkg) is not None
        except (ImportError, ValueError, AttributeError):
            return False
    return False


def check_tool_presence(tool_name: str) -> bool:
    """Check if a composed AI-security tool is installed locally."""
    meta = COMPOSED_AI_TOOLS.get(tool_name)
    return _tool_is_present(meta) if meta else False


def get_extension_tools_status(
    presence_checker: Callable[[str], bool] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return local availability for AI-estate extension tools."""
    results: dict[str, dict[str, Any]] = {}
    for name, meta in EXTENSION_AI_TOOLS.items():
        present = bool(presence_checker(name)) if presence_checker else _tool_is_present(meta)
        results[name] = {**meta, "present": present}
    return results


def get_composed_tools_status(
    presence_checker: Callable[[str], bool] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return status of all composed AI tools."""
    checker = presence_checker or check_tool_presence
    results: dict[str, dict[str, Any]] = {}
    for name, meta in COMPOSED_AI_TOOLS.items():
        present = bool(checker(name))
        results[name] = {
            **meta,
            "present": present,
        }
    return results


def validate_local_target(
    target: str | None,
    engagement: Engagement | None = None,
) -> tuple[bool, str]:
    """Verify that target is strictly local Ollama or an in-scope lab asset.

    Refuses any cloud API endpoints or out-of-scope addresses.
    """
    if not target:
        return True, "Defaulting to loopback Ollama endpoint (http://127.0.0.1:11434/v1)"

    target_str = str(target).strip()
    target_lower = target_str.lower()

    # 1. Cloud API refusal
    for cloud in FORBIDDEN_CLOUD_PATTERNS:
        if cloud in target_lower:
            return (
                False,
                f"SCOPE DENIED: AI evaluation tools must point at local Ollama only (no cloud API '{cloud}').",
            )

    # 2. Loopback endpoints are always valid for AI eval
    if any(re.match(pat, target_lower) for pat in LOCAL_TARGET_PATTERNS):
        return True, "Loopback Ollama endpoint"

    # 3. If an engagement is provided, check that custom target is within scope
    if engagement is not None:
        # Strip protocol/port if checking IP/hostname
        cleaned_host = re.sub(r"^https?://", "", target_lower).split(":")[0].split("/")[0]
        if not target_in_scope(cleaned_host, engagement):
            return False, f"SCOPE DENIED: Target '{target}' is out of engagement scope."

    return True, "In-scope target"


def validate_modelscan_target(target: str | None) -> tuple[bool, str]:
    """Allow model-file scans only for local filesystem paths.

    ModelScan must never turn a supplied model identifier or URL into a
    network fetch.  Existence is deliberately not required here: a missing
    local file is a tool/runtime concern, whereas a URI is a scope denial.
    """
    if not target:
        return True, "Defaulting to local model files"
    candidate = str(target).strip()
    if not candidate:
        return False, "SCOPE DENIED: modelscan requires a local model-file path."
    if candidate.startswith(("//", "\\\\")) or "://" in candidate or candidate.lower().startswith(
        ("file:", "http:", "https:")
    ):
        return False, "SCOPE DENIED: modelscan accepts local model files only; remote URLs are forbidden."
    if {"vault", "engagements", "reports"} & {part.lower() for part in Path(candidate).parts}:
        return False, "SCOPE DENIED: modelscan cannot read engagement evidence or report directories."
    return True, "Local model-file path"


def inventory_estate(
    router: McpRouter | None = None,
    presence_checker: Callable[[str], bool] | None = None,
    *,
    agentdojo_path: Path | None = None,
    tasks_dir: Path | None = None,
) -> Observation:
    """Inventory AI-estate composed tools and MCP supply-chain SBOM."""
    from aetherops.adapters.eval_oss import inventory_eval_oss

    tools_status = get_composed_tools_status(presence_checker)
    present_tools = [name for name, s in tools_status.items() if s["present"]]
    missing_tools = [name for name, s in tools_status.items() if not s["present"]]
    ext_status = get_extension_tools_status(presence_checker)
    ext_present = [name for name, s in ext_status.items() if s["present"]]
    ext_missing = [name for name, s in ext_status.items() if not s["present"]]
    eval_oss = inventory_eval_oss(
        presence_checker,
        agentdojo_path=agentdojo_path,
        tasks_dir=tasks_dir,
    )
    defensive = get_defensive_scanners_status(presence_checker)
    defensive_present = [name for name, s in defensive.items() if s["present"]]
    defensive_missing = [name for name, s in defensive.items() if not s["present"]]

    sbom_list: list[dict[str, Any]] = []
    if router is not None:
        sbom_list = router.get_mcp_sbom()

    summary = (
        f"AI-estate domain inventory: {len(present_tools)}/{len(tools_status)} composed AI tools present, "
        f"{len(ext_present)}/{len(ext_status)} landscape extensions present, "
        f"{len(sbom_list)} MCP servers in SBOM."
    )
    if missing_tools:
        summary += f" Missing tools ({', '.join(missing_tools)}) -> STOP on execution."
    if ext_missing:
        summary += f" Extension tools ({', '.join(ext_missing)}) -> STOP on guardrails/modelscan."
    if defensive_missing:
        summary += (
            f" Defensive MCP/skill scanners missing ({', '.join(defensive_missing)})"
            " -> STOP on estate.mcp_scan/skill_scan."
        )

    catalog_pin: dict[str, Any] = {}
    try:
        from aetherops.knowledge.prompt_hacking import PIN_SHA, inventory_catalog

        catalog_obs = inventory_catalog()
        catalog_pin = {
            "present": bool((catalog_obs.data or {}).get("present")),
            "commit": (catalog_obs.data or {}).get("commit"),
            "expected_commit": PIN_SHA,
            "license": (catalog_obs.data or {}).get("license"),
            "affiliation": (catalog_obs.data or {}).get("affiliation"),
            "kind": "offline_capability_catalog",
            "runtime_fetch": False,
        }
    except (AttributeError, ImportError, OSError, ValueError):
        catalog_pin = {"present": False, "runtime_fetch": False}

    ha_pin: dict[str, Any] = {}
    try:
        from aetherops.knowledge.hackagent_catalog import (
            PIN_SHA as HA_PIN_SHA,
        )
        from aetherops.knowledge.hackagent_catalog import (
            inventory_catalog as ha_inventory,
        )

        ha_obs = ha_inventory()
        ha_pin = {
            "present": bool((ha_obs.data or {}).get("present")),
            "commit": (ha_obs.data or {}).get("commit"),
            "expected_commit": HA_PIN_SHA,
            "license": (ha_obs.data or {}).get("license"),
            "affiliation": (ha_obs.data or {}).get("affiliation"),
            "kind": "offline_capability_catalog",
            "runtime_fetch": False,
            "hackagent_vendored": False,
        }
    except (AttributeError, ImportError, OSError, ValueError):
        ha_pin = {"present": False, "runtime_fetch": False, "hackagent_vendored": False}

    return ok(
        summary,
        data={
            "domain": "ai-estate",
            "composed_tools": tools_status,
            "present_tools": present_tools,
            "missing_tools": missing_tools,
            "all_tools_present": len(missing_tools) == 0,
            "extension_tools": ext_status,
            "extension_present": ext_present,
            "extension_missing": ext_missing,
            "mcp_sbom": sbom_list,
            "prompt_hacking_catalog": catalog_pin,
            "eval_oss": eval_oss,
            "defensive_scanners": defensive,
            "defensive_present": defensive_present,
            "defensive_missing": defensive_missing,
            "ha_catalog": ha_pin,
            "executed": False,
        },
        next_actions=[
            "Run estate.sbom for detailed MCP supply chain manifest",
            "Run estate.mcp_scan / estate.skill_scan (SkillSpector/mcp-scanner/agent-scan; missing → STOP)",
            "Run estate.assess with in-scope local model endpoint (run-or-STOP)",
            "aetherops prompt-hacking search 'prompt injection' (citation catalog; dual-use unsigned → SCOPE DENIED)",
            "Run estate.promptfoo / estate.spikee against loopback /v1 (run-or-STOP; no cloud judge)",
            "aetherops hackagent-catalog search 'PAIR' (HackAgent citations; dual-use unsigned → SCOPE DENIED)",
            "Run estate.guardrails or estate.modelscan for landscape-gap extensions",
        ],
    )


def run_estate_adapter(
    verb: str = "inventory",
    target: str | None = None,
    live: bool = False,
    engagement: Engagement | None = None,
    arguments: dict[str, Any] | None = None,
    router: McpRouter | None = None,
    presence_checker: Callable[[str], bool] | None = None,
    *,
    eval_runner: Callable[..., Any] | None = None,
    dvllm_path: Path | None = None,
    eval_oss_tasks_dir: Path | None = None,
    agentdojo_path: Path | None = None,
    settings: Settings | None = None,
    scanner_runner: Callable[[str, str, dict[str, Any] | None], Any] | None = None,
    workspace: Path | None = None,
    vault_dir: Path | None = None,
    reports_dir: Path | None = None,
    engagement_file: Path | None = None,
) -> Observation:
    """Execute or plan an AI-estate assessment action behind the scope gate.

    Run-or-STOP contract: if any required composed tool is missing, STOP immediately.
    """
    from aetherops.adapters.eval_oss import EVAL_OSS_VERBS, refused_eval_token, run_eval_oss
    from aetherops.adapters.lab_target import run_lab_target_adapter

    action = (verb or "inventory").strip().lower().replace("-", "_")
    cfg = settings or Settings()
    tasks_dir = eval_oss_tasks_dir if eval_oss_tasks_dir is not None else cfg.eval_oss_tasks_dir
    dojo_path = agentdojo_path if agentdojo_path is not None else cfg.agentdojo_path
    lab_path = dvllm_path if dvllm_path is not None else cfg.dvllm_path

    # Validate arguments (fail closed)
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )

    refused = refused_eval_token(action, arguments)
    if refused:
        return err(
            f"SCOPE DENIED: {refused} is not an in-envelope eval (no HarmBench/JailbreakBench/PAIR).",
            stop_condition="SCOPE DENIED. Use promptfoo, spikee, inspect_evals, or optional agentdojo.",
            data={"scope_refused": True, "executed": False, "refused": refused},
        )

    # 1. Inventory & SBOM verbs
    if action in {"inventory", "health"}:
        return inventory_estate(
            router=router,
            presence_checker=presence_checker,
            agentdojo_path=dojo_path,
            tasks_dir=tasks_dir,
        )

    if action in {"sbom", "mcp_sbom"}:
        if router is None:
            router = McpRouter(Settings())
        return router.inventory_sbom()

    eval_tool = str((arguments or {}).get("tool") or "").strip().lower().replace("-", "_")
    if action in EVAL_OSS_VERBS or (action == "eval" and eval_tool in EVAL_OSS_VERBS):
        return run_eval_oss(
            eval_tool if action == "eval" else action,
            target=target,
            live=live,
            engagement=engagement,
            arguments=arguments,
            presence_checker=presence_checker,
            eval_runner=eval_runner,
            tasks_dir=tasks_dir,
            agentdojo_path=dojo_path,
            vault_dir=cfg.vault_dir,
        )
    if action in {"dvllm", "lab_target"}:
        return run_lab_target_adapter(
            verb="dvllm",
            engagement=engagement,
            target=target,
            live=live,
            arguments=arguments,
            dvllm_path=lab_path,
            presence_checker=presence_checker,
            probe_runner=eval_runner,
            vault_dir=cfg.vault_dir,
        )
    if action in DEFENSIVE_VERBS:
        return run_defensive_scan(
            action,
            engagement=engagement,
            live=live,
            target=target,
            arguments=arguments,
            presence_checker=presence_checker,
            scanner_runner=scanner_runner,
            workspace=workspace or ROOT,
            vault_dir=vault_dir if vault_dir is not None else cfg.vault_dir,
            reports_dir=reports_dir,
            engagement_file=engagement_file,
        )

    # Landscape-gap extensions: guardrails + modelscan (run-or-STOP, never execute).
    if action in {"guardrails", "llm_guard", "nemo_guardrails"}:
        ext = get_extension_tools_status(presence_checker)
        if action == "llm_guard":
            required = ["llm_guard"]
        elif action == "nemo_guardrails":
            required = ["nemo_guardrails"]
        else:
            required = ["llm_guard", "nemo_guardrails"]
        missing = [tool for tool in required if not ext[tool]["present"]]
        is_valid, reason = validate_local_target(target, engagement)
        if not is_valid:
            return err(
                reason,
                root_cause_hint="Guardrails must wrap local Ollama (/v1) or an in-scope lab identity.",
                stop_condition="SCOPE DENIED. Point AI evaluation tools at local Ollama only.",
                data={"target": target, "scope_refused": True, "executed": False},
            )
        if live and missing:
            missing_str = ", ".join(missing)
            return err(
                f"STOP missing-tool: {missing_str}. Prompt-firewall tools are not installed locally.",
                root_cause_hint=f"Missing guardrail tools: {missing_str}. AetherOps composes tools as run-or-STOP.",
                retry="Install llm-guard / nemoguardrails locally or stay in plan-only mode.",
                stop_condition=f"STOP missing-tool: {missing_str}. Do not silently skip.",
                data={"missing_tools": missing, "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"Local prompt-firewall evaluation planned vs {target or 'http://127.0.0.1:11434/v1'} "
            f"(ATLAS AML.T0051/AML.T0054)."
            + ("" if not missing else f" [tools {', '.join(missing)} absent: requires installation before --live]"),
            data={
                "tools": required,
                "present_tools": [tool for tool in required if ext[tool]["present"]],
                "missing_tools": missing,
                "target": target or "http://127.0.0.1:11434/v1",
                "live": live,
                "executed": False,
                "technique": "AML.T0051",
            },
            next_actions=["Wrap local model I/O with llm-guard or NeMo Guardrails; never a cloud judge"],
        )

    if action in {"modelscan", "supply_chain"}:
        ext = get_extension_tools_status(presence_checker)
        present = bool(ext["modelscan"]["present"])
        is_valid, reason = validate_modelscan_target(target)
        if not is_valid:
            return err(
                reason,
                root_cause_hint="modelscan inspects local model files only; no remote fetch.",
                stop_condition="SCOPE DENIED. Point modelscan at a local file, not a URL.",
                data={"target": target, "scope_refused": True, "executed": False},
            )
        if live and not present:
            return err(
                "STOP missing-tool: modelscan. Model supply-chain scanner is not installed locally.",
                root_cause_hint="modelscan CLI is missing from PATH. AetherOps composes tools as run-or-STOP.",
                retry="Install modelscan locally or stay in plan-only mode.",
                stop_condition="STOP missing-tool: modelscan. Do not silently skip.",
                data={"tool": "modelscan", "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"Local ML model-file scan planned vs {target or 'local-model-files'} (ATLAS AML.T0010)."
            + ("" if present else " [tool modelscan absent: requires installation before --live]"),
            data={
                "tool": "modelscan",
                "target": target or "local-model-files",
                "present": present,
                "live": live,
                "executed": False,
                "technique": "AML.T0010",
            },
            next_actions=["Scan local pickle/keras/saved_model files; never download weights on an engagement host"],
        )

    # 2. Target validation (Local Ollama only)
    is_valid, reason = validate_local_target(target, engagement)
    if not is_valid:
        return err(
            reason,
            root_cause_hint="AI security eval must target local Ollama (/v1) or in-scope lab identity; cloud endpoints are refused.",
            stop_condition="SCOPE DENIED. Point AI evaluation tools at local Ollama only.",
            data={"target": target, "scope_refused": True, "executed": False},
        )

    tools_status = get_composed_tools_status(presence_checker)

    # 3. Composed action: Praxen (Remit vs Implementation / Agent-IAM)
    if action in {"remit", "praxen", "agent_iam"}:
        tool_name = "praxen"
        present = tools_status[tool_name]["present"]
        if live and not present:
            return err(
                f"STOP missing-tool: {tool_name}. Agent-IAM audit tool is not installed locally.",
                root_cause_hint="Praxen CLI is missing from PATH. AetherOps composes tools as run-or-STOP.",
                retry="Install praxen locally or use plan-only orchestration.",
                stop_condition=f"STOP missing-tool: {tool_name}. Do not silently skip.",
                data={"tool": tool_name, "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"Praxen agent-IAM remit verification planned vs {target or 'local agents'} (ATLAS AML.T0040)."
            + ("" if present else f" [tool {tool_name} absent: requires installation before --live]"),
            data={
                "tool": tool_name,
                "target": target or "local-agent-workspaces",
                "present": present,
                "live": live,
                "executed": False,
                "technique": "AML.T0040",
            },
            next_actions=["Map agent tool permissions to Praxen RAISE policy"],
        )

    # 4. Composed action: agentic_radar (Static workflow scan)
    if action in {"scan", "agentic_radar", "workflow_scan"}:
        tool_name = "agentic_radar"
        present = tools_status[tool_name]["present"]
        if live and not present:
            return err(
                f"STOP missing-tool: {tool_name}. Agent static analysis tool is not installed locally.",
                root_cause_hint="agentic-radar is missing from PATH. AetherOps composes tools as run-or-STOP.",
                retry="Install agentic-radar locally or use plan-only orchestration.",
                stop_condition=f"STOP missing-tool: {tool_name}. Do not silently skip.",
                data={"tool": tool_name, "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"agentic-radar static workflow scan planned vs {target or 'agent definitions'} (ATLAS AML.T0024)."
            + ("" if present else f" [tool {tool_name} absent: requires installation before --live]"),
            data={
                "tool": tool_name,
                "target": target or "local-agent-definitions",
                "present": present,
                "live": live,
                "executed": False,
                "technique": "AML.T0024",
            },
            next_actions=["Scan tool definitions for sensitive prompt disclosure"],
        )

    # 5. Composed action: promptmap / garak / pyrit (Prompt injection & LLM robustness)
    if action in {"robustness", "eval", "garak", "pyrit", "promptmap", "injection"}:
        required = ["garak", "promptmap"]
        missing = [t for t in required if not tools_status[t]["present"]]
        if live and missing:
            missing_str = ", ".join(missing)
            return err(
                f"STOP missing-tool: {missing_str}. AI evaluation tools are not installed locally.",
                root_cause_hint=f"Missing evaluation tools: {missing_str}. AetherOps composes tools as run-or-STOP.",
                retry="Install garak/promptmap locally or run in plan-only mode.",
                stop_condition=f"STOP missing-tool: {missing_str}. Do not silently skip.",
                data={"missing_tools": missing, "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"Local LLM robustness evaluation planned vs {target or 'http://127.0.0.1:11434/v1'} (ATLAS AML.T0051)."
            + ("" if not missing else f" [tools {', '.join(missing)} absent: requires installation before --live]"),
            data={
                "tools": ["garak", "promptmap", "pyrit"],
                "target": target or "http://127.0.0.1:11434/v1",
                "missing_tools": missing,
                "live": live,
                "executed": False,
                "technique": "AML.T0051",
            },
            next_actions=["Execute prompt injection boundary evaluation vs local model only"],
        )

    # 6. Composed action: assess (Full scoped estate assessment pipeline)
    if action in {"assess", "ai_estate", "pipeline"}:
        missing = [name for name, s in tools_status.items() if not s["present"]]
        if missing:
            missing_str = ", ".join(missing)
            return err(
                f"STOP missing-tool: {missing_str}. AI-estate assessment halted (run-or-STOP).",
                root_cause_hint=f"Composed estate tools missing: {missing_str}.",
                retry="Ensure all composed AI-security tools are installed locally.",
                stop_condition=f"STOP missing-tool: {missing_str}. Do not silently skip missing security tools.",
                data={"missing_tools": missing, "present": False, "executed": False, "scope_refused": True},
            )
        return ok(
            f"AI-estate assessment pipeline verified for {target or 'http://127.0.0.1:11434/v1'}.",
            data={
                "stages": ["remit", "scan", "sbom", "robustness"],
                "target": target or "http://127.0.0.1:11434/v1",
                "live": live,
                "executed": False,
                "all_tools_present": True,
            },
            next_actions=["Pair identified AI-estate findings with purple detection and controls"],
        )

    return err(
        f"Unknown estate verb: {verb}",
        stop_condition="Use estate inventory, sbom, remit, scan, robustness, promptfoo, spikee, inspect_evals, agentdojo, dvllm, assess, guardrails, modelscan, mcp_scan, skill_scan, or checklist.",
        data={"scope_refused": True, "executed": False},
    )
