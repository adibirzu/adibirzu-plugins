"""Local Promptfoo / Spikee / inspect_evals / AgentDojo compose (PRD-MS-4).

Run-or-STOP wrappers against loopback `/v1` only. No cloud judge, no HF
dataset pull, no HarmBench / JailbreakBench / PAIR. Jailbreak corpus
bodies stay out of git and vault (hash-only excerpts).
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from typing import Any

from aetherops.airlock.egress import is_loopback_host
from aetherops.harness.observation import (
    create_clean_negative_card,
    create_finding_card,
    err,
    ok,
    warn,
)
from aetherops.scope.gate import normalize_target
from aetherops.scope.verbs import arguments_have_payload_shape, exploit_arg_keys, extra_arg_keys
from aetherops.types import Engagement, Observation

DEFAULT_EVAL_TARGET = "http://127.0.0.1:11434/v1"
EXCERPT_LIMIT = 400

EVAL_OSS_TOOLS: dict[str, dict[str, Any]] = {
    "promptfoo": {
        "kind": "local_cli",
        "command": "promptfoo",
        "side": "red",
        "airgap_ok": True,
        "internet_required": False,
        "optional": False,
        "purpose": "Local LLM red-team eval vs loopback /v1",
        "atlas": "AML.T0051, AML.T0054",
    },
    "spikee": {
        "kind": "local_cli",
        "command": "spikee",
        "side": "red",
        "airgap_ok": True,
        "internet_required": False,
        "optional": False,
        "purpose": "Local prompt-injection tester vs loopback /v1",
        "atlas": "AML.T0051, AML.T0054",
    },
    "inspect_evals": {
        "kind": "python",
        "command": "inspect",
        "alt_command": "inspect-ai",
        "package": "inspect_evals",
        "side": "purple",
        "airgap_ok": True,
        "internet_required": False,
        "optional": False,
        "requires_local_tasks": True,
        "purpose": "Operator-local inspect cyber tasks; no HF pull",
        "atlas": "AML.T0051, AML.T0054",
    },
    "agentdojo": {
        "kind": "python",
        "command": "agentdojo",
        "package": "agentdojo",
        "side": "purple",
        "airgap_ok": True,
        "internet_required": False,
        "optional": True,
        "purpose": "Optional local agent-tool benchmark; no internet leaderboard",
        "atlas": "AML.T0040, AML.T0051",
    },
}

EVAL_OSS_VERBS = frozenset(EVAL_OSS_TOOLS)

# Long corpus names only — never match "pair" as a substring of unrelated words.
REFUSED_EVAL_CORPORA = frozenset(
    {
        "harmbench",
        "jailbreakbench",
        "easyjailbreak",
        "gptfuzz",
        "gptfuzzer",
    }
)
REFUSED_EVAL_EXACT = frozenset({"pair", "tap", "gcg", "gcgattack"})
REFUSED_CLI_FLAGS = frozenset(
    {
        "--network",
        "--online",
        "--cloud",
        "--share",
        "--remote",
        "--hf-dataset",
        "--download",
        "--leaderboard",
        "--push",
    }
)
OFFLINE_ENV_KEYS = (
    "HF_HUB_OFFLINE",
    "HF_DATASETS_OFFLINE",
    "TRANSFORMERS_OFFLINE",
    "PROMPTFOO_DISABLE_TELEMETRY",
    "PROMPTFOO_DISABLE_REMOTE",
)
CLOUD_ENV_DENY = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "PROMPTFOO_REMOTE_API_BASE",
    }
)


@dataclass(frozen=True)
class EvalInvocation:
    tool: str
    argv: tuple[str, ...]
    env: Mapping[str, str]
    target: str
    cwd: str


@dataclass(frozen=True)
class EvalResult:
    returncode: int
    output_hash: str
    excerpt: str
    raw_len: int = 0


EvalRunner = Callable[[EvalInvocation], EvalResult]


def check_eval_tool_presence(
    tool_name: str,
    *,
    agentdojo_path: Path | None = None,
) -> bool:
    """True when the named eval CLI or package is installed locally."""
    meta = EVAL_OSS_TOOLS.get(tool_name)
    if not meta:
        return False
    if tool_name == "agentdojo" and agentdojo_path is not None:
        text = str(agentdojo_path).strip()
        if text and Path(text).exists():
            return True
    cmd = meta.get("command")
    if cmd and which(str(cmd)) is not None:
        return True
    alt_cmd = meta.get("alt_command")
    if alt_cmd and which(str(alt_cmd)) is not None:
        return True
    pkg = meta.get("package")
    if pkg:
        try:
            return importlib.util.find_spec(str(pkg)) is not None
        except (ImportError, ValueError, AttributeError):
            return False
    return False


def local_tasks_present(path: Path | str | None) -> bool:
    """True when an operator-local inspect_evals task file or non-empty dir exists."""
    if path is None:
        return False
    candidate = Path(str(path).strip())
    if not str(path).strip() or not candidate.exists():
        return False
    if candidate.is_file():
        return True
    if candidate.is_dir():
        try:
            return any(candidate.iterdir())
        except OSError:
            return False
    return False


def refused_eval_token(verb: str, arguments: dict[str, Any] | None = None) -> str | None:
    """Return a refused corpus/attack-generator name, else None."""
    action = (verb or "").strip().lower().replace("-", "_")
    if action in REFUSED_EVAL_EXACT or action in REFUSED_EVAL_CORPORA:
        return action
    args = arguments or {}
    tool = str(args.get("tool") or "").strip().lower().replace("-", "_")
    if tool in REFUSED_EVAL_EXACT or tool in REFUSED_EVAL_CORPORA:
        return tool
    blob = f"{action} {tool}"
    for token in REFUSED_EVAL_CORPORA:
        if token in blob:
            return token
    return None


def refused_cli_flag(extra: list[str] | tuple[str, ...] | None) -> str | None:
    for item in extra or ():
        flag = str(item).strip().lower()
        if flag in REFUSED_CLI_FLAGS:
            return flag
        stem = flag.split("=", 1)[0]
        if stem in REFUSED_CLI_FLAGS:
            return stem
    return None


_FAIL_KV_RE = re.compile(r"(?:fail(?:ure)?s?|vuln\w*)\s*[=:]\s*(\d+)", re.IGNORECASE)
_FAIL_COUNT_RE = re.compile(r"(\d+)\s+(?:fail\w*|vuln\w*|jailbreak\w*|injection\w*)", re.IGNORECASE)
_PASS_KV_RE = re.compile(r"(?:pass(?:e[ds])?|success(?:es)?)\s*[=:]\s*(\d+)", re.IGNORECASE)
_SIGNAL_MARKERS = (
    "injection detected",
    "jailbreak detected",
    "jailbreak succeeded",
    "attack succeeded",
    "vulnerabilit",
)
_CLEAN_MARKERS = ("all passed", "no vulnerabilities", "no failures", "no findings", "0 failed")
CONFIG_ARGV_SUFFIXES = (".yaml", ".yml", ".json", ".jsonl", ".js", ".ts", ".py", ".toml")


def parse_eval_outcome(excerpt: str | None) -> str:
    """Classify a completed eval's output as 'signal', 'clean', or 'unknown'.

    A Potential card is only justified by a parsed failure/vulnerability
    signal, never by the mere fact that the tool ran to completion.
    """
    blob = (excerpt or "").lower()
    kv_counts = [int(n) for n in _FAIL_KV_RE.findall(blob)]
    if kv_counts:
        return "signal" if any(n > 0 for n in kv_counts) else "clean"
    if any(marker in blob for marker in _CLEAN_MARKERS):
        return "clean"
    loose_counts = [int(n) for n in _FAIL_COUNT_RE.findall(blob)]
    if loose_counts:
        return "signal" if any(n > 0 for n in loose_counts) else "clean"
    if any(marker in blob for marker in _SIGNAL_MARKERS):
        return "signal"
    if _PASS_KV_RE.search(blob):
        return "clean"
    return "unknown"


def _scan_config_argv(item: str) -> str | None:
    """Read a referenced local config file and refuse a cloud judge / corpus in it."""
    from aetherops.adapters.estate import FORBIDDEN_CLOUD_PATTERNS

    try:
        path = Path(item)
        if not path.is_file() or path.suffix.lower() not in CONFIG_ARGV_SUFFIXES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")[:20000].lower()
    except OSError:
        return None
    for cloud in FORBIDDEN_CLOUD_PATTERNS:
        if cloud in text:
            return cloud
    for token in REFUSED_EVAL_CORPORA:
        if token in text:
            return token
    return None


def refused_argv_item(extra: list[str] | tuple[str, ...] | None) -> tuple[str, str] | None:
    """Return (item, token) when an argv value smuggles a refused corpus/attack
    generator or a cloud endpoint (directly or via a referenced config), else None."""
    from aetherops.adapters.estate import FORBIDDEN_CLOUD_PATTERNS

    for item in extra or ():
        raw = str(item).strip()
        low = raw.lower()
        for token in REFUSED_EVAL_CORPORA:
            if token in low:
                return (raw, token)
        tokens = {part for part in re.split(r"[^a-z0-9]+", low) if part}
        exact = tokens & REFUSED_EVAL_EXACT
        if exact:
            return (raw, min(exact))
        for cloud in FORBIDDEN_CLOUD_PATTERNS:
            if cloud in low:
                return (raw, cloud)
        hit = _scan_config_argv(raw)
        if hit:
            return (raw, hit)
    return None


def _append_eval_evidence(
    *,
    vault_dir: Path | None,
    tool: str,
    invocation: EvalInvocation,
    result: EvalResult,
) -> str:
    """Append the eval's sanitized artifact to the append-only run ledger and
    return the real evidence id. Falls back to a content-hash id only when no
    vault is available (plan/unit paths that never reach a generated report)."""
    fallback = f"ev-{result.output_hash[:16]}"
    if vault_dir is None:
        return fallback
    from aetherops.evidence.run_ledger import LedgerReportError, RunLedger
    from aetherops.tooling.wrapper import ToolResult, input_hash

    argv = list(invocation.argv)
    try:
        ledger = RunLedger(
            Path(vault_dir) / "run-ledger.jsonl",
            artifacts_dir=Path(vault_dir) / "tool-artifacts",
        )
        if ledger.get(fallback) is not None:
            return fallback
        tool_result = ToolResult(
            tool=tool,
            argv=tuple(argv),
            cwd=invocation.cwd,
            input_hash=input_hash(argv=argv, cwd=invocation.cwd, stdin=""),
            output_hash=result.output_hash,
            normalized=result.excerpt,
            raw=result.excerpt,
            returncode=result.returncode,
            timeout_s=120,
            version="",
            binary=tool,
            target=invocation.target,
            evidence_id=fallback,
        )
        record = ledger.append_result(tool_result)
        return record.evidence_id
    except (OSError, LedgerReportError):
        return fallback


def build_offline_eval_env(*, target: str) -> dict[str, str]:
    """Minimal env for a local eval. Never copies cloud API keys from the parent."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "TERM": "dumb",
        "PYTHONNOUSERSITE": "1",
        "HF_HUB_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "PROMPTFOO_DISABLE_TELEMETRY": "1",
        "PROMPTFOO_DISABLE_REMOTE": "1",
    }
    base = target if target.startswith("http") else f"http://{target}/v1"
    env["OPENAI_BASE_URL"] = base
    env["OPENAI_API_BASE"] = base
    env["OPENAI_API_KEY"] = "local-ollama"
    return env


def hash_eval_output(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def sanitize_eval_excerpt(raw: str, *, limit: int = EXCERPT_LIMIT) -> str:
    """Keep a short status excerpt. Drop long lines that look like prompt bodies."""
    kept: list[str] = []
    for line in (raw or "").splitlines():
        text = line.strip()
        if not text:
            continue
        if len(text) > 240:
            continue
        kept.append(text)
        blob = "\n".join(kept)
        if len(blob) >= limit:
            return blob[:limit]
    excerpt = "\n".join(kept).strip()
    if not excerpt:
        return f"eval-output-hash-only len={len(raw or '')}"
    return excerpt[:limit]


def resolve_eval_command(tool_name: str) -> str:
    meta = EVAL_OSS_TOOLS[tool_name]
    cmd = str(meta.get("command") or tool_name)
    if which(cmd) is not None:
        return cmd
    alt = meta.get("alt_command")
    if alt and which(str(alt)) is not None:
        return str(alt)
    return cmd


def build_eval_argv(
    tool_name: str,
    *,
    extra: list[str] | None = None,
    local_tasks: Path | None = None,
) -> list[str]:
    command = resolve_eval_command(tool_name)
    extra = list(extra or [])
    if tool_name == "promptfoo":
        argv = [command, "eval", "--offline"]
    elif tool_name == "spikee":
        argv = [command, "run", "--offline"]
    elif tool_name == "inspect_evals":
        argv = [command, "eval"]
        if local_tasks is not None:
            argv.append(str(local_tasks))
    else:
        argv = [command, "eval"]
    argv.extend(extra)
    return argv


def default_eval_runner(invocation: EvalInvocation) -> EvalResult:
    """Subprocess compose. Tests inject a runner; this is the live operator path."""
    env = {key: value for key, value in invocation.env.items() if key not in CLOUD_ENV_DENY}
    env["OPENAI_API_KEY"] = "local-ollama"
    completed = subprocess.run(
        list(invocation.argv),
        cwd=invocation.cwd or None,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )
    raw = (completed.stdout or "") + (("\n" + completed.stderr) if completed.stderr else "")
    return EvalResult(
        returncode=int(completed.returncode),
        output_hash=hash_eval_output(raw),
        excerpt=sanitize_eval_excerpt(raw),
        raw_len=len(raw),
    )


def inventory_eval_oss(
    presence_checker: Callable[[str], bool] | None = None,
    *,
    agentdojo_path: Path | None = None,
    tasks_dir: Path | None = None,
) -> dict[str, Any]:
    checker = presence_checker or (lambda name: check_eval_tool_presence(name, agentdojo_path=agentdojo_path))
    results: dict[str, dict[str, Any]] = {}
    for name, meta in EVAL_OSS_TOOLS.items():
        present = bool(checker(name))
        row = {**meta, "present": present}
        if meta.get("requires_local_tasks"):
            row["local_tasks_present"] = local_tasks_present(tasks_dir)
        results[name] = row
    present_tools = [name for name, row in results.items() if row["present"]]
    missing_required = [
        name
        for name, row in results.items()
        if not row["present"] and not EVAL_OSS_TOOLS[name].get("optional")
    ]
    return {
        "composed_tools": results,
        "present_tools": present_tools,
        "missing_required": missing_required,
        "agentdojo_optional": True,
        "local_tasks_present": local_tasks_present(tasks_dir),
        "refused_corpora": sorted(REFUSED_EVAL_CORPORA | REFUSED_EVAL_EXACT),
        "executed": False,
    }


def _unsigned_live(engagement: Engagement | None, live: bool) -> Observation | None:
    if not live:
        return None
    if engagement is None:
        return err(
            "SCOPE DENIED: unsigned engagement.",
            stop_condition="SCOPE DENIED. Sign an engagement with allow_live_tools before live eval.",
            data={"scope_refused": True, "executed": False, "unsigned": True},
        )
    if not engagement.allow_live_tools:
        return err(
            "SCOPE DENIED: unsigned or allow_live_tools is false.",
            stop_condition="SCOPE DENIED. Do not run live eval without a signed engagement.",
            data={"scope_refused": True, "executed": False, "unsigned": True},
        )
    if engagement.autonomy_level < 1:
        return err(
            "SCOPE DENIED: live eval requires autonomy_level >= 1.",
            stop_condition="Do not self-escalate autonomy. Inventory only at L0.",
            data={"scope_refused": True, "executed": False, "unsigned": True},
        )
    if not engagement.authorization_ref or engagement.authorized_by in {"", "engagement-owner"}:
        return err(
            "SCOPE DENIED: example engagement is not a signed authorization.",
            stop_condition="Replace configs/engagement.example.yaml with a real ROE.",
            data={"scope_refused": True, "executed": False, "unsigned": True},
        )
    today = datetime.now(UTC).date().isoformat()
    if not (engagement.start <= today <= engagement.end):
        return err(
            "SCOPE DENIED: engagement window is not active.",
            stop_condition="Do not operate outside start/end dates.",
            data={"scope_refused": True, "executed": False},
        )
    return None


def _loopback_identity(target: str) -> bool:
    host = normalize_target(target)
    return bool(host) and is_loopback_host(host)


def run_eval_oss(
    verb: str,
    *,
    target: str | None = None,
    live: bool = False,
    engagement: Engagement | None = None,
    arguments: dict[str, Any] | None = None,
    presence_checker: Callable[[str], bool] | None = None,
    eval_runner: EvalRunner | None = None,
    tasks_dir: Path | None = None,
    agentdojo_path: Path | None = None,
    vault_dir: Path | None = None,
) -> Observation:
    """Compose one local eval tool. Live runs stay loopback-only and offline."""
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )
    smuggled = exploit_arg_keys(arguments)
    if smuggled or arguments_have_payload_shape(arguments):
        return err(
            "Denied: payload-shaped eval arguments.",
            stop_condition="Do not retry payload-shaped arguments.",
            data={"scope_refused": True, "executed": False},
        )

    refused = refused_eval_token(verb, arguments)
    if refused:
        return err(
            f"SCOPE DENIED: {refused} is not an in-envelope eval (no HarmBench/JailbreakBench/PAIR).",
            stop_condition="SCOPE DENIED. Use promptfoo, spikee, inspect_evals, or optional agentdojo.",
            data={"scope_refused": True, "executed": False, "refused": refused},
        )

    action = (verb or "").strip().lower().replace("-", "_")
    if action == "eval":
        action = str((arguments or {}).get("tool") or "").strip().lower().replace("-", "_")
    if action not in EVAL_OSS_TOOLS:
        return err(
            f"Unknown eval-oss verb: {verb}",
            stop_condition="Use estate.promptfoo, estate.spikee, estate.inspect_evals, or estate.agentdojo.",
            data={"scope_refused": True, "executed": False},
        )

    extra_argv: list[str] = []
    args = arguments or {}
    raw_extra = args.get("argv") or args.get("extra")
    if isinstance(raw_extra, list):
        extra_argv = [str(item) for item in raw_extra]
    banned_flag = refused_cli_flag(extra_argv)
    if banned_flag:
        return err(
            f"SCOPE DENIED: eval flag {banned_flag} would leave the air-gap.",
            stop_condition="SCOPE DENIED. Offline flags only; no network/cloud/leaderboard.",
            data={"scope_refused": True, "executed": False, "refused_flag": banned_flag},
        )
    banned_arg = refused_argv_item(extra_argv)
    if banned_arg:
        item, token = banned_arg
        return err(
            f"SCOPE DENIED: eval argument '{item}' references {token} "
            "(no HarmBench/JailbreakBench/PAIR, no cloud judge).",
            stop_condition="SCOPE DENIED. No refused corpora or cloud-judge configs via argv.",
            data={"scope_refused": True, "executed": False, "refused_arg": item, "refused": token},
        )

    resolved_target = (target or DEFAULT_EVAL_TARGET).strip() or DEFAULT_EVAL_TARGET
    from aetherops.adapters.estate import validate_local_target

    is_valid, reason = validate_local_target(resolved_target, engagement)
    if not is_valid:
        return err(
            reason,
            root_cause_hint="Eval compose must point at local Ollama /v1; cloud judges are refused.",
            stop_condition="SCOPE DENIED. Point evaluation tools at loopback /v1 only.",
            data={"target": resolved_target, "scope_refused": True, "executed": False},
        )
    if live and not _loopback_identity(resolved_target):
        return err(
            f"SCOPE DENIED: live eval target '{resolved_target}' is not loopback /v1.",
            stop_condition="SCOPE DENIED. Engage-path eval HTTP is loopback-only.",
            data={"target": resolved_target, "scope_refused": True, "executed": False},
        )

    unsigned = _unsigned_live(engagement, live)
    if unsigned is not None:
        data = dict(unsigned.data or {})
        data.update({"tool": action, "target": resolved_target, "live": live})
        return unsigned.model_copy(update={"data": data})

    checker = presence_checker or (
        lambda name: check_eval_tool_presence(name, agentdojo_path=agentdojo_path)
    )
    present = bool(checker(action))
    tasks_path = Path(str(args["path"])) if args.get("path") else tasks_dir
    needs_tasks = bool(EVAL_OSS_TOOLS[action].get("requires_local_tasks"))
    has_tasks = local_tasks_present(tasks_path) if needs_tasks else True

    if live and not present:
        return err(
            f"STOP missing-tool: {action}. Local eval CLI is not installed.",
            root_cause_hint="AetherOps composes Promptfoo/Spikee/inspect_evals as run-or-STOP.",
            retry="Install the CLI locally or stay plan-only.",
            stop_condition=f"STOP missing-tool: {action}. Do not silently skip.",
            data={
                "tool": action,
                "present": False,
                "executed": False,
                "scope_refused": True,
                "target": resolved_target,
            },
        )
    if live and needs_tasks and not has_tasks:
        return err(
            "STOP missing-local-tasks: inspect_evals requires operator-local files (no HF pull).",
            root_cause_hint="Set AETHEROPS_EVAL_OSS_TASKS_DIR or pass path= to a local task file.",
            retry="Point at a local inspect task directory, then retry.",
            stop_condition="STOP missing-local-tasks. Do not download datasets.",
            data={
                "tool": action,
                "present": present,
                "local_tasks_present": False,
                "executed": False,
                "scope_refused": True,
                "hf_hub_offline": True,
            },
        )

    atlas = str(EVAL_OSS_TOOLS[action]["atlas"])
    techniques = [part.strip() for part in atlas.split(",") if part.strip()]
    primary = techniques[0] if techniques else "AML.T0051"

    if not live:
        return ok(
            f"{action} planned vs {resolved_target} ({atlas})."
            + ("" if present else f" [tool {action} absent: requires installation before --live]"),
            data={
                "tool": action,
                "target": resolved_target,
                "present": present,
                "live": False,
                "executed": False,
                "technique": primary,
                "techniques": techniques,
                "optional": bool(EVAL_OSS_TOOLS[action].get("optional")),
                "local_tasks_present": has_tasks if needs_tasks else None,
                "offline": True,
                "cloud_judge": False,
            },
            next_actions=["Run with --live against loopback /v1 after the CLI is local"],
        )

    argv = build_eval_argv(action, extra=extra_argv, local_tasks=tasks_path if needs_tasks else None)
    env = build_offline_eval_env(target=resolved_target)
    if needs_tasks and tasks_path is not None:
        workdir = str(tasks_path.parent if tasks_path.is_file() else tasks_path)
    else:
        workdir = os.getcwd()
    invocation = EvalInvocation(
        tool=action,
        argv=tuple(argv),
        env=env,
        target=resolved_target,
        cwd=workdir,
    )
    runner = eval_runner or default_eval_runner
    base_data = {
        "tool": action,
        "target": resolved_target,
        "present": True,
        "live": True,
        "technique": primary,
        "techniques": techniques,
        "argv": list(argv),
        "offline": True,
        "cloud_judge": False,
        "hf_hub_offline": env.get("HF_HUB_OFFLINE") == "1",
    }
    try:
        result = runner(invocation)
    except FileNotFoundError:
        return err(
            f"STOP missing-tool: {action}. Local eval CLI was not found on PATH at exec.",
            root_cause_hint="A present package is not the same as an installed console script.",
            retry="Install the CLI locally or stay plan-only.",
            stop_condition=f"STOP missing-tool: {action}. Do not silently skip.",
            data={**base_data, "executed": False, "scope_refused": True},
        )
    except subprocess.TimeoutExpired:
        return err(
            f"STOP eval-timeout: {action} exceeded the local eval time budget.",
            root_cause_hint="A hung eval is not a finding.",
            retry="Reduce the eval scope or raise the budget, then retry.",
            stop_condition=f"STOP eval-timeout: {action}. Do not mint a finding from a hung run.",
            data={**base_data, "executed": False},
        )
    except OSError as exc:
        return err(
            f"STOP eval-error: {action} failed to launch ({exc}).",
            stop_condition=f"STOP eval-error: {action}. Do not mint a finding from a failed launch.",
            data={**base_data, "executed": False},
        )

    excerpt = sanitize_eval_excerpt(result.excerpt)
    if result.returncode != 0:
        return err(
            f"STOP eval-nonzero-exit: {action} exited {result.returncode}; no pass/fail outcome.",
            root_cause_hint="A non-zero eval exit is a tool/usage error, not a finding.",
            retry="Fix the local eval invocation, then retry --live.",
            stop_condition=f"STOP eval-nonzero-exit: {action}. Do not mint a finding from an errored run.",
            data={**base_data, "executed": True, "returncode": result.returncode, "excerpt": excerpt},
        )

    outcome = parse_eval_outcome(excerpt)
    if outcome == "unknown":
        return warn(
            f"{action} completed vs {resolved_target} but produced no parseable pass/fail outcome.",
            root_cause_hint="No failure/pass count or signal marker was found in the eval output.",
            data={**base_data, "executed": True, "returncode": 0, "excerpt": excerpt, "outcome": "unknown"},
            next_actions=["Inspect the local eval output format; re-run with a parseable summary"],
        )

    evidence_id = _append_eval_evidence(
        vault_dir=vault_dir, tool=action, invocation=invocation, result=result
    )

    if outcome == "clean":
        card = create_clean_negative_card(
            check_name=f"{action} local eval",
            target=resolved_target,
            observation=f"{action} local eval vs {resolved_target}: no prompt-injection/jailbreak signal.",
            technique=primary,
            adapter="estate",
            verb=action,
        )
        card.evidence_ids = [evidence_id]
        return ok(
            f"{action} executed vs {resolved_target}: clean negative (no {primary} signal).",
            evidence_status="clean-negative",
            technique=primary,
            adapter="estate",
            verb=action,
            target=resolved_target,
            data={
                **base_data,
                "executed": True,
                "evidence_status": "clean-negative",
                "status": "clean-negative",
                "finding": card.model_dump(),
                "output_hash": result.output_hash,
                "evidence_ids": [evidence_id],
                "excerpt": excerpt,
                "returncode": 0,
            },
            next_actions=["Record the clean negative; no purple pairing required"],
        )

    card = create_finding_card(
        observation=(
            f"{action} local eval vs {resolved_target}: Potential prompt-injection/jailbreak signal."
        ),
        target=resolved_target,
        evidence_status="Potential",
        technique=primary,
        adapter="estate",
        verb=action,
        domain="AI Estate",
        raw_excerpt=excerpt,
        title=f"Potential {primary} via {action}",
    )
    card.evidence_ids = [evidence_id]
    return ok(
        f"{action} executed vs {resolved_target} (Potential {primary}/{', '.join(techniques[1:] or ['AML.T0054'])}).",
        evidence_status="Potential",
        technique=primary,
        adapter="estate",
        verb=action,
        target=resolved_target,
        data={
            **base_data,
            "executed": True,
            "evidence_status": "Potential",
            "status": "Potential",
            "finding": card.model_dump(),
            "output_hash": result.output_hash,
            "evidence_ids": [evidence_id],
            "excerpt": excerpt,
            "returncode": result.returncode,
        },
        next_actions=["Pair the Potential card with purple-feedback before report"],
    )
