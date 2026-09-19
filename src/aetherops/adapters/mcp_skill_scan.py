"""Estate MCP / skill defensive scanners (PRD-MS-2).

Composes already-installed local CLIs (NVIDIA SkillSpector, Cisco mcp-scanner,
Snyk agent-scan) as run-or-STOP. Argv is constructed here — no shell, no
cloud judge, no plugin download. Scan paths stay inside the workspace and
never include vault/, engagements/, or reports/.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from shutil import which
from typing import Any
from uuid import uuid4

from aetherops.config import ROOT
from aetherops.evidence.run_ledger import RunLedger
from aetherops.harness.observation import err, ok
from aetherops.plan.stages import can_live
from aetherops.purple.catalog import lookup
from aetherops.scope.verbs import contains_payload_shape, is_permanent_deny
from aetherops.tooling.wrapper import (
    ToolResult,
    frozen_env,
    output_hash,
)
from aetherops.tooling.wrapper import (
    input_hash as argv_input_hash,
)
from aetherops.types import Engagement, Observation

ScannerRunner = Callable[[str, str, dict[str, Any] | None], Any]
PresenceChecker = Callable[[str], bool]

STDOUT_TRUNCATE = 512
LEAK_WINDOW = 48
LEAK_MAX_FILES = 20000
LEAK_MAX_BYTES = 4194304
LEAK_MAX_TOTAL_BYTES = 33554432
LEAK_REDACTED = ""
UNVERIFIED_PREFIX = "unverified-"
LEAK_ANCHOR = LEAK_WINDOW // 2
LEAK_MAX_ANCHOR_HITS = 512
JSON_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
JSON_ESCAPE_RE = re.compile(r'\\(u[0-9a-fA-F]{4}|["\\/bfnrt])')
FINDING_DESCRIPTION_KEYS = (
    "summary",
    "message",
    "description",
    "detail",
    "issue",
    "reason",
    "text",
)
FINDING_MAP_MAX_DEPTH = 6
TECHNIQUE = "AML.T0010"
SUPPLY_CHAIN = "T1195"
FORBIDDEN_PATH_PARTS = frozenset({"vault", "engagements", "reports"})
FORBIDDEN_FILE_RE = re.compile(r"^engagement.*\.ya?ml$", re.IGNORECASE)
PROTECTED_HINT = "vault/engagements/reports and the engagement ROE are never scanned"
FORBIDDEN_FLAGS = frozenset(
    {
        "--submit",
        "--cloud",
        "--judge",
        "--upload",
        "--download-plugins",
        "--remote-plugins",
        "--api-key",
        "--openai",
        "--anthropic",
    }
)
CLOUD_ENV = ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OFFSEC_LLM_BASE_URL")
LOCAL_TARGET_RE = re.compile(r"^https?://(?:127\.0\.0\.1|localhost)(?::\d+)?(?:/.*)?$", re.IGNORECASE)
HOST_LIKE_RE = re.compile(
    r"^(?:https?://)?(?:\d{1,3}(?:\.\d{1,3}){3}|localhost|127\.[0-9.]+)(?::\d+)?(?:/.*)?$",
    re.IGNORECASE,
)

DEFENSIVE_SCANNERS: dict[str, dict[str, Any]] = {
    "skillspector": {
        "kind": "local_cli",
        "command": "skillspector",
        "alt_commands": ("skill-spector", "nvidia-skillspector"),
        "verbs": frozenset({"skill_scan"}),
        "preferred_for": "skill_scan",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "NVIDIA SkillSpector: static/YARA/taint scan of local skill YAML",
        "atlas": TECHNIQUE,
        "attack": SUPPLY_CHAIN,
        "base_args": ("scan", "--offline"),
    },
    "mcp-scanner": {
        "kind": "local_cli",
        "command": "mcp-scanner",
        "alt_commands": ("mcp_scanner", "cisco-mcp-scanner"),
        "verbs": frozenset({"mcp_scan"}),
        "preferred_for": "mcp_scan",
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Cisco mcp-scanner: local MCP server/config scan for tool poisoning",
        "atlas": TECHNIQUE,
        "attack": SUPPLY_CHAIN,
        "base_args": ("--offline", "--no-remote"),
    },
    "agent-scan": {
        "kind": "local_cli",
        "command": "agent-scan",
        "alt_commands": ("agent_scan", "snyk-agent-scan"),
        "verbs": frozenset({"skill_scan", "mcp_scan"}),
        "preferred_for": None,
        "side": "blue",
        "airgap_ok": True,
        "internet_required": False,
        "purpose": "Snyk agent-scan: local agent/skill/MCP config scan",
        "atlas": TECHNIQUE,
        "attack": SUPPLY_CHAIN,
        "base_args": ("scan", "--offline"),
    },
}

MCP_SCAN_VERBS = frozenset({"mcp_scan"})
SKILL_SCAN_VERBS = frozenset({"skill_scan"})
CHECKLIST_VERBS = frozenset({"checklist", "mcp_checklist"})
DEFENSIVE_VERBS = MCP_SCAN_VERBS | SKILL_SCAN_VERBS | CHECKLIST_VERBS


def check_defensive_tool_presence(tool_name: str) -> bool:
    meta = DEFENSIVE_SCANNERS.get(tool_name)
    if not meta:
        return False
    cmd = str(meta.get("command") or "")
    if cmd and which(cmd) is not None:
        return True
    for alt in meta.get("alt_commands") or ():
        if which(str(alt)) is not None:
            return True
    return False


def get_defensive_scanners_status(
    presence_checker: PresenceChecker | None = None,
) -> dict[str, dict[str, Any]]:
    checker = presence_checker or check_defensive_tool_presence
    results: dict[str, dict[str, Any]] = {}
    for name, meta in DEFENSIVE_SCANNERS.items():
        results[name] = {**meta, "present": bool(checker(name)), "verbs": sorted(meta["verbs"])}
    return results


def scanners_for_verb(verb: str) -> tuple[str, ...]:
    action = (verb or "").strip().lower()
    names = [name for name, meta in DEFENSIVE_SCANNERS.items() if action in meta["verbs"]]
    preferred = [
        name for name, meta in DEFENSIVE_SCANNERS.items() if meta.get("preferred_for") == action
    ]
    ordered = preferred + [n for n in names if n not in preferred]
    return tuple(ordered)


def default_scan_path(verb: str, workspace: Path) -> Path:
    action = (verb or "").strip().lower()
    if action in MCP_SCAN_VERBS:
        local = workspace / "configs" / "mcp.json"
        if local.is_file():
            return local
        return workspace / "configs" / "mcp.example.json"
    return workspace / "skills"


def _cloud_env_blocked() -> str | None:
    for name in CLOUD_ENV:
        if os.environ.get(name):
            return name
    return None


def _flag_smuggled(arguments: dict[str, Any] | None) -> str | None:
    if not arguments:
        return None
    tokens: list[str] = []
    for value in arguments.values():
        if isinstance(value, str):
            tokens.extend(value.split())
        elif isinstance(value, (list, tuple)):
            tokens.extend(str(item) for item in value)
    for token in tokens:
        lowered = token.strip().lower()
        if lowered in FORBIDDEN_FLAGS:
            return lowered
    return None


def walk_scan_tree(path: Path) -> tuple[list[Path], list[Path], bool]:
    """Walk the scan tree, following symlinked directories. Returns (dirs, files, complete).

    ``complete`` is False when the walk could not be finished (unreadable entry,
    symlink loop, or budget exceeded), so callers fail closed instead of trusting
    partial coverage.
    """
    dirs: list[Path] = []
    files: list[Path] = []
    seen: set[Path] = set()
    stack: list[Path] = [path]
    while stack:
        current = stack.pop()
        try:
            real = current.resolve()
        except (OSError, RuntimeError):
            return dirs, files, False
        if real in seen:
            continue
        seen.add(real)
        if len(seen) > LEAK_MAX_FILES:
            return dirs, files, False
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return dirs, files, False
        for entry in entries:
            try:
                if entry.is_dir():
                    dirs.append(entry)
                    stack.append(entry)
                elif entry.is_file():
                    files.append(entry)
            except OSError:
                return dirs, files, False
    return dirs, files, True


def _resolved_conflict(candidate: Path, root: Path, protected: Sequence[Path]) -> str | None:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return f"SCOPE DENIED: scan path reaches '{candidate}' outside the workspace."
    for part in relative.parts:
        if part.lower() in FORBIDDEN_PATH_PARTS:
            return f"SCOPE DENIED: scan path reaches {part}/ (never vault/engagements/reports)."
        if FORBIDDEN_FILE_RE.match(part):
            return f"SCOPE DENIED: scan path reaches {part} (engagement ROE is never scanned)."
    for target in protected:
        if candidate == target:
            return f"SCOPE DENIED: scan path is protected {target.name} ({PROTECTED_HINT})."
        for inner, outer in ((target, candidate), (candidate, target)):
            try:
                inner.relative_to(outer)
            except ValueError:
                continue
            return f"SCOPE DENIED: scan path overlaps protected {target.name} ({PROTECTED_HINT})."
    return None


def _protected_conflict(
    resolved: Path, protected: Sequence[Path] = (), *, root: Path | None = None
) -> str | None:
    """Deny reason when the scan path — or anything its tree links to — is protected."""
    base = (root or resolved).resolve()
    guarded: list[Path] = []
    for target in protected:
        try:
            guarded.append(Path(target).resolve())
        except (OSError, RuntimeError):
            continue
    conflict = _resolved_conflict(resolved, base, guarded)
    if conflict:
        return conflict
    if not resolved.is_dir():
        return None
    dirs, files, complete = walk_scan_tree(resolved)
    if not complete:
        return (
            "SCOPE DENIED: scan path tree could not be verified "
            "(unreadable entry or symlink loop)."
        )
    for entry in dirs + files:
        try:
            real = entry.resolve()
        except (OSError, RuntimeError):
            return "SCOPE DENIED: scan path contains an unresolvable entry."
        conflict = _resolved_conflict(real, base, guarded)
        if conflict:
            return conflict
    return None


def resolve_scan_path(
    *,
    verb: str,
    requested: str | None,
    workspace: Path,
    protected: Sequence[Path] = (),
) -> tuple[Path | None, str | None]:
    """Return (resolved path, deny reason). Deny vault/engagements/reports and escapes."""
    root = workspace.resolve()
    raw = (requested or "").strip() or str(default_scan_path(verb, root))
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        return None, f"SCOPE DENIED: scan path is not resolvable ({exc})."
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None, f"SCOPE DENIED: scan path '{resolved}' is outside the workspace."
    for part in relative.parts:
        if part.lower() in FORBIDDEN_PATH_PARTS:
            return None, f"SCOPE DENIED: refusing to scan {part}/ (never vault/engagements/reports)."
    if resolved == root:
        return None, (
            "SCOPE DENIED: refusing to scan the workspace root "
            "(never vault/engagements/reports). Point --path at configs/mcp.json or skills/."
        )
    guarded = [root / name for name in sorted(FORBIDDEN_PATH_PARTS)]
    guarded.extend(Path(item) for item in protected)
    enclosed = _protected_conflict(resolved, guarded, root=root)
    if enclosed:
        return None, enclosed
    blob = str(resolved)
    if is_permanent_deny(blob) or contains_payload_shape(blob):
        return None, "SCOPE DENIED: scan path is C2/payload-shaped."
    if not resolved.exists():
        return None, f"STOP missing-path: scan path '{resolved}' does not exist."
    return resolved, None


def build_scanner_argv(tool_name: str, path: Path) -> list[str]:
    meta = DEFENSIVE_SCANNERS[tool_name]
    binary = str(meta["command"])
    resolved_bin = which(binary)
    if resolved_bin is None:
        for alt in meta.get("alt_commands") or ():
            resolved_bin = which(str(alt))
            if resolved_bin:
                break
    argv0 = resolved_bin or binary
    argv = [argv0, *[str(a) for a in meta.get("base_args") or ()], str(path)]
    for token in argv[1:]:
        if token.strip().lower() in FORBIDDEN_FLAGS:
            raise ValueError(f"refusing cloud/judge flag {token}")
    return argv


def _fingerprint(path: Path) -> str:
    """Hash path metadata (and file bytes for a single file). Never returned as a body.

    Uses the same symlink-following walk as the leak guard and the path ban, so the
    ledger's input_hash covers exactly what the scanner sees. An unverifiable tree
    fails closed to a distinctly prefixed digest instead of a content claim.
    """
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    lines: list[str] = []
    complete = True
    if path.is_dir():
        _dirs, files, complete = walk_scan_tree(path)
        seen: set[Path] = set()
        for child in sorted(files):
            try:
                real = child.resolve()
                if real in seen:
                    continue
                seen.add(real)
                rel = child.relative_to(path)
                st = child.stat()
            except (OSError, RuntimeError, ValueError):
                complete = False
                continue
            lines.append(f"{rel}:{st.st_size}:{st.st_mtime_ns}")
    digest = hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()
    return digest if complete else f"{UNVERIFIED_PREFIX}{digest}"


def _truncate(text: str) -> str:
    blob = text or ""
    if len(blob) <= STDOUT_TRUNCATE:
        return blob
    return blob[:STDOUT_TRUNCATE] + "…"


def _as_text(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (dict, list)):
        return json.dumps(raw, sort_keys=True, ensure_ascii=False)
    return str(raw)


def _looks_like_finding(payload: dict[str, Any]) -> bool:
    """A finding names itself (title/rule) or carries a severity, in any container."""
    if payload.get("title") or payload.get("rule"):
        return True
    return bool(payload.get("severity"))


def _collect_finding_items(value: Any, *, depth: int = 0) -> tuple[list[dict[str, Any]], bool]:
    """Return (finding objects, dropped) for one node of a findings/results container.

    Lists and maps are normalized by the same walk, so a scalar leaf is never a
    finding at one nesting level and dropped at another. ``dropped`` is True when a
    non-empty leaf was discarded, so the caller never reports a scan clean after
    throwing content away.
    """
    if value is None:
        return [], False
    if isinstance(value, (list, tuple)):
        items: list[dict[str, Any]] = []
        dropped = False
        for entry in value:
            nested, nested_dropped = _collect_finding_items(entry, depth=depth)
            items.extend(nested)
            dropped = dropped or nested_dropped
        return items, dropped
    if isinstance(value, dict):
        if not value:
            return [], False
        if _looks_like_finding(value):
            return [value], False
        if depth >= FINDING_MAP_MAX_DEPTH:
            return [], True
        items = []
        dropped = False
        for entry in value.values():
            nested, nested_dropped = _collect_finding_items(entry, depth=depth + 1)
            items.extend(nested)
            dropped = dropped or nested_dropped
        return items, dropped
    return [], bool(str(value).strip())


def parse_scanner_findings(raw: Any, *, path: Path, evidence_id: str) -> list[dict[str, Any]]:
    """Normalize scanner stdout to Potential cards. Never copies the scanned body."""
    payload: Any = raw
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith(("{", "[")):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"summary": _truncate(text)}
        else:
            payload = {"summary": _truncate(text)}
    items: list[Any] = []
    unparsed: str | None = None
    dropped = False
    if isinstance(payload, dict):
        if "findings" in payload or "results" in payload:
            container = payload["findings"] if "findings" in payload else payload["results"]
            items, dropped = _collect_finding_items(container)
        elif _looks_like_finding(payload):
            items = [payload]
        else:
            items, dropped = _collect_finding_items(payload)
            if not items:
                unparsed = _truncate(
                    str(payload.get("summary") or payload.get("message") or "")
                    or _as_text(payload)
                )
    elif isinstance(payload, list):
        items, dropped = _collect_finding_items(payload)
    else:
        unparsed = _truncate(_as_text(payload))
    if not items and dropped and not unparsed:
        unparsed = _truncate(_as_text(payload))
    purple = lookup(TECHNIQUE)
    pair = None
    if purple is not None:
        pair = {
            "detection_name": purple.name,
            "data_source": purple.data_source,
            "logic": purple.logic,
            "control": purple.control,
            "technique": purple.technique,
            "catalog_id": purple.catalog_id,
        }
    cards: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            item = {"title": _truncate(str(item))}
        title = str(item.get("title") or item.get("name") or item.get("rule") or "MCP/skill scanner finding")
        described = next(
            (str(item[key]) for key in FINDING_DESCRIPTION_KEYS if item.get(key)), title
        )
        observation = _truncate(described)
        cards.append(
            {
                "title": title[:120],
                "observation": observation,
                "target": str(path),
                "evidence_status": "Potential",
                "status": "Potential",
                "severity": str(item.get("severity") or "Medium"),
                "technique": TECHNIQUE,
                "adapter": "estate",
                "evidence_ids": [evidence_id],
                "purple_pair": pair,
                "raw_excerpt": None,
            }
        )
    if not cards:
        cards.append(
            {
                "title": "MCP/skill scan clean-or-unparsed"
                if unparsed
                else "MCP/skill scan clean-or-empty",
                "observation": unparsed or f"Scanner returned no finding objects for {path}.",
                "target": str(path),
                "evidence_status": "Potential",
                "status": "Potential",
                "severity": "Info",
                "technique": TECHNIQUE,
                "adapter": "estate",
                "evidence_ids": [evidence_id],
                "purple_pair": pair,
                "raw_excerpt": None,
            }
        )
    return cards


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split())


def _json_unescape(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("u"):
            try:
                return chr(int(token[1:], 16))
            except ValueError:
                return match.group(0)
        return JSON_ESCAPES.get(token, match.group(0))

    return JSON_ESCAPE_RE.sub(_replace, text or "")


def _leak_views(text: str) -> tuple[str, ...]:
    """Comparable forms of ``text``: whitespace-normalized, and JSON-unescaped."""
    plain = _normalize_ws(text)
    decoded = _normalize_ws(_json_unescape(text))
    if decoded == plain:
        return (plain,)
    return (plain, decoded)


def leak_corpus(path: Path) -> tuple[tuple[str, ...], bool]:
    """Return (comparable forms of the bodies under the scan path, coverage complete).

    Incomplete coverage fails closed: callers redact unconditionally rather than
    letting an unexamined body reach the vault.
    """
    if path.is_file():
        files = [path]
    elif path.is_dir():
        _dirs, walked, complete = walk_scan_tree(path)
        if not complete:
            return (), False
        seen: set[Path] = set()
        files = []
        for child in walked:
            try:
                real = child.resolve()
            except (OSError, RuntimeError):
                return (), False
            if real in seen:
                continue
            seen.add(real)
            files.append(child)
    else:
        return (), True
    if len(files) > LEAK_MAX_FILES:
        return (), False
    parts: list[str] = []
    total = 0
    for child in files:
        try:
            if child.stat().st_size > LEAK_MAX_BYTES:
                return (), False
            body = child.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return (), False
        total += len(body)
        if total > LEAK_MAX_TOTAL_BYTES:
            return (), False
        if body.strip():
            parts.append(body)
    return _leak_views("\n".join(parts)), True


def _blob_leaked(blob: str, corpus: str) -> bool:
    if len(blob) < LEAK_WINDOW or not corpus:
        return False
    probes = {
        blob[start : start + LEAK_WINDOW] for start in range(len(blob) - LEAK_WINDOW + 1)
    }
    anchors = {
        blob[start : start + LEAK_ANCHOR]
        for start in range(0, len(blob) - LEAK_ANCHOR + 1, LEAK_ANCHOR)
    }
    for anchor in anchors:
        start = 0
        hits = 0
        while True:
            found = corpus.find(anchor, start)
            if found < 0:
                break
            hits += 1
            if hits > LEAK_MAX_ANCHOR_HITS:
                return True
            for begin in range(max(0, found - LEAK_ANCHOR), found + 1):
                if corpus[begin : begin + LEAK_WINDOW] in probes:
                    return True
            start = found + 1
    return False


def body_leaked(text: str, corpus: Sequence[str], *, complete: bool = True) -> bool:
    """True when any LEAK_WINDOW-long run of ``text`` occurs verbatim in ``corpus``.

    Both sides are compared whitespace-normalized and JSON-unescaped, so a scanner
    that emits an echoed body as an escaped JSON string is caught too. Aligned
    anchors prefilter the corpus; every offset of the bounded text is then checked.
    """
    views = _leak_views(text)
    if not any(len(view) >= LEAK_WINDOW for view in views):
        return False
    if not complete:
        return True
    return any(_blob_leaked(view, blob) for view in views for blob in corpus)


def _scrub(text: str, corpus: Sequence[str], *, complete: bool = True) -> str:
    """Never let a scanned body reach the vault, the ledger, or a finding card."""
    return LEAK_REDACTED if body_leaked(text, corpus, complete=complete) else text


def _has_structured_findings(raw: Any) -> bool:
    payload: Any = raw
    if isinstance(raw, str):
        text = raw.strip()
        if not (text.startswith(("{", "["))):
            return False
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return False
    if isinstance(payload, (list, dict)):
        return bool(_collect_finding_items(payload)[0])
    return False


def _invoke(argv: list[str], *, cwd: Path, timeout_s: int = 60) -> tuple[str, str, int]:
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
        shell=False,
        cwd=str(cwd),
        env=frozen_env(Path(argv[0]), cwd),
    )
    return (completed.stdout or ""), (completed.stderr or ""), int(completed.returncode)


def run_defensive_scan(
    verb: str,
    *,
    engagement: Engagement | None,
    live: bool = False,
    target: str | None = None,
    arguments: dict[str, Any] | None = None,
    presence_checker: PresenceChecker | None = None,
    scanner_runner: ScannerRunner | None = None,
    workspace: Path | None = None,
    vault_dir: Path | None = None,
    reports_dir: Path | None = None,
    engagement_file: Path | None = None,
) -> Observation:
    action = (verb or "").strip().lower()
    if action in CHECKLIST_VERBS:
        from aetherops.knowledge.mcp_checklist import checklist_observation, is_checklist_id

        args = arguments or {}
        limit_raw = args.get("limit")
        try:
            limit = int(limit_raw) if limit_raw is not None else 32
        except (TypeError, ValueError):
            limit = 32
        control_id = str(args.get("skill") or "").strip()
        if not control_id:
            candidate = str(args.get("name") or "").strip()
            if is_checklist_id(candidate):
                control_id = candidate
        return checklist_observation(
            query=str(args.get("query") or target or ""),
            name=control_id or None,
            limit=limit,
        )
    if action not in MCP_SCAN_VERBS | SKILL_SCAN_VERBS:
        return err(
            f"Unknown defensive scan verb: {verb}",
            stop_condition="Use estate mcp_scan, skill_scan, or checklist.",
            data={"scope_refused": True, "executed": False},
        )

    root = (workspace or ROOT).resolve()
    args = arguments or {}
    smuggled = _flag_smuggled(args) or _flag_smuggled({"target": target})
    if smuggled:
        return err(
            "SCOPE DENIED: cloud judge / submit flag is not allowed on defensive scanners.",
            stop_condition="Do not pass --submit/--cloud/--judge. Local CLI only.",
            data={"scope_refused": True, "executed": False, "flag": smuggled, "verb": action},
        )

    requested = str(args.get("path") or "").strip() or None
    if not requested:
        hint = (target or "").strip()
        if hint and not HOST_LIKE_RE.match(hint) and not LOCAL_TARGET_RE.match(hint):
            requested = hint
    protected = [
        Path(item) for item in (vault_dir, reports_dir, engagement_file) if item is not None
    ]
    path, deny = resolve_scan_path(
        verb=action, requested=requested, workspace=root, protected=protected
    )
    if deny or path is None:
        reason = deny or "SCOPE DENIED: scan path refused."
        refused = not reason.startswith("STOP ")
        return err(
            reason,
            stop_condition=(
                "SCOPE DENIED. Scan local configs/mcp.json or skills/ only. Never vault/."
                if refused
                else "STOP missing-path. Point --path at an existing local config or skill directory."
            ),
            data={
                "scope_refused": refused,
                "path_missing": not refused,
                "executed": False,
                "path": requested,
                "verb": action,
            },
        )

    applicable = scanners_for_verb(action)
    status = get_defensive_scanners_status(presence_checker)
    present = [name for name in applicable if status[name]["present"]]
    missing = [name for name in applicable if name not in present]

    if not live:
        return ok(
            f"estate.{action} planned vs {path} (ATLAS {TECHNIQUE}; not executed).",
            data={
                "verb": action,
                "path": str(path),
                "scanners": applicable,
                "present": present,
                "missing_tools": missing,
                "live": False,
                "executed": False,
                "technique": TECHNIQUE,
            },
            next_actions=["Signed L1 + allow_live_tools + installed CLI to execute; missing CLI → STOP"],
        )

    if engagement is None or not can_live(engagement):
        return err(
            "SCOPE DENIED: example/unsigned engagement cannot execute MCP/skill scanners.",
            stop_condition="Replace configs/engagement.example.yaml with a signed ROE (allow_live_tools, L1).",
            data={"scope_refused": True, "executed": False, "verb": action, "path": str(path)},
        )

    blocked = _cloud_env_blocked()
    if blocked:
        return err(
            "SCOPE DENIED: cloud LLM judge env is set on the engage path.",
            root_cause_hint=f"{blocked} must be unset; no cloud judge.",
            stop_condition="Do not send scanner output to a cloud judge.",
            data={"executed": False, "scope_refused": True, "env": blocked},
        )

    run_names = list(present)
    if not run_names and scanner_runner is not None:
        run_names = [applicable[0]] if applicable else []
    if not run_names:
        missing_str = ", ".join(missing or applicable) or action
        return err(
            f"STOP missing-tool: {missing_str}. MCP/skill defensive scanner is not installed locally.",
            root_cause_hint="AetherOps composes SkillSpector / mcp-scanner / agent-scan as run-or-STOP.",
            retry="Install one applicable local CLI, then retry. Do not skip.",
            stop_condition=f"STOP missing-tool: {missing_str}. Do not silently skip.",
            data={
                "missing_tools": missing or list(applicable),
                "present": False,
                "executed": False,
                "tool_failed": True,
                "scope_refused": False,
                "verb": action,
            },
        )

    path_hash = _fingerprint(path)
    corpus, leak_complete = leak_corpus(path)
    ledger = (
        RunLedger(Path(vault_dir) / "run-ledger.jsonl", artifacts_dir=Path(vault_dir) / "artifacts")
        if vault_dir is not None
        else None
    )
    collected: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    truncated_chunks: list[str] = []
    evidence_ids: list[str] = []
    for name in run_names:
        argv = build_scanner_argv(name, path)
        returncode = 0
        stderr_text = ""
        if scanner_runner is not None:
            raw = scanner_runner(name, str(path), args)
        else:
            try:
                raw, stderr_text, returncode = _invoke(argv, cwd=root)
            except FileNotFoundError:
                return err(
                    f"STOP missing-tool: {name}. MCP/skill defensive scanner is not installed locally.",
                    stop_condition=f"STOP missing-tool: {name}. Do not silently skip.",
                    data={
                        "tool": name,
                        "present": False,
                        "executed": False,
                        "tool_failed": True,
                        "scope_refused": False,
                        "evidence_ids": list(evidence_ids),
                    },
                )
            except subprocess.TimeoutExpired:
                return err(
                    f"STOP: {name} exceeded timeout.",
                    stop_condition="Retry with a smaller local path. Do not skip.",
                    data={
                        "tool": name,
                        "executed": False,
                        "tool_failed": True,
                        "scope_refused": False,
                        "evidence_ids": list(evidence_ids),
                    },
                )
        text = _as_text(raw)
        leaked = body_leaked(_truncate(text), corpus, complete=leak_complete)
        chunk = LEAK_REDACTED if leaked else _truncate(text)
        stderr_leaked = body_leaked(_truncate(stderr_text), corpus, complete=leak_complete)
        stderr_chunk = LEAK_REDACTED if stderr_leaked else _truncate(stderr_text)
        leaked = leaked or stderr_leaked
        if returncode != 0 and not _has_structured_findings(raw):
            kept = (
                f" {len(runs)} prior scanner(s) succeeded; "
                f"{len(collected)} finding(s) kept."
                if runs
                else ""
            )
            return err(
                f"STOP scanner-failed: {name} exited {returncode} without parseable findings.{kept}",
                root_cause_hint="The local CLI ran but did not produce a scan result (bad argv or crash).",
                retry="Fix the local scanner invocation, then retry. Do not treat the error text as a finding.",
                stop_condition=f"STOP scanner-failed: {name} exited {returncode}. Do not silently skip.",
                data={
                    "tool": name,
                    "returncode": returncode,
                    "executed": False,
                    "tool_failed": True,
                    "scope_refused": False,
                    "verb": action,
                    "path": str(path),
                    "argv": argv,
                    "stdout_truncated": chunk,
                    "stderr_truncated": stderr_chunk,
                    "stdout_redacted": leaked,
                    "evidence_ids": list(evidence_ids),
                    "findings": list(collected),
                    "runs": list(runs),
                    "scanners": list(run_names),
                    "partial_stdout_truncated": _scrub(
                        _truncate("\n".join(part for part in truncated_chunks if part)),
                        corpus,
                        complete=leak_complete,
                    ),
                },
            )
        evidence_id = f"ev-{uuid4().hex[:16]}"
        artifact_text = chunk + (f"\n[stderr] {stderr_chunk}" if stderr_chunk else "")
        digest_in = argv_input_hash(argv=argv, cwd=str(root), stdin=path_hash)
        digest_out = output_hash(artifact_text)
        if ledger is not None:
            ledger.append_result(
                ToolResult(
                    tool=name,
                    argv=tuple(argv),
                    cwd=str(root),
                    input_hash=digest_in,
                    output_hash=digest_out,
                    normalized=artifact_text,
                    raw=artifact_text,
                    returncode=returncode,
                    timeout_s=60,
                    version="",
                    binary=name,
                    target=str(path),
                    evidence_id=evidence_id,
                )
            )
        evidence_ids.append(evidence_id)
        truncated_chunks.append(chunk)
        runs.append(
            {
                "tool": name,
                "evidence_id": evidence_id,
                "argv": argv,
                "input_hash": digest_in,
                "output_hash": digest_out,
                "returncode": returncode,
                "redacted": leaked,
                "stderr_truncated": stderr_chunk,
            }
        )
        for card in parse_scanner_findings(raw, path=path, evidence_id=evidence_id):
            card["title"] = (
                _scrub(card["title"], corpus, complete=leak_complete) or "MCP/skill scanner finding"
            )
            card["observation"] = _scrub(card["observation"], corpus, complete=leak_complete)
            card["tool"] = name
            collected.append(card)

    truncated = _scrub(
        _truncate("\n".join(chunk for chunk in truncated_chunks if chunk)),
        corpus,
        complete=leak_complete,
    )

    return ok(
        f"estate.{action} executed vs {path} ({len(collected)} Potential card(s), {TECHNIQUE}).",
        data={
            "verb": action,
            "path": str(path),
            "path_hash": path_hash,
            "scanners": run_names,
            "missing_tools": missing,
            "live": True,
            "executed": True,
            "evidence_id": evidence_ids[0],
            "evidence_ids": evidence_ids,
            "runs": runs,
            "input_hash": runs[0]["input_hash"],
            "output_hash": runs[0]["output_hash"],
            "stdout_truncated": truncated,
            "stdout_redacted": any(bool(run["redacted"]) for run in runs) or not leak_complete,
            "leak_guard_complete": leak_complete,
            "findings": collected,
            "technique": TECHNIQUE,
            "argv": runs[0]["argv"],
        },
        evidence_status="Potential",
        technique=TECHNIQUE,
        next_actions=["Pair Potential cards with purple AML.T0010 / T1195 before report"],
    )
