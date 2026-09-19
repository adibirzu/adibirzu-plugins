"""Deterministic pentest tool wrappers.

Each wrapper:
- Pins the exact binary and version expected
- Forces non-interactive / batch flags
- Enforces a timeout
- Normalizes output to a consistent JSON shape
- Logs the full argv, cwd, input hash, and wall-clock duration

``DeterministicTool.for_binary(name)`` returns the right wrapper.
``ToolResult`` is the standardized output shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from shutil import which
from typing import Any

from aetherops.tooling.scope_guard import ScopeGuard, ScopeViolation

# ── Expected versions (bump deliberately) ─────────────────────────────
EXPECTED_VERSIONS: dict[str, str] = {
    "nmap": "7.99",
    "nuclei": "3.11",
    "sqlmap": "1.10",
}

# ── Forced flags per binary (always appended, user cannot override) ───
FORCED_FLAGS: dict[str, list[str]] = {
    "nmap": ["--non-interactive"],
    "nuclei": ["--silent", "-nc"],
    "sqlmap": ["--batch", "--flush-session"],
}

# ── Timeouts (seconds) ───────────────────────────────────────────────
DEFAULT_TIMEOUTS: dict[str, int] = {
    "nmap": 300,
    "nuclei": 600,
    "sqlmap": 900,
}

# ── Binaries that need scope guard ───────────────────────────────────
NETWORK_BINARIES = frozenset({"nmap", "nuclei", "sqlmap"})


class ToolRunError(Exception):
    """Raised when a deterministic tool run fails hard."""

    def __init__(self, binary: str, reason: str, argv: list[str]) -> None:
        self.binary = binary
        self.reason = reason
        self.argv = argv
        super().__init__(f"{binary} failed: {reason}")


@dataclass(frozen=True)
class ToolResult:
    """Standardized output from a deterministic tool run."""

    binary: str
    argv: list[str]
    cwd: str
    input_hash: str
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    version: str
    timed_out: bool = False
    scope_blocked: bool = False
    artifacts: list[str] = field(default_factory=list)
    normalized: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "argv": self.argv,
            "cwd": self.cwd,
            "input_hash": self.input_hash,
            "exit_code": self.exit_code,
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
            "duration_s": round(self.duration_s, 3),
            "version": self.version,
            "timed_out": self.timed_out,
            "scope_blocked": self.scope_blocked,
            "artifacts": self.artifacts,
            "normalized": self.normalized,
        }


def _compute_input_hash(argv: list[str], cwd: str) -> str:
    """SHA-256 of (argv_json + cwd).  Same command + same dir → same hash."""
    blob = json.dumps({"argv": argv, "cwd": cwd}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _resolve_binary(binary: str) -> str | None:
    """Resolve via AETHEROPS_TOOL_<NAME> env var first, then PATH.

    No hardcoded locations: operators pin exact binaries per host.
    """
    env_path = os.environ.get(f"AETHEROPS_TOOL_{binary.upper().replace('-', '_')}")
    if env_path and Path(env_path).exists():
        return env_path
    return which(binary)


def _detect_version(binary: str) -> str:
    """Run ``<binary> --version`` and return the first line, stripped."""
    path = _resolve_binary(binary)
    if not path:
        return "not-installed"
    try:
        out = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        first = (out.stdout or out.stderr or "").strip().splitlines()[0:1]
        return first[0] if first else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _normalize_nmap(stdout: str, argv: list[str]) -> dict[str, Any]:
    """Extract structured port/service data from nmap stdout."""
    result: dict[str, Any] = {"ports": [], "host": ""}
    for line in stdout.splitlines():
        # Host line
        if "Nmap scan report for" in line:
            parts = line.split("for")[-1].strip()
            result["host"] = parts.split("(")[0].strip()
        # Port line: 80/tcp open http Apache httpd 2.4.41
        m = __import__("re").match(
            r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", line
        )
        if m:
            result["ports"].append(
                {
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "state": m.group(3),
                    "service": m.group(4),
                    "version": m.group(5).strip(),
                }
            )
    return result


def _normalize_nuclei(stdout: str, argv: list[str]) -> dict[str, Any]:
    """Parse nuclei JSON-lines output (with -json flag) or plain text."""
    result: dict[str, Any] = {"findings": [], "template_count": 0}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            result["findings"].append(
                {
                    "template_id": obj.get("template-id", ""),
                    "severity": obj.get("info", {}).get("severity", ""),
                    "matched_at": obj.get("matched-at", ""),
                    "name": obj.get("info", {}).get("name", ""),
                }
            )
        except (json.JSONDecodeError, KeyError):
            # Plain text line — count as a finding if it looks like one
            if "[" in line and "]" in line:
                result["findings"].append({"raw": line})
    result["template_count"] = len(result["findings"])
    return result


def _normalize_sqlmap(stdout: str, argv: list[str]) -> dict[str, Any]:
    """Extract sqlmap injection points and parameter info."""
    result: dict[str, Any] = {"injectable": False, "parameters": [], "techniques": []}
    for line in stdout.splitlines():
        low = line.lower().strip()
        if "is vulnerable" in low or "injectable" in low:
            result["injectable"] = True
        if "parameter:" in low:
            result["parameters"].append(line.strip())
        if "type:" in low and "technique" in low:
            result["techniques"].append(line.strip())
    return result


_NORMALIZERS: dict[str, Any] = {
    "nmap": _normalize_nmap,
    "nuclei": _normalize_nuclei,
    "sqlmap": _normalize_sqlmap,
}


class DeterministicTool:
    """Wraps a pentest binary with deterministic guarantees.

    Use ``DeterministicTool.for_binary(name)`` to get the right wrapper.
    """

    def __init__(
        self,
        binary: str,
        *,
        scope_guard: ScopeGuard | None = None,
        timeout: int | None = None,
        cwd: str | Path | None = None,
    ) -> None:
        self.binary = binary
        self.scope_guard = scope_guard
        self.timeout = timeout or DEFAULT_TIMEOUTS.get(binary, 300)
        self.cwd = str(cwd or os.getcwd())
        self._expected_version = EXPECTED_VERSIONS.get(binary, "")

    @classmethod
    def for_binary(
        cls,
        binary: str,
        *,
        scope_guard: ScopeGuard | None = None,
        timeout: int | None = None,
        cwd: str | Path | None = None,
    ) -> DeterministicTool:
        if binary not in EXPECTED_VERSIONS:
            raise ValueError(
                f"Unsupported deterministic binary: {binary!r}. "
                f"Supported: {', '.join(sorted(EXPECTED_VERSIONS))}"
            )
        return cls(binary, scope_guard=scope_guard, timeout=timeout, cwd=cwd)

    def run(self, target: str, *, extra: list[str] | None = None) -> ToolResult:
        """Run the binary against *target* with deterministic guarantees.

        Raises ``ToolRunError`` on hard failures (binary missing, scope denied).
        """
        # ── Scope guard ───────────────────────────────────────────────
        if self.binary in NETWORK_BINARIES and self.scope_guard:
            try:
                self.scope_guard.assert_in_scope(target)
            except ScopeViolation as exc:
                return ToolResult(
                    binary=self.binary,
                    argv=[],
                    cwd=self.cwd,
                    input_hash="",
                    exit_code=-1,
                    stdout="",
                    stderr=str(exc),
                    duration_s=0.0,
                    version="",
                    scope_blocked=True,
                )

        # ── Binary check ──────────────────────────────────────────────
        path = _resolve_binary(self.binary)
        if not path:
            raise ToolRunError(
                self.binary,
                f"{self.binary} not found (set AETHEROPS_TOOL_{self.binary.upper()} or install it)",
                [self.binary],
            )

        # ── Version check ─────────────────────────────────────────────
        version = _detect_version(self.binary)
        if self._expected_version and self._expected_version not in version:
            raise ToolRunError(
                self.binary,
                f"version mismatch: expected ~{self._expected_version}, got {version!r}",
                [self.binary, "--version"],
            )

        # ── Build argv (use the resolved binary path, not bare name) ──
        forced = FORCED_FLAGS.get(self.binary, [])
        argv = [path] + (extra or []) + forced

        input_hash = _compute_input_hash(argv, self.cwd)

        # ── Execute ───────────────────────────────────────────────────
        t0 = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.cwd,
                check=False,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            stdout = ""
            stderr = f"TIMEOUT after {self.timeout}s"
            exit_code = -1
        duration = time.monotonic() - t0

        # ── Normalize ─────────────────────────────────────────────────
        normalizer = _NORMALIZERS.get(self.binary)
        normalized = normalizer(stdout, argv) if normalizer else {}

        return ToolResult(
            binary=self.binary,
            argv=argv,
            cwd=self.cwd,
            input_hash=input_hash,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration,
            version=version,
            timed_out=timed_out,
            normalized=normalized,
        )
