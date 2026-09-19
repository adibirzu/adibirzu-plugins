"""One wrapper for every external scanner invocation."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aetherops.scope.gate import target_in_scope
from aetherops.tooling.manifest import ToolchainManifest, ToolSpec, load_manifest
from aetherops.tooling.normalize import normalize
from aetherops.types import Engagement


class ScopeRefused(Exception):
    """Networked tool asked to touch a target outside the signed engagement."""

    def __init__(self, target: str | None, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"SCOPE DENIED: {reason} (target={target})")


class ToolchainDrift(Exception):
    """Declared version or binary path does not match the live tool."""


class ToolNotDeclared(KeyError):
    """Invocation named a tool that is not in the manifest."""


@dataclass(frozen=True)
class ToolResult:
    tool: str
    argv: tuple[str, ...]
    cwd: str
    input_hash: str
    output_hash: str
    normalized: str
    raw: str
    returncode: int
    timeout_s: int
    version: str
    binary: str
    target: str | None = None
    evidence_id: str | None = None


_FROZEN_ENV_KEYS = ("LC_ALL", "LANG", "TZ", "TERM", "HOME", "PATH")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_hash(*, argv: list[str], cwd: str, stdin: str) -> str:
    payload = json.dumps(
        {"argv": argv, "cwd": cwd, "stdin": stdin},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return _sha256_bytes(payload.encode("utf-8"))


def output_hash(normalized: str) -> str:
    return _sha256_bytes(normalized.encode("utf-8"))


class DeterministicToolRunner:
    """Resolve binaries from the manifest, freeze argv/env, normalize stdout."""

    def __init__(
        self,
        manifest: ToolchainManifest | None = None,
        *,
        manifest_path: Path | None = None,
        engagement: Engagement | None = None,
        workdir: Path | None = None,
        resolved: dict[str, Path] | None = None,
    ) -> None:
        self.manifest = manifest or load_manifest(manifest_path)
        self.engagement = engagement
        self.workdir = Path(workdir) if workdir is not None else Path.cwd()
        self._resolved: dict[str, Path] = dict(resolved or {})

    def verify(self, name: str | None = None) -> dict[str, str]:
        """Resolve binaries and fail closed on version drift. No PATH at run time."""
        names = [name] if name else list(self.manifest.tools)
        live: dict[str, str] = {}
        for tool_name in names:
            spec = self.manifest.get(tool_name)
            path = self._resolve_binary(spec)
            reported = self._read_version(path, spec)
            if spec.version not in reported:
                raise ToolchainDrift(
                    f"{tool_name}: expected version {spec.version!r}, live reported {reported!r}"
                )
            self._resolved[tool_name] = path
            live[tool_name] = reported.strip()
        return live

    def run(
        self,
        name: str,
        extra_args: list[str] | None = None,
        *,
        target: str | None = None,
        cwd: Path | None = None,
        stdin: str = "",
        timeout_s: int | None = None,
    ) -> ToolResult:
        try:
            spec = self.manifest.get(name)
        except KeyError as exc:
            raise ToolNotDeclared(str(exc)) from exc
        if spec.networked:
            self._assert_scope(target)
        if name not in self._resolved:
            self.verify(name)
        binary = self._resolved[name]
        workdir = Path(cwd) if cwd is not None else self.workdir
        workdir.mkdir(parents=True, exist_ok=True)
        argv = self._argv(binary, spec, extra_args or [])
        digest = input_hash(argv=argv, cwd=str(workdir.resolve()), stdin=stdin)
        timeout = int(timeout_s if timeout_s is not None else spec.timeout_s)
        env = self._frozen_env(binary, workdir)
        try:
            completed = subprocess.run(
                argv,
                cwd=str(workdir),
                input=stdin if stdin else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"{name} exceeded timeout_s={timeout}") from exc
        raw = (completed.stdout or "") + (("\n" + completed.stderr) if completed.stderr else "")
        normalized = normalize(spec.normalizer, raw)
        return ToolResult(
            tool=name,
            argv=tuple(argv),
            cwd=str(workdir.resolve()),
            input_hash=digest,
            output_hash=output_hash(normalized),
            normalized=normalized,
            raw=raw,
            returncode=int(completed.returncode),
            timeout_s=timeout,
            version=spec.version,
            binary=str(binary),
            target=target,
        )

    def _assert_scope(self, target: str | None) -> None:
        if self.engagement is None:
            raise ScopeRefused(target, "networked tool requires a signed engagement")
        if not target:
            raise ScopeRefused(target, "networked tool requires an explicit in-scope target")
        if not target_in_scope(target, self.engagement):
            raise ScopeRefused(
                target,
                "target is outside scope_hosts/scope_cidrs or listed out_of_scope",
            )

    def _resolve_binary(self, spec: ToolSpec) -> Path:
        candidate = Path(spec.binary)
        if candidate.is_absolute():
            if not candidate.is_file():
                raise ToolchainDrift(f"{spec.name}: binary not found at {candidate}")
            return candidate.resolve()
        # Bare names resolve once at verify() against PATH, then freeze.
        path_env = os.environ.get("PATH", "")
        for folder in path_env.split(os.pathsep):
            if not folder:
                continue
            hit = Path(folder) / spec.binary
            if hit.is_file() and os.access(hit, os.X_OK):
                return hit.resolve()
        raise ToolchainDrift(f"{spec.name}: binary {spec.binary!r} not found (no ambient fallback after verify)")

    def _read_version(self, path: Path, spec: ToolSpec) -> str:
        try:
            completed = subprocess.run(
                [str(path), *spec.version_args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=self._frozen_env(path, self.workdir),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ToolchainDrift(f"{spec.name}: version probe failed: {exc}") from exc
        return (completed.stdout or "") + (completed.stderr or "")

    def _argv(self, binary: Path, spec: ToolSpec, extra: list[str]) -> list[str]:
        argv = [str(binary)]
        argv.extend(spec.base_args)
        argv.extend(spec.non_interactive_args)
        argv.extend(extra)
        return argv

    def _frozen_env(self, binary: Path, workdir: Path) -> dict[str, str]:
        return frozen_env(binary, workdir)


def frozen_env(binary: Path, workdir: Path) -> dict[str, str]:
    """Minimal environment for a spawned tool: no inherited credentials or proxies."""
    env: dict[str, str] = {key: "" for key in _FROZEN_ENV_KEYS}
    entries = [str(binary.parent)] if binary.is_absolute() else []
    entries.extend(["/usr/bin", "/bin"])
    env.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "TERM": "dumb",
            "HOME": str(workdir.resolve()),
            "PATH": os.pathsep.join(entries),
        }
    )
    return env


def invocation_log(result: ToolResult) -> dict[str, Any]:
    """Full argv + cwd + input-hash record for the evidence ledger."""
    return {
        "tool": result.tool,
        "argv": list(result.argv),
        "cwd": result.cwd,
        "input_hash": result.input_hash,
        "output_hash": result.output_hash,
        "binary": result.binary,
        "version": result.version,
        "target": result.target,
        "returncode": result.returncode,
        "timeout_s": result.timeout_s,
    }
