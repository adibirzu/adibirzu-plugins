"""Append-only JSONL evidence ledger for deterministic tool runs.

Every record gets a unique evidence ID (``evd-<short-hash>``), the full
argv, timestamp, target, input hash, and the raw tool output artifact
path.  The ledger file is strictly append-only — no reads-back, no
edits, no truncation.

Usage::

    ledger = EvidenceLedger(Path("evidence.jsonl"))
    record = ledger.record(tool_result)
    # record.evidence_id  →  "evd-a3f1b2c4"
    # record.artifact_path →  Path("evidence/evd-a3f1b2c4.txt")
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aetherops.tooling.deterministic import ToolResult


@dataclass(frozen=True)
class EvidenceRecord:
    """One ledger entry for a deterministic tool run."""

    evidence_id: str
    timestamp: str
    binary: str
    argv: list[str]
    cwd: str
    target: str
    input_hash: str
    exit_code: int
    version: str
    duration_s: float
    timed_out: bool
    scope_blocked: bool
    artifact_path: Path | None = None
    normalized: dict[str, Any] = field(default_factory=dict)
    stderr_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "binary": self.binary,
            "argv": self.argv,
            "cwd": self.cwd,
            "target": self.target,
            "input_hash": self.input_hash,
            "exit_code": self.exit_code,
            "version": self.version,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "scope_blocked": self.scope_blocked,
            "normalized": self.normalized,
        }
        if self.artifact_path:
            d["artifact_path"] = str(self.artifact_path)
        if self.stderr_snippet:
            d["stderr_snippet"] = self.stderr_snippet
        return d


def _short_hash(full_hash: str) -> str:
    return full_hash[:12]


def _make_evidence_id(argv: list[str], timestamp: str) -> str:
    """Deterministic evidence ID from argv + timestamp."""
    blob = json.dumps({"argv": argv, "ts": timestamp}, sort_keys=True)
    h = hashlib.sha256(blob.encode()).hexdigest()
    return f"evd-{_short_hash(h)}"


def _derive_target(argv: list[str]) -> str:
    """Best-effort target extraction from argv."""
    # For nmap: first non-flag arg.  For nuclei: -target value.  For sqlmap: -u value.
    args = argv[1:] if argv else []
    for i, a in enumerate(args):
        if a == "-target" and i + 1 < len(args):
            return args[i + 1]
        if a == "-u" and i + 1 < len(args):
            return args[i + 1]
    # First non-flag argument
    for a in args:
        if not a.startswith("-"):
            return a
    return ""


class EvidenceLedger:
    """Append-only JSONL ledger for deterministic tool run evidence.

    Each ``record()`` call:
    1. Writes the raw stdout/stderr to ``<evidence_dir>/<evidence_id>.txt``
    2. Appends a JSON line to the ledger file

    The ledger file is never read back or modified after creation.
    """

    def __init__(
        self,
        ledger_path: Path | str,
        *,
        evidence_dir: Path | str | None = None,
    ) -> None:
        self.ledger_path = Path(ledger_path)
        self.evidence_dir = Path(evidence_dir) if evidence_dir else self.ledger_path.parent / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def record(self, result: ToolResult) -> EvidenceRecord:
        """Append a tool result to the ledger.  Returns the created record."""
        now = datetime.now(UTC).isoformat()
        evidence_id = _make_evidence_id(result.argv, now)
        target = _derive_target(result.argv)

        # Write artifact file
        artifact_path = self.evidence_dir / f"{evidence_id}.txt"
        with open(artifact_path, "w", encoding="utf-8") as f:
            f.write(f"# {result.binary} — {now}\n")
            f.write(f"# argv: {result.argv}\n")
            f.write(f"# exit_code: {result.exit_code}\n")
            f.write(f"# input_hash: {result.input_hash}\n")
            f.write("--- STDOUT ---\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        record = EvidenceRecord(
            evidence_id=evidence_id,
            timestamp=now,
            binary=result.binary,
            argv=result.argv,
            cwd=result.cwd,
            target=target,
            input_hash=result.input_hash,
            exit_code=result.exit_code,
            version=result.version,
            duration_s=result.duration_s,
            timed_out=result.timed_out,
            scope_blocked=result.scope_blocked,
            artifact_path=artifact_path,
            normalized=result.normalized,
            stderr_snippet=result.stderr[:200] if result.stderr else "",
        )

        # Append to ledger
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")

        return record

    def record_manual(
        self,
        binary: str,
        argv: list[str],
        target: str,
        *,
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        version: str = "manual",
        input_hash: str = "",
    ) -> EvidenceRecord:
        """Record a manual / external tool run not executed by DeterministicTool."""
        from aetherops.tooling.deterministic import _compute_input_hash

        now = datetime.now(UTC).isoformat()
        evidence_id = _make_evidence_id(argv, now)
        if not input_hash:
            input_hash = _compute_input_hash(argv, os.getcwd())

        artifact_path = self.evidence_dir / f"{evidence_id}.txt"
        with open(artifact_path, "w", encoding="utf-8") as f:
            f.write(f"# {binary} — {now} (manual)\n")
            f.write(f"# argv: {argv}\n")
            f.write("--- STDOUT ---\n")
            f.write(stdout)
            if stderr:
                f.write("\n--- STDERR ---\n")
                f.write(stderr)

        record = EvidenceRecord(
            evidence_id=evidence_id,
            timestamp=now,
            binary=binary,
            argv=argv,
            cwd=os.getcwd(),
            target=target,
            input_hash=input_hash,
            exit_code=exit_code,
            version=version,
            duration_s=0.0,
            timed_out=False,
            scope_blocked=False,
            artifact_path=artifact_path,
            stderr_snippet=stderr[:200] if stderr else "",
        )

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")

        return record
