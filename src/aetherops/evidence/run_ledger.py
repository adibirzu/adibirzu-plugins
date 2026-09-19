"""Append-only JSONL run-evidence ledger (CP-10).

Distinct from the CP-7 compliance ledger in ledger.py. Every finding that
reaches a generated report must cite evidence_ids that already exist here.
A finding without evidence ids cannot be constructed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from aetherops.tooling.wrapper import ToolResult, invocation_log


class EvidenceRecord(BaseModel):
    """One tool invocation: raw artifact + command + timestamp + target."""

    evidence_id: str
    tool: str
    argv: list[str]
    cwd: str
    input_hash: str
    output_hash: str
    artifact_path: str
    timestamp: str
    target: str | None = None
    binary: str = ""
    version: str = ""
    returncode: int = 0
    timeout_s: int = 0


class EvidencedFinding(BaseModel):
    """Finding that cannot exist without at least one evidence id."""

    id: str
    title: str
    observation: str = ""
    target: str | None = None
    evidence_ids: list[str] = Field(min_length=1)
    severity: str = "Medium"
    technique: str = "unknown"

    @field_validator("evidence_ids")
    @classmethod
    def _ids_present(cls, value: list[str]) -> list[str]:
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        if not cleaned:
            raise ValueError("evidence_ids must contain at least one id")
        return cleaned


class LedgerReportError(ValueError):
    """Report generation refused because evidence is missing."""


class RunLedger:
    """Append-only JSONL. Existing evidence_ids are never rewritten."""

    def __init__(self, path: Path, artifacts_dir: Path | None = None) -> None:
        self.path = Path(path)
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir is not None else self.path.parent / "artifacts"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def records(self) -> list[EvidenceRecord]:
        rows: list[EvidenceRecord] = []
        text = self.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip():
                continue
            rows.append(EvidenceRecord.model_validate(json.loads(line)))
        return rows

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        for row in self.records():
            if row.evidence_id == evidence_id:
                return row
        return None

    def known_ids(self) -> set[str]:
        return {row.evidence_id for row in self.records()}

    def append_result(self, result: ToolResult, *, timestamp: str | None = None) -> EvidenceRecord:
        stamp = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        evidence_id = result.evidence_id or f"ev-{uuid4().hex[:16]}"
        if evidence_id in self.known_ids():
            raise LedgerReportError(f"evidence_id {evidence_id} already exists (append-only)")
        artifact = self.artifacts_dir / f"{evidence_id}.txt"
        artifact.write_text(result.normalized, encoding="utf-8")
        payload = invocation_log(result)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            tool=str(payload["tool"]),
            argv=list(payload["argv"]),
            cwd=str(payload["cwd"]),
            input_hash=str(payload["input_hash"]),
            output_hash=str(payload["output_hash"]),
            artifact_path=str(artifact),
            timestamp=stamp,
            target=payload.get("target"),
            binary=str(payload.get("binary") or ""),
            version=str(payload.get("version") or ""),
            returncode=int(payload.get("returncode") or 0),
            timeout_s=int(payload.get("timeout_s") or 0),
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        return record


def require_evidence(finding: EvidencedFinding, ledger: RunLedger) -> None:
    missing = [eid for eid in finding.evidence_ids if ledger.get(eid) is None]
    if missing:
        raise LedgerReportError(f"finding {finding.id} cites unknown evidence_ids: {missing}")


def render_from_ledger(findings: list[EvidencedFinding], ledger: RunLedger) -> str:
    """Generate a report body from the ledger. Missing evidence is impossible to emit."""
    if not findings:
        return "# Findings\n\nNo evidenced findings.\n"
    lines = ["# Findings", ""]
    for finding in findings:
        require_evidence(finding, ledger)
        lines.append(f"## {finding.id}: {finding.title}")
        lines.append("")
        lines.append(finding.observation or "")
        lines.append("")
        lines.append(f"- target: `{finding.target or 'n/a'}`")
        lines.append(f"- severity: {finding.severity}")
        lines.append(f"- technique: {finding.technique}")
        lines.append("- evidence:")
        for eid in finding.evidence_ids:
            rec = ledger.get(eid)
            assert rec is not None  # require_evidence already checked
            lines.append(
                f"  - `{rec.evidence_id}` tool={rec.tool} "
                f"output_hash={rec.output_hash} artifact={rec.artifact_path}"
            )
        lines.append("")
    return "\n".join(lines)


def finding_from_dict(payload: dict[str, Any]) -> EvidencedFinding:
    return EvidencedFinding.model_validate(payload)
