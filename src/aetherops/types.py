from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Role = Literal["red", "blue", "purple"]
Status = Literal["success", "warning", "error"]
Lang = Literal["en", "ro"]
Classification = Literal["engagement", "capability", "unknown"]


EvidenceStatus = Literal["Potential", "Verified", "clean-negative", "denied"]
LedgerStatus = Literal["met", "partial", "gap", "not-applicable"]


class FindingCard(BaseModel):
    """Formalized finding / observation card stored in vault/."""

    kind: str = "finding"
    id: str | None = None
    title: str | None = None
    asset: str | None = None
    target: str | None = None
    observation: str = ""
    evidence_status: EvidenceStatus | str = "Potential"
    status: str = "Potential"
    severity: str = "Medium"
    technique: str = "unknown"
    purple_pair: dict[str, Any] | None = None
    vault_ref: str | None = None
    adapter: str | None = None
    verb: str | None = None
    timestamp: str | None = None
    raw_excerpt: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    domain: str = "Infrastructure"
    access_posture: str = "Unauthenticated"
    prod_blocker: bool = False
    remediation: str | None = None
    priority: str = "P1"
    detection_name: str | None = None
    data_source: str | None = None
    logic: str | None = None
    control: str | None = None
    check_name: str | None = None
    round: str | None = None
    control_ids: list[str] = Field(default_factory=list)
    control_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """Deterministic tool result. Every adapter must return this shape."""

    status: Status
    summary: str
    next_actions: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    root_cause_hint: str | None = None
    retry: str | None = None
    stop_condition: str | None = None
    evidence_status: EvidenceStatus | str | None = None
    technique: str | None = None
    purple_pair: dict[str, Any] | None = None
    vault_ref: str | None = None
    adapter: str | None = None
    verb: str | None = None
    target: str | None = None


class Engagement(BaseModel):
    engagement_id: str
    authorized_by: str
    authorization_ref: str
    start: str  # YYYY-MM-DD
    end: str  # YYYY-MM-DD
    scope_cidrs: list[str] = Field(default_factory=list)
    scope_hosts: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    roe: list[str] = Field(default_factory=list)
    airgap: bool = True
    allow_live_tools: bool = False
    # Phase 5 privilege. Default false. Signed L3 may draft a local demo
    # artifact; payload execution stays off.
    allow_exploit_dev: bool = False
    validation_target: str | None = None
    # Lab snapshot the Phase 5 validator must restore to. Unused until wired.
    snapshot_ref: str | None = None
    # Where allowlisted CLIs run (SSH). Empty → local Mac PATH.
    exec_host: str | None = None
    # target | exec | both. If omitted, derived from exec_host vs validation_target.
    lab_role: str | None = None
    # Fusion VMX path for DHCP refresh. Gitignored engagement only.
    vmx_path: str | None = None
    # 0 = inventory/chat, 1 = supervised ReAct, 2 = recon-only, 3 = validate.
    # Target is L3; Phase 1 ships L1-capable loop with live still gated.
    autonomy_level: int = 0
    notes: str = ""


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProofOfExploitability(BaseModel):
    """Potential → Verified promotion schema. Runtime stays unwired.

    Words and vault paths only. `executed` is always false in this build.
    """

    finding_id: str
    issue_class: str
    target: str
    verb: str
    from_status: EvidenceStatus = "Potential"
    to_status: EvidenceStatus = "Verified"
    validator_evidence_path: str | None = None
    snapshot_ref: str | None = None
    restore_plan: str | None = None
    executed: bool = False
    phase5: str = "unwired"
    capability: bool = False


class PocPlan(BaseModel):
    """Human-review plan stored in the private vault; never runnable code."""

    technique: str
    endpoint: str | None = None
    steps: list[str] = Field(min_length=1)
    expected_result: str
    human_review_required: bool = True
    execution: Literal["manual-human-only"] = "manual-human-only"
    executed: bool = False
    capability: bool = False


class LedgerEntry(BaseModel):
    """One observation × control-ID evidence row. Offline only."""

    control_id: str
    status: LedgerStatus
    vault_ref: str | None = None
    hash: str
    theme: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    posture_only: bool = False
