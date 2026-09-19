"""Gated exploit-VALIDATION hypothesis card (no capability).

Phase 5 will run a KlinVM-bound validator behind allow_exploit_dev.
This module only checks that a card is complete and in-scope, then
always returns STOP phase5-unwired. It never emits a payload or PoC.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from aetherops.scope.gate import normalize_target, target_in_scope
from aetherops.scope.verbs import contains_payload_shape, is_permanent_deny
from aetherops.types import Engagement, Observation

CARD_FIELDS = (
    "issue_class",
    "target",
    "intent",
    "evidence_path",
    "snapshot_ref",
    "restore_plan",
    "evidence_capture",
)


class ValidationHypothesis(BaseModel):
    """Inputs the future validator needs. Words only — no exploit text."""

    issue_class: str
    target: str
    intent: str
    evidence_path: str
    snapshot_ref: str
    restore_plan: str
    evidence_capture: list[str] = Field(default_factory=list)
    allow_exploit_dev: bool = False
    validation_target: str | None = None

    @field_validator("issue_class", "target", "intent", "evidence_path", "snapshot_ref", "restore_plan")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = (value or "").strip()
        if not text:
            raise ValueError("field is empty")
        return text


def _refuse(field: str, hint: str) -> Observation:
    return Observation(
        status="error",
        summary=f"REFUSE {field}",
        root_cause_hint=hint,
        stop_condition="STOP phase5-unwired",
        data={"result": f"REFUSE {field}", "phase5": "unwired", "scope_refused": True},
        next_actions=["Do not invent an exploit path", "Point purple-feedback at the same class"],
    )


def _unsigned(engagement: Engagement) -> bool:
    return (
        not engagement.authorization_ref
        or engagement.authorized_by in {"", "engagement-owner", "REPLACE-WITH-SIGNER"}
    )


def assess_validation_hypothesis(
    card: dict[str, Any] | ValidationHypothesis,
    engagement: Engagement,
) -> Observation:
    """Gate a hypothesis card. CARD-READY still ends in STOP phase5-unwired."""
    if isinstance(card, ValidationHypothesis):
        raw = card.model_dump()
    else:
        raw = dict(card or {})

    for field in CARD_FIELDS:
        value = raw.get(field)
        if value is None or value == "" or value == []:
            return _refuse(field, f"Hypothesis card missing {field}.")

    try:
        parsed = ValidationHypothesis.model_validate(raw)
    except (TypeError, ValueError) as exc:
        return _refuse("card", f"Hypothesis card failed validation: {exc}")

    if _unsigned(engagement):
        return _refuse("engagement", "Example / unsigned engagement is not authorization.")
    if not engagement.allow_exploit_dev:
        return _refuse("allow_exploit_dev", "allow_exploit_dev is false.")
    if engagement.autonomy_level < 3:
        return _refuse("autonomy_level", "Validation requires autonomy_level >= 3.")

    expected = normalize_target(engagement.validation_target)
    got = normalize_target(parsed.target)
    if not expected:
        return _refuse("validation_target", "Engagement validation_target is empty.")
    if got != expected:
        return _refuse("target", "Named target is not the signed validation_target.")
    if not target_in_scope(got, engagement):
        return _refuse("target", "SCOPE DENIED: validation target is out of scope.")

    if not parsed.evidence_path.startswith("vault/"):
        return _refuse("evidence_path", "Evidence must be a local vault/ path.")
    if contains_payload_shape(parsed.intent) or contains_payload_shape(parsed.restore_plan):
        return _refuse("intent", "Intent/restore plan contains a payload shape.")
    if is_permanent_deny(parsed.intent) or is_permanent_deny(parsed.issue_class):
        return _refuse("intent", "Permanent-deny class (C2/exfil/worm/wiper) cannot be validated.")

    snapshot = (engagement.snapshot_ref or "").strip()
    if snapshot and parsed.snapshot_ref != snapshot:
        return _refuse("snapshot_ref", "Card snapshot_ref does not match the engagement snapshot.")

    return Observation(
        status="error",
        summary="CARD-READY + STOP phase5-unwired",
        root_cause_hint="Card is complete and in-scope; Phase 5 runtime is not implemented.",
        stop_condition="STOP phase5-unwired",
        data={
            "result": "CARD-READY + STOP phase5-unwired",
            "phase5": "unwired",
            "target": got,
            "issue_class": parsed.issue_class,
            "evidence_path": parsed.evidence_path,
            "snapshot_ref": parsed.snapshot_ref,
            "restore_plan": parsed.restore_plan,
            "evidence_capture": parsed.evidence_capture,
            "capability": False,
        },
        next_actions=[
            "Do not invent an exploit path",
            "Hand the same class to purple-feedback / detection-engineering",
        ],
    )


RECHECK_STEPS = ("snapshot", "restore", "evidence", "scope")


def recheck_validation_step(
    card: dict[str, Any] | ValidationHypothesis,
    engagement: Engagement,
    *,
    step: str,
    target: str | None = None,
    verb: str | None = None,
) -> Observation:
    """Re-check snapshot/restore/evidence/scope before a hypothetical validate step.

    Always ends STOP phase5-unwired. Never emits capability. A denied verb
    or target drift fails closed even when the card itself was CARD-READY.
    """
    base = assess_validation_hypothesis(card, engagement)
    if "CARD-READY" not in (base.summary or ""):
        return base

    name = (step or "").strip().lower()
    if name not in RECHECK_STEPS:
        return _refuse("step", f"Unknown validation recheck step: {step}")

    raw = card.model_dump() if isinstance(card, ValidationHypothesis) else dict(card or {})
    parsed = ValidationHypothesis.model_validate(raw)
    step_target = normalize_target(target or parsed.target)
    expected = normalize_target(engagement.validation_target)

    if verb and (is_permanent_deny(verb) or contains_payload_shape(verb)):
        return _refuse("verb", "Permanent-deny / payload verb cannot be a validation step.")
    if step_target != expected or not target_in_scope(step_target, engagement):
        return _refuse("target", "SCOPE DENIED: step target drifted from validation_target.")

    if name == "snapshot" and not parsed.snapshot_ref.strip():
        return _refuse("snapshot_ref", "Snapshot missing at recheck.")
    if name == "restore" and (
        not parsed.restore_plan.strip() or contains_payload_shape(parsed.restore_plan)
    ):
        return _refuse("restore_plan", "Restore plan missing or payload-shaped at recheck.")
    if name == "evidence":
        captures = [str(item).strip() for item in parsed.evidence_capture if str(item).strip()]
        if not captures or any(not item.startswith("vault/") for item in captures):
            return _refuse("evidence_capture", "Evidence capture must be non-empty vault/ paths.")

    data = dict(base.data or {})
    data.update(
        {
            "recheck_step": name,
            "recheck": "ok",
            "capability": False,
            "phase5": "unwired",
        }
    )
    return Observation(
        status="error",
        summary=f"RECHECK-OK {name} + STOP phase5-unwired",
        root_cause_hint="Step re-check passed; Phase 5 runtime is still not implemented.",
        stop_condition="STOP phase5-unwired",
        data=data,
        next_actions=[
            "Do not invent an exploit path",
            "Restore the lab snapshot after any future validate attempt",
        ],
    )


def bind_klinvm_validator(
    card: dict[str, Any] | ValidationHypothesis,
    engagement: Engagement,
    *,
    verb: str = "klinvm.bind",
    live: bool = False,
    airgap: bool = True,
    arguments: dict[str, Any] | None = None,
) -> Observation:
    """Phase 5 KlinVM bind seam. Always STOP phase5-unwired. Never executes.

    Routes through authorize() first. A CARD-READY hypothesis still cannot
    fire — this is the interface the future jail would call.
    """
    from aetherops.scope.exploitation import request_exploitation

    raw = card.model_dump() if isinstance(card, ValidationHypothesis) else dict(card or {})
    target = str(raw.get("target") or engagement.validation_target or "")
    gated = request_exploitation(
        tool=verb,
        target=target or None,
        engagement=engagement,
        airgap=airgap,
        live=live,
        arguments=arguments,
        issue_class=str(raw.get("issue_class") or ""),
    )
    # request_exploitation always refuses in this build. Surface the card
    # check too so missing snapshot/restore still names the field.
    card_obs = assess_validation_hypothesis(card, engagement)
    data = dict(gated.data or {})
    data.update(
        {
            "executed": False,
            "capability": False,
            "phase5": "unwired",
            "verb": verb,
            "card_summary": card_obs.summary,
            "klinvm_bound": False,
        }
    )
    return Observation(
        status="error",
        summary="KlinVM bind refused + STOP phase5-unwired",
        root_cause_hint=(
            gated.root_cause_hint
            or card_obs.root_cause_hint
            or "Phase 5 KlinVM validator is not implemented."
        ),
        stop_condition="STOP phase5-unwired",
        data=data,
        next_actions=[
            "Do not invent an exploit path",
            "Keep the hypothesis card in vault/ until Phase 5 is wired",
        ],
    )


def promote_potential_to_verified(
    card: dict[str, Any] | ValidationHypothesis,
    engagement: Engagement,
    *,
    verb: str = "validator.promote",
) -> Observation:
    """Potential → Verified promotion seam. Always refused in this build."""
    return bind_klinvm_validator(card, engagement, verb=verb)
