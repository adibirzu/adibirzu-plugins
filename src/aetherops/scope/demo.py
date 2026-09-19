"""Demonstration artifacts for signed L3 catalog verbs.

Words and vault paths only. Never executes a payload against a guest.
Never calls HexStrike exploit-generate. Local Qwythos first; connected
fallback is logged, waived, and sanitized.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from aetherops.airlock.egress import EgressDenied
from aetherops.airlock.vault import store
from aetherops.scope.verbs import contains_payload_shape, is_permanent_deny
from aetherops.types import ChatMessage, Engagement, Observation, PocPlan

DEMO_SYSTEM = (
    "You are AetherOps on an authorized air-gapped lab engagement. "
    "Write a detailed words-only PoC-PLAN for one finding class. "
    "Hard rules: words and vault path names only. Do not emit exploit code, "
    "payloads, shell one-liners, C2, reverse shells, implants, or weaponized steps. "
    "Do not invent live offensive commands. Use four labelled prose sections: "
    "Technique, Endpoint, Review steps, Expected result. Bind it only to the "
    "signed identity, make every step a human review or existing-evidence step, "
    "and state that execution is manual-human-only. If you cannot demonstrate "
    "without a payload, say so and stop."
)

LlmChat = Callable[[list[ChatMessage]], dict[str, Any]]

_CODE_SHAPES = ("```", "#!/", "<script", "import socket", "subprocess.", "os.system(")


def _llm_text(data: dict[str, Any]) -> str:
    message = data.get("message") if isinstance(data, dict) else None
    if isinstance(message, dict):
        return str(message.get("content") or "")
    return str(data.get("content") or "") if isinstance(data, dict) else ""


def _poc_plan(*, issue_class: str | None, target: str | None, body: str) -> PocPlan:
    """Build the persisted plan envelope independently of model formatting."""
    technique = issue_class or "unknown finding class"
    return PocPlan(
        technique=technique,
        endpoint=target,
        steps=[
            "Human reviewer verifies that the signed engagement, target, and finding class still match.",
            "Human reviewer inspects the existing allowlisted scanner and vault evidence for the stated technique.",
            "Human reviewer decides whether a separate manual validation is justified; this harness does not execute it.",
        ],
        expected_result=body[:4000],
    )


def draft_demo_artifact(
    *,
    tool: str,
    target: str | None,
    engagement: Engagement,
    vault_dir: Path,
    issue_class: str | None = None,
    finding: dict[str, Any] | None = None,
    llm_chat: LlmChat | None = None,
) -> Observation:
    """Call local Qwythos (or logged connected fallback) and store a vault demo."""
    finding_blob = dict(finding or {})
    user = (
        f"tool={tool}\n"
        f"target={target}\n"
        f"issue_class={issue_class or finding_blob.get('issue_class') or 'unknown'}\n"
        f"engagement_id={engagement.engagement_id}\n"
        f"snapshot_ref={engagement.snapshot_ref or ''}\n"
        f"finding={finding_blob}\n"
        "Write the demonstration artifact now."
    )
    messages = [
        ChatMessage(role="system", content=DEMO_SYSTEM),
        ChatMessage(role="user", content=user[:2000]),
    ]
    provider = "injected"
    fallback = False
    log = "llm_provider=injected fallback=false"
    try:
        if llm_chat is not None:
            data = llm_chat(messages)
        else:
            from aetherops.config import Settings
            from aetherops.llm.brain import Brain

            turn = Brain(Settings()).chat(
                messages,
                engagement=engagement,
                issue_class=issue_class or str(finding_blob.get("issue_class") or ""),
            )
            data = turn.payload
            provider = turn.provider
            fallback = turn.fallback
            log = turn.log
    except (EgressDenied, OSError, ValueError, TypeError, httpx.HTTPError) as exc:
        return Observation(
            status="error",
            summary=f"Demonstration brain failed: {exc}",
            stop_condition="Do not send an unsanitized prompt to a cloud API.",
            data={
                "executed": False,
                "capability": False,
                "phase5": "wired",
                "tool": tool,
                "llm_provider": provider,
                "llm_fallback": fallback,
            },
        )

    text = _llm_text(data if isinstance(data, dict) else {})
    if contains_payload_shape(text) or is_permanent_deny(text) or any(shape in text.lower() for shape in _CODE_SHAPES):
        return Observation(
            status="error",
            summary="Demonstration refused: model output had runnable-code, payload, or permanent-deny shape.",
            stop_condition="Do not store weaponized model output. Retry with words only.",
            data={
                "executed": False,
                "capability": False,
                "phase5": "wired",
                "tool": tool,
                "payload_refused": True,
                "llm_provider": provider,
                "llm_fallback": fallback,
            },
        )
    if not text.strip():
        return Observation(
            status="error",
            summary="Demonstration refused: empty model output.",
            stop_condition="Do not invent a demonstration artifact.",
            data={
                "executed": False,
                "capability": False,
                "phase5": "wired",
                "tool": tool,
                "llm_provider": provider,
                "llm_fallback": fallback,
            },
        )

    plan = _poc_plan(
        issue_class=issue_class or str(finding_blob.get("issue_class") or ""),
        target=target,
        body=text,
    )
    path = store(
        vault_dir,
        "demo-artifact",
        {
            "kind": "demo_artifact",
            "tool": tool,
            "target": target,
            "issue_class": issue_class or finding_blob.get("issue_class"),
            "engagement_id": engagement.engagement_id,
            "snapshot_ref": engagement.snapshot_ref,
            "body": text[:4000],
            "poc_plan": plan.model_dump(),
            "executed": False,
            "capability": False,
            "phase5": "wired",
            "llm_provider": provider,
            "llm_fallback": fallback,
            "llm_log": log,
        },
    )
    return Observation(
        status="success",
        summary=f"Demonstration artifact stored for {tool} on {target}.",
        artifacts=[str(path)],
        data={
            "executed": False,
            "capability": False,
            "phase5": "wired",
            "tool": tool,
            "target": target,
            "artifact_path": str(path),
            "in_catalog": True,
            "poc_plan": plan.model_dump(),
            "llm_provider": provider,
            "llm_fallback": fallback,
            "llm_log": log,
        },
        next_actions=["Human-review the words-only PoC plan", "Pair the finding with purple-feedback", "Do not execute a payload"],
    )
