"""Loopback-only finding triage. Rule-based default; Qwythos optional.

Never imports openai/anthropic/google SDKs. HTTP only via EgressSession.
"""

from __future__ import annotations

import json
from typing import Any

from aetherops.airlock.egress import EgressDenied
from aetherops.llm.client import QwythosClient
from aetherops.types import ChatMessage, Observation


def rule_triage(finding: dict[str, Any] | None) -> dict[str, Any]:
    payload = finding or {}
    severity = str(payload.get("severity") or "medium").strip().lower()
    return {
        "vulnerable": severity in {"critical", "high", "medium"},
        "confidence": 0.4 if severity in {"low", "info", "informational"} else 0.6,
        "reason": "rule-based triage; no cloud judge",
        "provider": "rules",
    }


def judge_finding(
    finding: dict[str, Any] | None,
    *,
    client: QwythosClient | None = None,
    use_model: bool = False,
) -> Observation:
    """Triage one finding. Default is rules. Model path is loopback-only."""
    if not use_model or client is None:
        verdict = rule_triage(finding)
        return Observation(
            status="success",
            summary="Rule-based triage (loopback judge idle).",
            data={**verdict, "executed": False},
        )
    try:
        data = client.chat(
            [
                ChatMessage(
                    role="system",
                    content="Reply ONLY with JSON {vulnerable: bool, confidence: number, reason: string}.",
                ),
                ChatMessage(
                    role="user",
                    content=json.dumps(finding or {}, ensure_ascii=False)[:1500],
                ),
            ]
        )
    except (EgressDenied, OSError, ValueError, TypeError) as exc:
        return Observation(
            status="error",
            summary=f"Loopback judge failed: {exc}",
            stop_condition="Do not send the prompt to a cloud API.",
            data={"executed": False, "scope_refused": True},
        )
    text = ((data.get("message") or {}).get("content")) or ""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = rule_triage(finding)
        parsed["reason"] = "model reply was not JSON; fell back to rules"
    parsed["provider"] = "qwythos-loopback"
    return Observation(status="success", summary="Loopback Qwythos triage.", data={**parsed, "executed": True})
