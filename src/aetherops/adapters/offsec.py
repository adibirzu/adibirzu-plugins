"""Passive offsec-ai scanner adapter. Never instantiates *Attacker classes.

Judge/cloud keys are refused. Live HTTP uses EgressSession (loopback) or an
injected runner. Missing offsec-ai package → plan-or-STOP, not a fake finding.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from aetherops.airlock.egress import EgressDenied, EgressSession, assert_loopback_url
from aetherops.harness.observation import err, ok, warn
from aetherops.types import Engagement, Observation

OFFSEC_VERBS = (
    "health",
    "inventory",
    "port_scan",
    "cert_check",
    "l7_check",
    "headers",
    "owasp_scan",
    "ai_owasp_scan",
    "mcp_scan",
    "a2a_scan",
    "auth_scan",
    "postman_scan",
    "k8s_scan",
    "openclaw_scan",
)

_ATTACK_VERBS = frozenset(
    {
        "mcp_attack",
        "a2a_attack",
        "auth_attack",
        "postman_attack",
        "k8s_attack",
        "openclaw_attack",
        "llm_attack",
    }
)
_CLOUD_ENV = ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OFFSEC_LLM_BASE_URL")

OffsecRunner = Callable[[str, str | None, dict[str, Any] | None], Any]


def _cloud_judge_blocked() -> str | None:
    for name in _CLOUD_ENV:
        if os.environ.get(name):
            return name
    return None


def run_offsec_adapter(
    verb: str,
    *,
    engagement: Engagement,
    target: str | None = None,
    live: bool = False,
    arguments: dict[str, Any] | None = None,
    runner: OffsecRunner | None = None,
) -> Observation:
    action = (verb or "").strip().lower()
    if action in _ATTACK_VERBS or action.endswith("_attack"):
        return err(
            "Denied: offsec attacker verbs are not available.",
            stop_condition="Do not retry denied tools. Passive scanners only.",
            data={"executed": False, "verb": action, "scope_refused": True},
        )
    if action not in OFFSEC_VERBS:
        return err(
            "SCOPE DENIED: unknown offsec verb.",
            stop_condition="Use inventory or an allowlisted scanner verb.",
            data={"executed": False, "verb": action, "scope_refused": True},
        )
    if action in {"health", "inventory"}:
        return ok(
            "offsec-ai passive scanners (no attackers, no cloud judge).",
            data={"verbs": list(OFFSEC_VERBS), "executed": False, "attacks": False},
        )

    blocked = _cloud_judge_blocked()
    if blocked:
        return err(
            "SCOPE DENIED: cloud LLM judge env is set on the engage path.",
            root_cause_hint=f"{blocked} must be unset; loopback Qwythos only.",
            stop_condition="Do not send probes to a cloud judge.",
            data={"executed": False, "scope_refused": True, "env": blocked},
        )

    if arguments:
        url = str(arguments.get("judge_url") or arguments.get("base_url") or "")
        if url:
            try:
                assert_loopback_url(url)
            except EgressDenied:
                return err(
                    "SCOPE DENIED: offsec judge URL is not loopback.",
                    stop_condition="Do not send the prompt to a cloud API.",
                    data={"executed": False, "scope_refused": True},
                )

    if not live:
        return ok(
            f"offsec.{action} planned (passive, not executed).",
            data={"verb": action, "target": target, "executed": False},
            next_actions=["Live scan requires a signed engagement"],
        )

    if runner is not None:
        raw = runner(action, target, arguments)
        return ok(
            f"offsec.{action} mocked scan",
            data={"verb": action, "target": target, "executed": True, "raw": raw, "evidence_status": "Potential"},
        )

    # Live without a runner: refuse to invent. Do not import offsec_ai attackers.
    try:
        import offsec_ai  # noqa: F401
    except ImportError:
        return warn(
            "STOP live-unwired: offsec-ai package is not installed.",
            stop_condition="Do not invent scanner results when the tool is missing.",
            data={"executed": False, "verb": action, "target": target},
        )
    return warn(
        "STOP live-unwired: offsec live runner is not wired on this host.",
        stop_condition="Do not invent scanner results. Tests inject a runner; Lane 2 supplies one.",
        data={"executed": False, "verb": action, "target": target},
    )


def assert_loopback_judge_probe(url: str) -> None:
    """Used by tests to prove cloud judge URLs fail closed."""
    with EgressSession(timeout=1.0) as client:
        client.get(url)
