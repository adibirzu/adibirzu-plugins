"""Per-step fail-closed gate for the autonomous ReAct loop.

Every model tool call is authorized here *before* AdapterRegistry.run.
Unknown adapter names, empty verbs, extra arguments, and load failures
deny. The loop must stop; it must not ask the model to try another path.
"""

from __future__ import annotations

from typing import Any

from aetherops.i18n import t
from aetherops.scope.gate import authorize
from aetherops.scope.verbs import is_exploit_dev, is_permanent_deny
from aetherops.types import Engagement, Observation, ToolCall


def _stop(obs: Observation) -> Observation:
    data = dict(obs.data or {})
    data["scope_refused"] = True
    return obs.model_copy(update={"data": data})


def authorize_step(
    *,
    name: str,
    verb: str,
    target: str | None,
    live: bool,
    engagement: Engagement,
    airgap: bool,
    internet_required: bool = False,
    arguments: dict[str, Any] | None = None,
    lang: str = "en",
) -> Observation | None:
    """Return an error Observation if this step is forbidden, else None."""
    adapter = (name or "").strip()
    action = (verb or "").strip()
    if not adapter:
        return _stop(
            Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="Empty adapter name.",
                stop_condition="SCOPE DENIED. Do not retry unnamed tools.",
            )
        )
    if not action:
        return _stop(
            Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="Empty verb.",
                stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
            )
        )
    tool = f"{adapter}.{action}"
    if is_permanent_deny(adapter) or is_permanent_deny(action) or is_permanent_deny(tool):
        return _stop(
            Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="Permanent deny on adapter or verb.",
                stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
                data={"tool": tool},
            )
        )
    if is_exploit_dev(adapter) or is_exploit_dev(action) or is_exploit_dev(tool):
        blocked = authorize(
            tool=tool,
            verb=action,
            target=target,
            engagement=engagement,
            airgap=airgap,
            internet_required=internet_required,
            live=live,
            lang=lang,
            arguments=arguments,
        )
        return _stop(blocked) if blocked else None
    blocked = authorize(
        tool=tool,
        verb=action,
        target=target,
        engagement=engagement,
        airgap=airgap,
        internet_required=internet_required,
        live=live,
        lang=lang,
        arguments=arguments,
    )
    return _stop(blocked) if blocked else None


def authorize_tool_call(
    tc: ToolCall,
    *,
    name: str,
    verb: str,
    target: str | None,
    live: bool,
    engagement: Engagement,
    airgap: bool,
    lang: str = "en",
) -> Observation | None:
    return authorize_step(
        name=name,
        verb=verb,
        target=target,
        live=live,
        engagement=engagement,
        airgap=airgap,
        arguments=tc.arguments,
        lang=lang,
    )


def should_halt(obs: Observation) -> bool:
    """Fail closed on any gate refusal, not only explicit SCOPE DENIED."""
    if obs.status == "error":
        return True
    if (obs.data or {}).get("scope_refused"):
        return True
    blob = f"{obs.stop_condition or ''} {obs.summary or ''} {obs.root_cause_hint or ''}".upper()
    return any(
        token in blob
        for token in (
            "SCOPE DENIED",
            "DENIED",
            "PHASE 5",
            "EXPLOIT-DEV",
            "EXPLOIT DEV",
        )
    )
