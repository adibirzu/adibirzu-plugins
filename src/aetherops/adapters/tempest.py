"""T3MP3ST planning-only adapter (Phase 7 / PRD-6).

Adjacent-tree presence probe plus inventory / mission-plan verbs.
This module never imports, vendors, copies, or reads the adjacent AGPL
tree — the planning surface is a conceptual interface only. Missing tree
→ present: false + STOP, same as a timed-out MCP server. Denied
archetype names stay invisible even when a mock advertises them.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from aetherops.harness.observation import err, ok, warn
from aetherops.mcp.router import McpRouter, filter_advertised_tools
from aetherops.scope.gate import authorize
from aetherops.scope.verbs import (
    DENY_SUBSTRINGS,
    extra_arg_keys,
    is_exploit_dev,
    is_permanent_deny,
    is_readonly_verb,
)
from aetherops.types import Engagement, Observation

# Conceptual planning interface. Not imported from the adjacent tree.
ALLOWLISTED_VERBS = frozenset({"health", "inventory", "mission_plan", "mission-plan"})
PLANNING_INTERFACE: tuple[str, ...] = ("health", "inventory", "mission_plan")

# Adjacent-harness archetype names that must never surface.
DENIED_ARCHETYPES = frozenset(
    {
        "exfiltrator",
        "ghost",
        "coordinator",
        "exploiter",
    }
)


def adjacent_tree_present(path: Path | None) -> bool:
    """True only when a configured local path exists. No remote probe."""
    if path is None:
        return False
    text = str(path).strip()
    if not text:
        return False
    return Path(path).exists()


def normalize_tempest_verb(verb: str) -> str:
    return (verb or "").strip().lower().replace("-", "_")


def is_denied_archetype(name: str) -> bool:
    blob = (name or "").strip().lower().replace("-", "_")
    if not blob:
        return False
    stem = blob.split(".", 1)[-1]
    return any(token == stem or token in blob for token in DENIED_ARCHETYPES)


def filter_tempest_tools(
    advertised: Iterable[str | dict[str, Any]],
    allowlist: Iterable[str] | None = None,
    deny_patterns: Iterable[str] | None = None,
) -> list[str]:
    """Router intersection: advertised ∩ allowlisted ∩ not-denied."""
    allow = list(allowlist) if allowlist is not None else list(PLANNING_INTERFACE)
    extra_deny = tuple(deny_patterns or ()) + tuple(DENIED_ARCHETYPES)
    filtered = filter_advertised_tools(
        advertised,
        allowlist=allow,
        adapter_name="tempest",
        deny_patterns=extra_deny,
    )
    return [name for name in filtered if not is_denied_archetype(name)]


def _missing_tree() -> Observation:
    return warn(
        "T3MP3ST tree not configured or not detectable.",
        root_cause_hint="Set AETHEROPS_TEMPEST_PATH to the adjacent local tree, or stay inventory-only.",
        retry="Configure the local path, then retry inventory.",
        stop_condition="STOP. Missing adjacent tree. Do not fall back to a remote host.",
        data={
            "adapter": "tempest",
            "present": False,
            "executed": False,
            "egress": False,
            "tools": [],
        },
    )


def _refused(summary: str, *, verb: str, hint: str | None = None) -> Observation:
    return err(
        summary,
        root_cause_hint=hint,
        stop_condition="Do not retry denied tools. Use allowlisted planning verbs only.",
        data={
            "adapter": "tempest",
            "verb": verb,
            "scope_refused": True,
            "executed": False,
            "egress": False,
        },
    )


def _signed_scope(engagement: Engagement) -> dict[str, Any]:
    """Signed engagement identities only. Never a private-range default."""
    return {
        "hosts": list(engagement.scope_hosts or []),
        "cidrs": list(engagement.scope_cidrs or []),
        "out_of_scope": list(engagement.out_of_scope or []),
    }


def _plan_steps(
    engagement: Engagement,
    *,
    target: str | None,
    tools: list[str],
) -> list[dict[str, Any]]:
    scope_target = target or (list(engagement.scope_hosts or [])[:1] or [None])[0]
    return [
        {
            "step": "inventory",
            "adapter": "tempest",
            "verb": "inventory",
            "executed": False,
        },
        {
            "step": "mission-plan",
            "adapter": "tempest",
            "verb": "mission_plan",
            "target": scope_target,
            "tools": list(tools),
            "executed": False,
        },
    ]


def run_tempest_adapter(
    verb: str = "inventory",
    *,
    engagement: Engagement,
    target: str | None = None,
    live: bool = False,
    airgap: bool = True,
    arguments: dict[str, Any] | None = None,
    tempest_path: Path | None = None,
    advertised: Iterable[str | dict[str, Any]] | None = None,
    allowlist: Iterable[str] | None = None,
    deny_patterns: Iterable[str] | None = None,
    router: McpRouter | None = None,
) -> Observation:
    """Authorize and describe one planning verb. Never executes, never imports AGPL."""
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            "Denied: unexpected tool arguments (fail closed).",
            root_cause_hint=f"Unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments. Advertised keys only.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )

    action = (verb or "inventory").strip().lower()
    normalized = normalize_tempest_verb(action)
    tool = f"tempest.{normalized}"

    if (
        is_permanent_deny(tool)
        or is_permanent_deny(action)
        or is_denied_archetype(action)
        or is_denied_archetype(tool)
        or any(tok in tool for tok in DENY_SUBSTRINGS)
    ):
        return _refused(
            "Denied: planning adapter does not expose that verb.",
            verb=action,
            hint="Denied archetype and refuse-listed verbs stay invisible.",
        )
    if is_exploit_dev(tool) or is_exploit_dev(action):
        return _refused(
            "Denied: gated offensive-dev verbs are not available.",
            verb=action,
            hint="Planning verbs only. Offensive-dev stays refused.",
        )
    if normalized not in {normalize_tempest_verb(item) for item in ALLOWLISTED_VERBS}:
        return _refused(
            "Denied: verb is not on the T3MP3ST planning allowlist.",
            verb=action,
            hint="Use health, inventory, or mission_plan only.",
        )

    blocked = authorize(
        tool=tool,
        verb=normalized,
        target=target,
        engagement=engagement,
        airgap=airgap,
        internet_required=False,
        live=live,
        arguments=arguments,
    )
    if blocked:
        data = dict(blocked.data or {})
        data.update(
            {
                "adapter": "tempest",
                "verb": normalized,
                "scope_refused": True,
                "executed": False,
                "egress": False,
            }
        )
        return blocked.model_copy(update={"data": data})

    if advertised is None and router is not None:
        inv = router.inventory_tempest(
            allowlist=allowlist or PLANNING_INTERFACE,
            deny_patterns=deny_patterns,
        )
        if not (inv.data or {}).get("present"):
            return inv
        tools = [str(item) for item in (inv.data or {}).get("tools") or []]
        advertised_count = int((inv.data or {}).get("advertised_count") or len(tools))
        return _planning_observation(
            verb=normalized,
            engagement=engagement,
            target=target,
            tools=tools,
            advertised_count=advertised_count,
        )

    if not adjacent_tree_present(tempest_path):
        return _missing_tree()

    raw_advertised = list(advertised) if advertised is not None else list(PLANNING_INTERFACE)
    tools = filter_tempest_tools(raw_advertised, allowlist=allowlist, deny_patterns=deny_patterns)
    return _planning_observation(
        verb=normalized,
        engagement=engagement,
        target=target,
        tools=tools,
        advertised_count=len(raw_advertised),
    )


def _planning_observation(
    *,
    verb: str,
    engagement: Engagement,
    target: str | None,
    tools: list[str],
    advertised_count: int,
) -> Observation:
    scope = _signed_scope(engagement)
    data: dict[str, Any] = {
        "adapter": "tempest",
        "verb": verb,
        "present": True,
        "executed": False,
        "egress": False,
        "readonly": is_readonly_verb(verb) or verb in {"mission_plan", "health", "inventory"},
        "allowlisted": True,
        "tools": tools,
        "advertised_count": advertised_count,
        "filtered_count": len(tools),
        "denied_count": max(advertised_count - len(tools), 0),
        "scope": scope,
        "target": target,
        "attack_path": {"executed": False, "hops": []},
        "live": False,
    }
    if verb == "mission_plan":
        data["plan"] = _plan_steps(engagement, target=target, tools=tools)
        return ok(
            "T3MP3ST mission plan ready (planning only, not executed).",
            data=data,
            next_actions=[
                "Stay inside the signed engagement scope",
                "Do not dispatch the adjacent tree",
            ],
        )
    return ok(
        f"T3MP3ST planning inventory: {len(tools)} verb(s) available.",
        data=data,
        next_actions=["Call tempest.mission_plan against a signed in-scope identity"],
    )
