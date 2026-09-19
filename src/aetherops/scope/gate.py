from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from aetherops.i18n import t
from aetherops.scope.verbs import (
    arguments_have_payload_shape,
    exploit_arg_keys,
    extra_arg_keys,
    is_catalogued_demo_verb,
    is_exploit_dev,
    is_path_scoped_verb,
    is_permanent_deny,
    is_readonly_verb,
    is_workspace_scan_path,
)
from aetherops.types import Engagement, Observation


def load_engagement(path: Path) -> Engagement:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Engagement.model_validate(raw)


def load_engagement_or_deny(path: Path, lang: str = "en") -> tuple[Engagement | None, Observation | None]:
    """Fail closed when the engagement file is missing or unreadable."""
    try:
        return load_engagement(path), None
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        return None, Observation(
            status="error",
            summary=t(lang, "out_of_scope"),
            root_cause_hint=f"Engagement file unreadable: {exc}",
            stop_condition="SCOPE DENIED. Do not retry without a readable signed engagement.",
        )


def normalize_target(target: str | None) -> str | None:
    """Strip URL scheme/path and :port so scope checks see the host/IP."""
    if target is None:
        return None
    text = str(target).strip()
    if not text:
        return None
    if "://" in text or text.startswith("//"):
        parsed = urlparse(text if "://" in text else f"http:{text}")
        text = parsed.hostname or text
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    return text.strip() or None


def _in_scope(target: str, engagement: Engagement) -> bool:
    identity = normalize_target(target)
    if not identity:
        return False
    if identity in engagement.out_of_scope:
        return False
    lowered = identity.lower()
    if any(identity == item or lowered == item.lower() for item in engagement.out_of_scope):
        return False
    if any(identity == item or lowered == item.lower() for item in engagement.scope_hosts):
        return True
    try:
        addr = ip_address(identity)
    except ValueError:
        return False
    return any(addr in ip_network(cidr, strict=False) for cidr in engagement.scope_cidrs)


def target_in_scope(target: str | None, engagement: Engagement) -> bool:
    if not target:
        return False
    return _in_scope(target, engagement)


def _denied(lang: str, *, hint: str, stop: str, data: dict[str, Any] | None = None) -> Observation:
    return Observation(
        status="error",
        summary=t(lang, "denied_tool"),
        root_cause_hint=hint,
        stop_condition=stop,
        data=data or {},
    )


def _scope_denied(lang: str, target: str | None, hint: str) -> Observation:
    return Observation(
        status="error",
        summary=t(lang, "out_of_scope"),
        data={"target": target},
        root_cause_hint=hint,
        stop_condition="SCOPE DENIED. Do not retry out-of-scope targets.",
    )


def _scans_workspace_path(
    tool: str, verb: str, arguments: dict[str, Any] | None
) -> bool:
    """Estate MCP/skill scanners are scoped by a workspace path, not by a host."""
    if not is_path_scoped_verb(verb):
        return False
    adapter = (tool or "").split(".", 1)[0].strip().lower()
    if adapter != "estate":
        return False
    return is_workspace_scan_path(str((arguments or {}).get("path") or ""))


def authorize(
    *,
    tool: str,
    target: str | None,
    engagement: Engagement,
    airgap: bool,
    internet_required: bool,
    live: bool,
    lang: str = "en",
    verb: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> Observation | None:
    """Return an error Observation if the action is forbidden, else None.

    Fail-closed: extra/payload arguments, missing live targets, unsigned
    windows, and exploit-dev without L3 + matching validation_target all
    deny. Catalogued verbs on a signed L3 file may draft a local Qwythos
    demonstration artifact; payload execution and HexStrike exploit verbs stay off.
    """
    resolved_verb = (verb or "").strip().lower()
    if "." in (tool or "") and not resolved_verb:
        resolved_verb = tool.split(".", 1)[1].strip().lower()

    if is_permanent_deny(tool) or (resolved_verb and is_permanent_deny(resolved_verb)):
        return _denied(
            lang,
            hint="Permanent deny (C2/exfil/worm/ransomware/wiper/beacon).",
            stop="Do not retry denied tools. Use allowlisted wrappers only.",
            data={"tool": tool, "verb": resolved_verb},
        )

    extra = extra_arg_keys(arguments)
    if extra:
        return _denied(
            lang,
            hint=f"Unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop="Do not retry with extra arguments. Advertised keys only.",
            data={"extra_keys": list(extra)},
        )
    smuggled = exploit_arg_keys(arguments)
    if smuggled:
        return _denied(
            lang,
            hint=f"Payload-shaped argument keys: {', '.join(smuggled)}",
            stop="Do not retry exploit/payload arguments.",
            data={"exploit_keys": list(smuggled)},
        )
    if arguments_have_payload_shape(arguments):
        return _denied(
            lang,
            hint="Payload shape in tool arguments.",
            stop="Do not retry payload-shaped arguments.",
        )

    exploit_dev = is_exploit_dev(tool) or (resolved_verb and is_exploit_dev(resolved_verb))
    signer = engagement.authorized_by.strip().lower()
    authorization_ref = engagement.authorization_ref.strip()
    placeholder_signer = not signer or signer in {"engagement-owner", "replace-with-signer"}
    if live and (not authorization_ref or placeholder_signer):
        return Observation(
            status="error",
            summary=t(lang, "unauthorized"),
            root_cause_hint="Engagement is missing a non-placeholder signer or authorization reference.",
            stop_condition="Replace configs/engagement.example.yaml with a real ROE.",
        )
    if exploit_dev:
        if not engagement.allow_exploit_dev:
            return Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="allow_exploit_dev is false (unsigned or Phase 1 default).",
                stop_condition="Do not retry exploit-dev verbs. They require a signed flag and Phase 5.",
            )
        if engagement.autonomy_level < 3:
            return Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="exploit-dev requires autonomy_level >= 3 (L3 validate).",
                stop_condition="Do not self-escalate autonomy. Wait for a signed L3 engagement.",
            )
        if not authorization_ref or placeholder_signer:
            return Observation(
                status="error",
                summary=t(lang, "unauthorized"),
                root_cause_hint="Exploit-development requires a non-placeholder signed ROE.",
                stop_condition="Do not retry exploit-dev without a signed L3 engagement.",
            )
        today = datetime.now(UTC).date().isoformat()
        if not (engagement.start <= today <= engagement.end):
            return Observation(
                status="error",
                summary=t(lang, "unauthorized"),
                root_cause_hint="Engagement window is not active.",
                stop_condition="Do not operate exploit-dev outside start/end dates.",
            )
        expected = normalize_target(engagement.validation_target)
        got = normalize_target(target)
        if not expected:
            return Observation(
                status="error",
                summary=t(lang, "denied_tool"),
                root_cause_hint="validation_target is empty; exploit-dev has nowhere to bind.",
                stop_condition="Do not retry exploit-dev without a signed validation_target.",
            )
        if not got:
            return _scope_denied(
                lang,
                target,
                "exploit-dev requires the signed validation_target as the tool target.",
            )
        if got != expected:
            return _scope_denied(
                lang,
                got,
                "validation_target mismatch — validator binds to the signed lab identity only.",
            )
        if not _in_scope(got, engagement):
            return _scope_denied(lang, got, "validation_target is not in the signed scope.")
        catalogued = is_catalogued_demo_verb(tool, resolved_verb)
        if not catalogued:
            return Observation(
                status="error",
                summary=t(lang, "exploit_dev_unwired"),
                root_cause_hint="KlinVM jail and non-catalog exploit-dev verbs stay unwired even on a signed L3 file.",
                stop_condition="STOP phase5-unwired. Do not invent an exploit path.",
            )
        return None

    if live and not engagement.allow_live_tools:
        return Observation(
            status="error",
            summary=t(lang, "unauthorized"),
            root_cause_hint="allow_live_tools is false on the engagement file.",
            retry="Set allow_live_tools after written authorization, then retry.",
            stop_condition="Do not run live adapters without a signed engagement.",
        )
    if live and engagement.autonomy_level < 1:
        return Observation(
            status="error",
            summary=t(lang, "unauthorized"),
            root_cause_hint="Live adapters require autonomy_level >= 1.",
            stop_condition="Do not self-escalate autonomy. Inventory only at L0.",
        )
    today = datetime.now(UTC).date().isoformat()
    if not (engagement.start <= today <= engagement.end):
        return Observation(
            status="error",
            summary=t(lang, "unauthorized"),
            root_cause_hint="Engagement window is not active.",
            stop_condition="Do not operate outside start/end dates.",
        )
    if airgap and internet_required:
        return Observation(
            status="error",
            summary=t(lang, "airgap_block"),
            stop_condition="Use a local adapter or disable air-gap only on an isolated jump host.",
        )
    identity = normalize_target(target)
    if identity and not _in_scope(identity, engagement):
        return _scope_denied(lang, identity, "Target is outside scope_hosts/scope_cidrs or listed out_of_scope.")
    if (
        live
        and not is_readonly_verb(resolved_verb)
        and not identity
        and not _scans_workspace_path(tool, resolved_verb, arguments)
    ):
        return _scope_denied(
            lang,
            target,
            "Live non-inventory verbs require an explicit in-scope target.",
        )
    return None
