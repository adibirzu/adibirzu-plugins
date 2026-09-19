"""Assessment-strategy S0–S8 as data, plus a pure next-stage function.

`(engagement, inventory, vault_index) -> next_stage | STOP`

Readonly. Never emits a permanent-deny or gated offensive-dev verb, never
raises autonomy_level, never invents targets, and never marks an attack path
as executed. A missing adapter is STOP, not a substitute verb.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from aetherops.scope.gate import target_in_scope
from aetherops.scope.verbs import is_exploit_dev, is_permanent_deny
from aetherops.types import Engagement, Observation

# In-tree pipelines are always available as code (not optional CLIs).
IN_TREE_ADAPTERS = frozenset(
    {"plan", "pack", "estate", "mcp", "offsec", "completeness", "remote_exec", "whw"}
)

# Verbs that imply a live assessment step. Unsigned / L0 / expired fixtures
# must not see these as the current allowlist.
LIVE_ASSESSMENT_VERBS = frozenset(
    {
        "nmap_scan",
        "nuclei_scan",
        "trivy_scan",
        "checkov_iac_scan",
        "prowler_scan",
        "web",
        "infra",
        "k8s",
        "estate",
        "ai-estate",
        "assess",
        "scan",
        "robustness",
        "eval",
        "injection",
        "workflow_scan",
    }
)

LIVE_ASSESSMENT_TOOLS = frozenset({"estate.mcp_scan", "estate.skill_scan"})

UNSIGNED_SIGNERS = frozenset({"", "engagement-owner", "REPLACE-WITH-SIGNER"})


@dataclass(frozen=True)
class Stage:
    id: str
    name: str
    adapter: str | None
    verb: str | None
    live: bool = False
    internet_required: bool = False
    pass_through: bool = False


# authorize → plan → recon → analyse → hypothesize → domain packs (S5b) →
# coverage → purple → report. Phase-5 / deny verbs are intentionally absent.
STAGES: tuple[Stage, ...] = (
    Stage("S0", "authorize", adapter="hexstrike", verb="health", live=False),
    Stage("plan", "plan", adapter="hexstrike", verb="inventory", live=False),
    Stage("S1", "recon", adapter="hexstrike", verb="nmap_scan", live=True),
    Stage("S2", "analyse", adapter="hexstrike", verb="inventory", live=False),
    Stage("hyp", "hypothesize", adapter=None, verb=None, pass_through=True),
    Stage("S3", "assess-infra", adapter="pack", verb="infra", live=True),
    Stage("S4", "assess-web", adapter="pack", verb="web", live=True),
    Stage("S5", "assess-k8s", adapter="pack", verb="k8s", live=True),
    Stage("S5b", "assess-ai-estate", adapter="pack", verb="estate", live=True),
    Stage("S6", "coverage", adapter=None, verb=None),
    Stage("S7", "purple", adapter=None, verb=None),
    Stage("S8", "report", adapter=None, verb=None),
)


def window_active(engagement: Engagement, today: str | None = None) -> bool:
    # Local calendar date — must match scope.gate.authorize window check.
    day = today or date.today().isoformat()  # noqa: DTZ011
    return bool(engagement.start and engagement.end and engagement.start <= day <= engagement.end)


def is_signed(engagement: Engagement) -> bool:
    return bool(engagement.authorization_ref) and engagement.authorized_by not in UNSIGNED_SIGNERS


def can_live(engagement: Engagement, today: str | None = None) -> bool:
    return (
        window_active(engagement, today=today)
        and is_signed(engagement)
        and bool(engagement.allow_live_tools)
        and int(engagement.autonomy_level or 0) >= 1
    )


def _airgap(engagement: Engagement) -> bool:
    return bool(getattr(engagement, "airgap", True))


def signed_target(engagement: Engagement) -> str | None:
    """First already-in-scope host. Never invents an identity."""
    for host in engagement.scope_hosts or []:
        text = str(host).strip()
        if text and target_in_scope(text, engagement):
            return text
    return None


def _inventory_rows(inventory: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not inventory:
        return []
    rows = inventory.get("adapters")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict) and row.get("name")]
    return []


def _row_for(name: str, inventory: dict[str, Any] | None) -> dict[str, Any] | None:
    wanted = (name or "").strip().lower()
    for row in _inventory_rows(inventory):
        if str(row.get("name") or "").strip().lower() == wanted:
            return row
    return None


def adapter_available(name: str, inventory: dict[str, Any] | None) -> bool:
    row = _row_for(name, inventory)
    if row is None:
        return False
    if name in IN_TREE_ADAPTERS:
        return True
    return bool(row.get("present"))


def current_allowlist(
    engagement: Engagement,
    inventory: dict[str, Any] | None,
    *,
    today: str | None = None,
) -> set[str]:
    """Catalogued adapter.verb pairs that are legal for this engagement, plus STOP."""
    allowed: set[str] = {"STOP"}
    live_ok = can_live(engagement, today=today)
    for row in _inventory_rows(inventory):
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        verbs = list(row.get("allow") or ())
        if not verbs:
            verbs = ["health", "inventory"]
        for verb in verbs:
            action = str(verb or "").strip()
            if not action:
                continue
            tool = f"{name}.{action}"
            if (
                is_permanent_deny(tool)
                or is_permanent_deny(action)
                or is_exploit_dev(tool)
                or is_exploit_dev(action)
            ):
                continue
            if (not live_ok) and (
                action in LIVE_ASSESSMENT_VERBS or tool in LIVE_ASSESSMENT_TOOLS
            ):
                continue
            allowed.add(tool)
    return allowed


def _completed_ids(vault_index: dict[str, Any] | None) -> set[str]:
    idx = vault_index or {}
    raw = idx.get("completed_stages") or []
    done: set[str] = set()
    alias = {stage.name: stage.id for stage in STAGES}
    alias.update({stage.id: stage.id for stage in STAGES})
    for item in raw:
        key = str(item or "").strip()
        if key in alias:
            done.add(alias[key])
        elif key:
            done.add(key)

    for finding in idx.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        adapter = str(finding.get("adapter") or "").strip().lower()
        verb = str(finding.get("verb") or "").strip().lower()
        if adapter == "hexstrike" and verb == "health":
            done.add("S0")
        elif adapter == "hexstrike" and verb == "inventory":
            done.add("plan")
        elif adapter == "hexstrike" and verb == "nmap_scan":
            done.add("S1")
        elif adapter == "pack" and verb == "infra":
            done.add("S3")
        elif adapter == "pack" and verb == "web":
            done.add("S4")
        elif adapter == "pack" and verb == "k8s":
            done.add("S5")
        elif adapter == "estate" or (adapter == "pack" and verb in {"estate", "ai-estate"}):
            done.add("S5b")

    if idx.get("coverage_dry"):
        done.add("S6")
    if int(idx.get("purple_pair_count") or 0) > 0 or idx.get("purple_pairs"):
        done.add("S7")
    return done


def _analysis_hops(engagement: Engagement) -> list[dict[str, Any]]:
    """In-scope analysis-only edges. Empty when a second host is not already signed."""
    hosts: list[str] = []
    for host in engagement.scope_hosts or []:
        text = str(host).strip()
        if text and target_in_scope(text, engagement) and text not in hosts:
            hosts.append(text)
    if len(hosts) < 2:
        return []
    return [
        {
            "from": hosts[0],
            "to": hosts[1],
            "technique": "T1046",
            "coverage": "planned",
        }
    ]


def _attack_path_block(engagement: Engagement) -> dict[str, Any]:
    return {"executed": False, "hops": _analysis_hops(engagement)}


def _base_data(
    *,
    engagement: Engagement,
    stage: Stage | None,
    nxt: str,
    target: str | None = None,
    attack_path: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "next": nxt,
        "stage": stage.id if stage else "S8",
        "stage_name": stage.name if stage else "report",
        "adapter": stage.adapter if stage else None,
        "verb": stage.verb if stage else None,
        "live": bool(stage.live) if stage and nxt != "STOP" else False,
        "target": target,
        "executed": False,
        "attack_path": attack_path or _attack_path_block(engagement),
        "autonomy_level": int(engagement.autonomy_level or 0),
        "readonly": True,
    }


def _stop(
    engagement: Engagement,
    summary: str,
    *,
    stage: Stage | None,
    hint: str | None = None,
    attack_path: dict[str, Any] | None = None,
) -> Observation:
    data = _base_data(
        engagement=engagement,
        stage=stage,
        nxt="STOP",
        attack_path=attack_path,
    )
    return Observation(
        status="warning",
        summary=summary,
        root_cause_hint=hint,
        stop_condition="STOP. Do not invent a substitute verb or raise autonomy.",
        data=data,
        next_actions=["Stay inside the signed lab", "Do not retry around the gate"],
    )


def _suggest(
    engagement: Engagement,
    stage: Stage,
    *,
    target: str | None,
    attack_path: dict[str, Any],
) -> Observation:
    tool = f"{stage.adapter}.{stage.verb}"
    data = _base_data(
        engagement=engagement,
        stage=stage,
        nxt=tool,
        target=target,
        attack_path=attack_path,
    )
    return Observation(
        status="success",
        summary=f"Next assessment stage {stage.id} ({stage.name}): {tool}.",
        data=data,
        next_actions=[
            f"Call run_adapter name={stage.adapter} verb={stage.verb}",
            "authorize_step still wins if the model asks for something else",
        ],
    )


_HTTP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 3000, 8888})
_K8S_PORTS = frozenset({6443, 10250, 2379, 10255, 10257, 10259})


def _index_ports(vault_index: dict[str, Any] | None) -> set[int]:
    ports: set[int] = set()
    for item in (vault_index or {}).get("ports") or []:
        try:
            ports.add(int(item))
        except (TypeError, ValueError):
            continue
    for finding in (vault_index or {}).get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for port in finding.get("ports") or []:
            try:
                ports.add(int(port))
            except (TypeError, ValueError):
                continue
    return ports


def _na_stage_ids(vault_index: dict[str, Any] | None) -> set[str]:
    """Skip domain packs that the recon port map shows are not present."""
    ports = _index_ports(vault_index)
    if not ports:
        return set()
    na: set[str] = set()
    if not (ports & _HTTP_PORTS):
        na.add("S4")
    if not (ports & _K8S_PORTS):
        na.add("S5")
    return na


def next_stage(
    engagement: Engagement,
    inventory: dict[str, Any] | None,
    vault_index: dict[str, Any] | None,
    *,
    today: str | None = None,
) -> Observation:
    """Pure planner. Does not call adapters, the gate, or the network."""
    autonomy = int(engagement.autonomy_level or 0)
    attack_path = _attack_path_block(engagement)

    if not window_active(engagement, today=today):
        obs = _stop(
            engagement,
            "STOP: engagement window is not active.",
            stage=STAGES[0],
            hint="Do not operate outside start/end dates.",
            attack_path=attack_path,
        )
        obs.data["autonomy_level"] = autonomy
        return obs

    done = _completed_ids(vault_index)
    done.update(_na_stage_ids(vault_index))
    current: Stage | None = None
    for stage in STAGES:
        if stage.id in done:
            continue
        current = stage
        if stage.pass_through:
            continue
        if not stage.adapter or not stage.verb:
            return _stop(
                engagement,
                f"STOP: stage {stage.id} ({stage.name}) has no installed adapter.",
                stage=stage,
                hint="Missing adapter → STOP, not a substitute verb.",
                attack_path=attack_path,
            )
        tool = f"{stage.adapter}.{stage.verb}"
        if (
            is_permanent_deny(tool)
            or is_permanent_deny(stage.verb)
            or is_exploit_dev(tool)
            or is_exploit_dev(stage.verb)
        ):
            return _stop(
                engagement,
                "STOP: stage verb is refused.",
                stage=stage,
                hint="Planner will not emit a refused verb.",
                attack_path=attack_path,
            )
        if not adapter_available(stage.adapter, inventory):
            return _stop(
                engagement,
                f"STOP: adapter {stage.adapter} is missing.",
                stage=stage,
                hint="Missing adapter → STOP, not a substitute verb.",
                attack_path=attack_path,
            )
        if stage.internet_required and _airgap(engagement):
            return _stop(
                engagement,
                "STOP: stage requires network under air-gap.",
                stage=stage,
                attack_path=attack_path,
            )
        if stage.live and not can_live(engagement, today=today):
            return _stop(
                engagement,
                "STOP: live assessment stage is not authorized on this engagement.",
                stage=stage,
                hint="Do not self-escalate autonomy or invent a live verb.",
                attack_path=attack_path,
            )
        target = None
        if stage.live:
            target = signed_target(engagement)
            if not target:
                return _stop(
                    engagement,
                    "STOP: live stage has no in-scope host on the engagement.",
                    stage=stage,
                    hint="Planner does not invent targets.",
                    attack_path=attack_path,
                )
        return _suggest(engagement, stage, target=target, attack_path=attack_path)

    return _stop(
        engagement,
        "STOP: assessment stages are complete; write the local report.",
        stage=current or STAGES[-1],
        attack_path=attack_path,
    )
