"""Damn Vulnerable LLM Agent lab-target fixture (PRD-MS-4).

Path probe like T3MP3ST. Live attack against the fixture only on a
captain-signed L3 engagement with allow_exploit_dev and a matching
validation_target. Default probes are already-local promptmap/garak —
never PAIR. Engage-path HTTP stays loopback /v1.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from typing import Any

from aetherops.adapters.eval_oss import (
    DEFAULT_EVAL_TARGET,
    EvalInvocation,
    EvalRunner,
    _append_eval_evidence,
    build_offline_eval_env,
    default_eval_runner,
    parse_eval_outcome,
    refused_eval_token,
    sanitize_eval_excerpt,
)
from aetherops.airlock.egress import is_loopback_host
from aetherops.harness.observation import (
    create_clean_negative_card,
    create_finding_card,
    err,
    ok,
    warn,
)
from aetherops.scope.gate import normalize_target
from aetherops.scope.verbs import arguments_have_payload_shape, exploit_arg_keys, extra_arg_keys
from aetherops.types import Engagement, Observation

ALLOWLISTED_VERBS = frozenset({"health", "inventory", "dvllm"})
DEFAULT_PROBES = ("promptmap", "garak")


def adjacent_tree_present(path: Path | str | None) -> bool:
    """True only when a configured local DV LLM Agent path exists. No remote probe."""
    if path is None:
        return False
    text = str(path).strip()
    if not text:
        return False
    return Path(text).exists()


def _refused(summary: str, *, verb: str, data: dict[str, Any] | None = None) -> Observation:
    payload = {
        "adapter": "lab_target",
        "verb": verb,
        "scope_refused": True,
        "executed": False,
        "egress": False,
    }
    if data:
        payload.update(data)
    return err(
        summary,
        stop_condition="SCOPE DENIED. DV LLM Agent is a signed lab target only.",
        data=payload,
    )


def _missing_tree() -> Observation:
    return warn(
        "Damn Vulnerable LLM Agent tree not configured or not detectable.",
        root_cause_hint="Set AETHEROPS_DVLLM_PATH to the local lab fixture, or stay inventory-only.",
        retry="Configure the local path, then retry inventory.",
        stop_condition="STOP. Missing lab-target tree. Do not fall back to a remote host.",
        data={
            "adapter": "lab_target",
            "present": False,
            "executed": False,
            "egress": False,
            "tools": [],
        },
    )


def _signed_lab_live(engagement: Engagement | None, target: str | None) -> Observation | None:
    """Live DV probes need signed L3 + allow_exploit_dev + matching validation_target."""
    if engagement is None:
        return _refused("SCOPE DENIED: unsigned engagement.", verb="dvllm", data={"unsigned": True})
    if not engagement.allow_live_tools or not engagement.allow_exploit_dev:
        return _refused(
            "SCOPE DENIED: DV live probe requires signed allow_live_tools and allow_exploit_dev.",
            verb="dvllm",
            data={"unsigned": True},
        )
    if engagement.autonomy_level < 3:
        return _refused(
            "SCOPE DENIED: DV live probe requires autonomy_level >= 3.",
            verb="dvllm",
            data={"unsigned": True},
        )
    if not engagement.authorization_ref or engagement.authorized_by in {"", "engagement-owner"}:
        return _refused(
            "SCOPE DENIED: example engagement is not a signed authorization.",
            verb="dvllm",
            data={"unsigned": True},
        )
    today = datetime.now(UTC).date().isoformat()
    if not (engagement.start <= today <= engagement.end):
        return _refused("SCOPE DENIED: engagement window is not active.", verb="dvllm")
    expected = normalize_target(engagement.validation_target)
    got = normalize_target(target)
    if not expected:
        return _refused(
            "SCOPE DENIED: validation_target is empty; DV live has nowhere to bind.",
            verb="dvllm",
        )
    if not got or got != expected:
        return _refused(
            "SCOPE DENIED: DV live target must match the signed validation_target.",
            verb="dvllm",
            data={"target": target, "validation_target": engagement.validation_target},
        )
    if not is_loopback_host(got):
        return _refused(
            "SCOPE DENIED: DV live HTTP is loopback /v1 only (air-gap).",
            verb="dvllm",
            data={"target": target},
        )
    return None


def run_lab_target_adapter(
    verb: str = "inventory",
    *,
    engagement: Engagement | None = None,
    target: str | None = None,
    live: bool = False,
    arguments: dict[str, Any] | None = None,
    dvllm_path: Path | None = None,
    presence_checker: Callable[[str], bool] | None = None,
    probe_runner: EvalRunner | None = None,
    vault_dir: Path | None = None,
) -> Observation:
    """Inventory or (when signed) probe the DV LLM Agent fixture. Never PAIR."""
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )
    if exploit_arg_keys(arguments) or arguments_have_payload_shape(arguments):
        return err(
            "Denied: payload-shaped lab-target arguments.",
            stop_condition="Do not retry payload-shaped arguments.",
            data={"scope_refused": True, "executed": False},
        )

    action = (verb or "inventory").strip().lower().replace("-", "_")
    refused = refused_eval_token(action, arguments)
    if refused:
        return _refused(
            f"SCOPE DENIED: {refused} is not an allowed DV probe (no PAIR).",
            verb=action,
            data={"refused": refused},
        )
    if action not in ALLOWLISTED_VERBS:
        return _refused(
            "Denied: verb is not on the lab_target allowlist.",
            verb=action,
        )

    present = adjacent_tree_present(dvllm_path)
    if action in {"health", "inventory"}:
        if not present:
            return _missing_tree()
        return ok(
            "Damn Vulnerable LLM Agent lab fixture present (path probe only).",
            data={
                "adapter": "lab_target",
                "verb": action,
                "present": True,
                "executed": False,
                "egress": False,
                "live": False,
                "probes": list(DEFAULT_PROBES),
                "refused_probes": ["pair"],
            },
            next_actions=[
                "Live probe only with signed L3 + allow_exploit_dev + matching validation_target",
                "Default probes are promptmap/garak already on PATH — never PAIR",
            ],
        )

    # dvllm live or plan
    if not live:
        if not present:
            return _missing_tree()
        return ok(
            "DV LLM Agent probe planned (signed L3 live path not taken).",
            data={
                "adapter": "lab_target",
                "verb": action,
                "present": True,
                "executed": False,
                "live": False,
                "probes": list(DEFAULT_PROBES),
                "target": target,
            },
            next_actions=["Pass --live only on a signed L3 lab engagement"],
        )

    blocked = _signed_lab_live(engagement, target)
    if blocked is not None:
        return blocked
    if not present:
        return _missing_tree()

    checker = presence_checker or (lambda name: which(name) is not None)
    missing = [name for name in DEFAULT_PROBES if not checker(name)]
    if missing:
        missing_str = ", ".join(missing)
        return err(
            f"STOP missing-tool: {missing_str}. DV default probes are local promptmap/garak.",
            root_cause_hint="Do not substitute PAIR or a cloud judge.",
            retry="Install promptmap/garak locally or stay inventory-only.",
            stop_condition=f"STOP missing-tool: {missing_str}. Do not silently skip.",
            data={
                "adapter": "lab_target",
                "verb": action,
                "present": True,
                "executed": False,
                "scope_refused": True,
                "missing_tools": missing,
                "refused_probes": ["pair"],
            },
        )

    resolved = (target or DEFAULT_EVAL_TARGET).strip() or DEFAULT_EVAL_TARGET
    if not resolved.startswith("http"):
        resolved = f"http://{resolved}/v1"
    env = build_offline_eval_env(target=resolved)
    base_data = {
        "adapter": "lab_target",
        "verb": "dvllm",
        "present": True,
        "live": True,
        "probes": list(DEFAULT_PROBES),
        "refused_probes": ["pair"],
        "target": resolved,
        "offline": True,
        "cloud_judge": False,
    }
    evidence_ids: list[str] = []
    excerpts: list[str] = []
    outcomes: list[str] = []
    runner = probe_runner or default_eval_runner
    for probe in DEFAULT_PROBES:
        invocation = EvalInvocation(
            tool=probe,
            argv=(probe, "--offline"),
            env=env,
            target=resolved,
            cwd=str(dvllm_path) if dvllm_path is not None else ".",
        )
        try:
            result = runner(invocation)
        except FileNotFoundError:
            return err(
                f"STOP missing-tool: {probe}. DV probe CLI was not found on PATH at exec.",
                retry="Install promptmap/garak locally or stay inventory-only.",
                stop_condition=f"STOP missing-tool: {probe}. Do not silently skip.",
                data={**base_data, "executed": False, "scope_refused": True, "missing_tools": [probe]},
            )
        except subprocess.TimeoutExpired:
            return err(
                f"STOP probe-timeout: {probe} exceeded the local probe time budget.",
                stop_condition=f"STOP probe-timeout: {probe}. Do not mint a finding from a hung run.",
                data={**base_data, "executed": False},
            )
        except OSError as exc:
            return err(
                f"STOP probe-error: {probe} failed to launch ({exc}).",
                stop_condition=f"STOP probe-error: {probe}. Do not mint a finding from a failed launch.",
                data={**base_data, "executed": False},
            )
        if result.returncode != 0:
            return err(
                f"STOP probe-nonzero-exit: {probe} exited {result.returncode}; no pass/fail outcome.",
                root_cause_hint="A non-zero probe exit is a tool/usage error, not a finding.",
                stop_condition=f"STOP probe-nonzero-exit: {probe}. Do not mint a finding from an errored run.",
                data={**base_data, "executed": True, "returncode": result.returncode},
            )
        evidence_ids.append(
            _append_eval_evidence(vault_dir=vault_dir, tool=probe, invocation=invocation, result=result)
        )
        excerpts.append(sanitize_eval_excerpt(result.excerpt))
        outcomes.append(parse_eval_outcome(result.excerpt))

    excerpt = sanitize_eval_excerpt("\n".join(excerpts))
    if all(o == "unknown" for o in outcomes):
        return warn(
            f"DV LLM Agent probed vs {resolved} but produced no parseable pass/fail outcome.",
            root_cause_hint="No failure/pass count or signal marker was found in the probe output.",
            data={**base_data, "executed": True, "excerpt": excerpt, "outcome": "unknown"},
            next_actions=["Inspect the local probe output format; re-run with a parseable summary"],
        )

    if any(o == "signal" for o in outcomes):
        card = create_finding_card(
            observation=f"DV LLM Agent local probe vs {resolved}: Potential prompt-injection signal.",
            target=resolved,
            evidence_status="Potential",
            technique="AML.T0051",
            adapter="lab_target",
            verb="dvllm",
            domain="AI Estate",
            raw_excerpt=excerpt,
            title="Potential AML.T0051 via DV lab fixture",
        )
        card.evidence_ids = evidence_ids
        return ok(
            f"DV LLM Agent probed via promptmap/garak vs {resolved} (Potential AML.T0051/AML.T0054).",
            evidence_status="Potential",
            technique="AML.T0051",
            adapter="lab_target",
            verb="dvllm",
            target=resolved,
            data={
                **base_data,
                "executed": True,
                "technique": "AML.T0051",
                "techniques": ["AML.T0051", "AML.T0054"],
                "evidence_status": "Potential",
                "status": "Potential",
                "finding": card.model_dump(),
                "evidence_ids": evidence_ids,
                "excerpt": excerpt,
            },
            next_actions=["Pair the Potential card with purple-feedback before report"],
        )

    card = create_clean_negative_card(
        check_name="DV LLM Agent prompt-injection probe",
        target=resolved,
        observation=f"DV LLM Agent local probe vs {resolved}: no prompt-injection signal.",
        technique="AML.T0051",
        adapter="lab_target",
        verb="dvllm",
    )
    card.evidence_ids = evidence_ids
    return ok(
        f"DV LLM Agent probed via promptmap/garak vs {resolved}: clean negative (no AML.T0051 signal).",
        evidence_status="clean-negative",
        technique="AML.T0051",
        adapter="lab_target",
        verb="dvllm",
        target=resolved,
        data={
            **base_data,
            "executed": True,
            "technique": "AML.T0051",
            "techniques": ["AML.T0051", "AML.T0054"],
            "evidence_status": "clean-negative",
            "status": "clean-negative",
            "finding": card.model_dump(),
            "evidence_ids": evidence_ids,
            "excerpt": excerpt,
        },
        next_actions=["Record the clean negative; no purple pairing required"],
    )
