from __future__ import annotations

import logging
import re

import httpx

from aetherops.adapters.base import AdapterRegistry
from aetherops.agent.checkpoint import load_latest_checkpoint, save_checkpoint
from aetherops.agent.tools import ADAPTER_TOOLS, resolve_tool_call
from aetherops.config import ROOT, Settings
from aetherops.knowledge.retriever import retrieve
from aetherops.llm.brain import Brain, BrainDenied
from aetherops.llm.client import QwythosClient, load_role_prompt
from aetherops.scope.gate import load_engagement_or_deny
from aetherops.scope.step import authorize_step, should_halt
from aetherops.types import ChatMessage, Observation

_ADVANCED_REASONING = re.compile(r"\b(reason|reasoning|analy[sz]e|hypothes|correlat|explain)\b", re.IGNORECASE)
_REPORT_GENERATION = re.compile(r"\b(report|executive summary|customer summary)\b", re.IGNORECASE)
_IP_OR_HOST = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", re.IGNORECASE)
_LOG = logging.getLogger(__name__)


def llm_purpose(user_text: str) -> str | None:
    """Return the only two purposes that may invoke an LLM in the run loop.

    Routine scanner, enumeration, parser, health, and inventory work goes
    through the deterministic adapter boundary.  This is intentionally based
    on purpose rather than a model-provided tool call, so a model cannot make
    itself the dispatcher for routine collection.
    """
    text = user_text or ""
    if _REPORT_GENERATION.search(text):
        return "report-generation"
    if _ADVANCED_REASONING.search(text):
        return "advanced-reasoning"
    return None


def _target_from_routine_text(text: str) -> str | None:
    match = _IP_OR_HOST.search(text or "")
    return match.group(0) if match else None


def _deterministic_routine(
    *,
    settings: Settings,
    adapters: AdapterRegistry,
    engagement,
    user_text: str,
) -> Observation | None:
    """Perform one routine collection step without invoking the LLM."""
    text = (user_text or "").lower()
    target = _target_from_routine_text(user_text)
    if any(token in text for token in ("payload", "exploit", "poc", "shellcode")):
        return Observation(
            status="error",
            summary="Denied: routine path never dispatches exploit or payload generation.",
            stop_condition="Do not retry denied tools. Human review remains required.",
            data={"executed": False, "capability": False, "llm_invoked": False, "llm_boundary": "deterministic"},
        )

    if "health" in text:
        name, verb, target, live = "hexstrike", "health", None, False
    elif any(token in text for token in ("whw", "webhackers", "web-hackers", "web hackers weapons")):
        name, verb, target, live = "whw", "coverage", None, False
    elif "inventory" in text or "enumerat" in text or "parser" in text:
        name, verb, live = "hexstrike", "inventory", False
    elif any(token in text for token in ("scan", "recon", "discover")):
        # A routine scan must carry a caller-supplied identity.  If the text
        # has none, let the governed ReAct path surface the signed target; do
        # not infer or invent one here.
        if target is None:
            return None
        name, verb, live = "hexstrike", "nmap_scan", False
    else:
        return None

    gated = authorize_step(
        name=name,
        verb=verb,
        target=target,
        live=live,
        engagement=engagement,
        airgap=settings.airgap,
        lang=settings.lang,
    )
    if gated:
        data = dict(gated.data or {})
        data.update({"executed": False, "capability": False, "llm_invoked": False, "llm_boundary": "deterministic"})
        return gated.model_copy(update={"data": data})
    observation = adapters.run(name, verb=verb, target=target, live=live)
    data = dict(observation.data or {})
    data.update({"llm_invoked": False, "llm_boundary": "deterministic", "routine_tool": f"{name}.{verb}"})
    return observation.model_copy(update={"data": data})


def _should_stop(obs: Observation) -> bool:
    return should_halt(obs)


def _maybe_harvest(settings: Settings, obs: Observation) -> Observation:
    """Best-effort capability lesson after a run. Never blocks chat."""
    if not getattr(settings, "harvest_lessons", True):
        return obs
    try:
        from aetherops.knowledge.lessons import harvest_from_observation

        harvest_from_observation(obs, index_dir=settings.knowledge_dir / "index")
    except (OSError, TypeError, ValueError, KeyError):
        return obs
    return obs


def _halt_from_gate(
    obs: Observation,
    *,
    last_text: str,
    settings: Settings,
    turn: int,
    trace: list[dict],
    stopped: str,
    messages: list[ChatMessage] | None = None,
    engagement_id: str = "LAB",
) -> Observation:
    data = dict(obs.data or {})
    data.update(
        {
            "full": last_text,
            "model": settings.run_model,
            "role": settings.role,
            "turns": turn + 1,
            "tool_trace": trace,
            "stopped_tool": stopped,
            "scope_refused": True,
        }
    )
    result = Observation(
        status="error",
        summary=obs.summary,
        data=data,
        root_cause_hint=obs.root_cause_hint,
        retry=obs.retry,
        stop_condition=obs.stop_condition or "SCOPE DENIED or denied verb. Stop.",
        next_actions=["Do not retry around the gate"],
    )
    try:
        save_checkpoint(
            settings.vault_dir,
            engagement_id=engagement_id,
            turn=turn + 1,
            halt_reason="scope_denied",
            messages=messages or [],
            trace=trace,
            last_observation=result,
        )
    except (OSError, TypeError, ValueError) as exc:
        _LOG.warning("Unable to persist scope-denial checkpoint: %s", exc)
    return result


def run_chat(
    settings: Settings,
    user_text: str = "",
    skill_names: list[str] | None = None,
    client: QwythosClient | None = None,
    registry: AdapterRegistry | None = None,
    resume: bool = False,
) -> Observation:
    """Scope-bound ReAct loop. parse_tool_calls → per-step gate → AdapterRegistry.run."""
    adapters = registry or AdapterRegistry(settings)
    trace: list[dict] = []
    messages: list[ChatMessage] = []

    if resume:
        cp = load_latest_checkpoint(settings.vault_dir)
        if not cp:
            return Observation(
                status="warning",
                summary="No checkpoint found in vault/checkpoints/ to resume.",
                stop_condition="Run a chat turn first before attempting resume.",
                data={"resume_failed": True},
            )
        for msg in cp.get("messages", []):
            messages.append(ChatMessage(**msg))
        trace = list(cp.get("tool_trace", []))
        if user_text and user_text.strip():
            messages.append(ChatMessage(role="user", content=user_text.strip()))
    else:
        system = load_role_prompt(ROOT, settings.role)
        context = retrieve(
            settings.knowledge_dir,
            settings.skills_dir,
            query=user_text,
            names=skill_names,
            budget=settings.retrieval_char_budget,
            evolve_cache=settings.evolve_cache,
            use_embeddings=settings.use_embeddings,
            embed_model=settings.embed_model,
            ollama_host=settings.ollama_host,
        )
        if context:
            system += "\n\n--- retrieved offline skills/knowledge ---\n" + context
        messages = [
            ChatMessage(role="system", content=system),
            ChatMessage(role="user", content=user_text),
        ]
    tools = ADAPTER_TOOLS if settings.native_tools else None
    trace: list[dict] = []
    last_text = ""
    max_turns = max(1, int(settings.max_turns or 1))

    engagement, load_err = load_engagement_or_deny(settings.engagement_file, lang=settings.lang)
    if load_err or engagement is None:
        return load_err or Observation(
            status="error",
            summary="SCOPE DENIED: engagement file unreadable.",
            stop_condition="SCOPE DENIED. Do not retry without a readable signed engagement.",
            data={"scope_refused": True, "tool_trace": trace},
        )

    # Explicit deterministic-first boundary: collection is never delegated to
    # the LLM.  Only prior-finding reasoning and report generation continue to
    # the ReAct brain below.
    if (
        getattr(settings, "deterministic_first", True)
        and not resume
        and llm_purpose(user_text) is None
    ):
        routine = _deterministic_routine(
            settings=settings,
            adapters=adapters,
            engagement=engagement,
            user_text=user_text,
        )
        if routine is not None:
            return _maybe_harvest(settings, routine)

    # An injected client is a test seam.  In production Brain owns the
    # local-runtime chain; the parser remains protocol-compatible with the
    # Ollama tool-call shape across the supported local runtimes.
    parser = client or QwythosClient(settings)
    brain = Brain(settings, local_client=client)

    for turn in range(max_turns):
        try:
            brain_turn = brain.chat(messages, tools=tools, engagement=engagement, tool_trace=trace)
            data = brain_turn.payload
            brain_meta = {
                "llm_provider": brain_turn.provider,
                "llm_fallback": brain_turn.fallback,
                "llm_log": brain_turn.log,
            }
        except (httpx.HTTPError, OSError, ValueError, TypeError, BrainDenied) as exc:
            err_obs = Observation(
                status="error",
                summary=f"Brain chat failed: {exc}",
                retry="Confirm local Ollama, or set cloud-llm-fallback-waived-this-run and a sanitised fallback key.",
                stop_condition="Do not send an unsanitized prompt to a cloud API.",
                data={"turns": turn, "tool_trace": trace},
            )
            try:
                save_checkpoint(
                    settings.vault_dir,
                    engagement_id=getattr(engagement, "engagement_id", "LAB"),
                    turn=turn,
                    halt_reason="error",
                    messages=messages,
                    trace=trace,
                    last_observation=err_obs,
                )
            except (OSError, TypeError, ValueError) as exc:
                _LOG.warning("Unable to persist brain-error checkpoint: %s", exc)
            return _maybe_harvest(settings, err_obs)
        message = data.get("message") or {}
        last_text = message.get("content") or ""
        tool_calls = parser.parse_tool_calls(data)
        if not tool_calls:
            from aetherops.airlock.vault import index_vault
            from aetherops.scope.completeness import check_completeness, should_drive_plan

            vault_index = index_vault(settings.vault_dir)
            inventory = None
            if hasattr(adapters, "inventory"):
                inventory = adapters.inventory().data
            if should_drive_plan(engagement, vault_index, inventory):
                plan_obs = adapters.run("plan", verb="next", target=None, live=False)
                if _should_stop(plan_obs):
                    return _maybe_harvest(
                        settings,
                        _halt_from_gate(
                            plan_obs,
                            last_text=last_text,
                            settings=settings,
                            turn=turn,
                            trace=trace,
                            stopped="plan.next",
                            messages=messages,
                            engagement_id=getattr(engagement, "engagement_id", "LAB"),
                        ),
                    )
                nxt = (plan_obs.data or {}).get("next") or "STOP"
                trace.append(
                    {
                        "id": f"drive_{turn}",
                        "name": "plan",
                        "verb": "next",
                        "target": None,
                        "live": False,
                        "status": plan_obs.status,
                        "summary": plan_obs.summary,
                    }
                )
                if nxt == "STOP":
                    success_obs = Observation(
                        status="success",
                        summary=last_text[:400] or plan_obs.summary,
                        data={
                            "full": last_text,
                            "model": settings.run_model,
                            "role": settings.role,
                            "turns": turn + 1,
                            "tool_trace": trace,
                            "completeness": check_completeness(
                                engagement, vault_index, inventory
                            ).data,
                            **brain_meta,
                        },
                        next_actions=[
                            "Keep findings in vault/",
                            "Pair every red finding with purple-feedback before the customer report",
                        ],
                    )
                    return _maybe_harvest(settings, success_obs)
                messages.append(
                    ChatMessage(
                        role="tool",
                        content=plan_obs.model_dump_json(),
                        name="plan.next",
                        tool_call_id=f"drive_{turn}",
                    )
                )
                continue
            success_obs = Observation(
                status="success",
                summary=last_text[:400] or "(empty model reply)",
                data={
                    "full": last_text,
                    "model": settings.run_model,
                    "role": settings.role,
                    "turns": turn + 1,
                    "tool_trace": trace,
                    **brain_meta,
                },
                next_actions=[
                    "Keep findings in vault/",
                    "Use romanian-reporting only after the English report exists",
                    "Pair every red finding with purple-feedback before the customer report",
                ],
            )
            try:
                save_checkpoint(
                    settings.vault_dir,
                    engagement_id=getattr(engagement, "engagement_id", "LAB"),
                    turn=turn + 1,
                    halt_reason="success",
                    messages=messages,
                    trace=trace,
                    last_observation=success_obs,
                )
            except (OSError, TypeError, ValueError) as exc:
                _LOG.warning("Unable to persist success checkpoint: %s", exc)
            return _maybe_harvest(settings, success_obs)

        raw_calls = message.get("tool_calls") or [
            {"function": {"name": tc.name, "arguments": tc.arguments}} for tc in tool_calls
        ]
        messages.append(
            ChatMessage(role="assistant", content=last_text, tool_calls=raw_calls)
        )
        for tc in tool_calls:
            name, verb, target, live = resolve_tool_call(tc)
            gated = authorize_step(
                name=name,
                verb=verb,
                target=target,
                live=live,
                engagement=engagement,
                airgap=settings.airgap,
                arguments=tc.arguments,
                lang=settings.lang,
            )
            if gated:
                entry = {
                    "id": tc.id,
                    "name": name,
                    "verb": verb,
                    "target": target,
                    "live": live,
                    "status": gated.status,
                    "summary": gated.summary,
                    "scope_refused": True,
                }
                trace.append(entry)
                return _maybe_harvest(
                    settings,
                    _halt_from_gate(
                        gated,
                        last_text=last_text,
                        settings=settings,
                        turn=turn,
                        trace=trace,
                        stopped=f"{name}.{verb}",
                        messages=messages,
                        engagement_id=getattr(engagement, "engagement_id", "LAB"),
                    ),
                )
            try:
                obs = adapters.run(
                    name,
                    verb=verb,
                    target=target,
                    live=live,
                    arguments=tc.arguments,
                )
            except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
                obs = Observation(
                    status="error",
                    summary="SCOPE DENIED: adapter step failed closed.",
                    root_cause_hint=str(exc),
                    stop_condition="SCOPE DENIED. Do not retry around a failed gate.",
                    data={"scope_refused": True},
                )
            entry = {
                "id": tc.id,
                "name": name,
                "verb": verb,
                "target": target,
                "live": live,
                "status": obs.status,
                "summary": obs.summary,
            }
            if _should_stop(obs):
                entry["scope_refused"] = True
            trace.append(entry)
            if _should_stop(obs):
                return _maybe_harvest(
                    settings,
                    _halt_from_gate(
                        obs,
                        last_text=last_text,
                        settings=settings,
                        turn=turn,
                        trace=trace,
                        stopped=f"{name}.{verb}",
                        messages=messages,
                        engagement_id=getattr(engagement, "engagement_id", "LAB"),
                    ),
                )
            messages.append(
                ChatMessage(
                    role="tool",
                    content=obs.model_dump_json(),
                    name=f"{name}.{verb}",
                    tool_call_id=tc.id,
                )
            )

    warn_obs = Observation(
        status="warning",
        summary=last_text[:400] or f"Stopped after {max_turns} turns.",
        data={
            "full": last_text,
            "model": settings.run_model,
            "role": settings.role,
            "turns": max_turns,
            "tool_trace": trace,
        },
        stop_condition="max_turns reached. Ask the operator before another loop.",
        next_actions=["Keep findings in vault/"],
    )
    try:
        save_checkpoint(
            settings.vault_dir,
            engagement_id=getattr(engagement, "engagement_id", "LAB"),
            turn=max_turns,
            halt_reason="max_turns",
            messages=messages,
            trace=trace,
            last_observation=warn_obs,
        )
    except (OSError, TypeError, ValueError) as exc:
        _LOG.warning("Unable to persist max-turns checkpoint: %s", exc)
    return _maybe_harvest(settings, warn_obs)


def run_adapter(settings: Settings, name: str, verb: str, target: str | None, live: bool) -> Observation:
    return AdapterRegistry(settings).run(name, verb=verb, target=target, live=live)
