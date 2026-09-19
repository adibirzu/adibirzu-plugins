"""Reasoning/demo brain: local Qwythos first, then logged connected fallback.

Fallback is not silent. It requires an explicit ROE waiver, exact allowlisted
HTTPS URLs, and sanitize_outbound. The cursor CLI is never invoked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aetherops.airlock.classifier import OutboundRefused, sanitize_outbound
from aetherops.airlock.connected import (
    PROVIDER_URLS,
    ConnectedDenied,
    post_chat_completions,
    refuse_forbidden_cli,
)
from aetherops.airlock.egress import EgressDenied
from aetherops.config import Settings
from aetherops.knowledge.train_capture import capture_turn
from aetherops.lab.exfil_preflight import has_cloud_llm_fallback_waiver
from aetherops.llm.runtime import LocalRuntimeChain, LocalRuntimeUnavailable
from aetherops.types import ChatMessage, Engagement

LOCAL_PROVIDER = "ollama"
FALLBACK_ORDER = ("grok", "cline")


class BrainDenied(ValueError):
    """Local brain failed and fallback was refused or also failed."""


@dataclass
class BrainTurn:
    payload: dict[str, Any]
    provider: str
    fallback: bool
    log: str

    def content(self) -> str:
        return str((self.payload.get("message") or {}).get("content") or "")


def _local_unavailable(exc: BaseException) -> bool:
    return isinstance(exc, (httpx.HTTPError, OSError, EgressDenied, TimeoutError, ConnectionError, LocalRuntimeUnavailable))


def _api_key(provider: str) -> str:
    if provider == "grok":
        return (
            os.environ.get("AETHEROPS_XAI_API_KEY")
            or os.environ.get("XAI_API_KEY")
            or ""
        )
    if provider == "cline":
        return (
            os.environ.get("AETHEROPS_CLINE_API_KEY")
            or os.environ.get("OPENROUTER_API_KEY")
            or ""
        )
    return ""


def _model_for(provider: str, settings: Settings) -> str:
    if provider == "grok":
        return getattr(settings, "fallback_grok_model", None) or "grok-4"
    if provider == "cline":
        return getattr(settings, "fallback_cline_model", None) or "anthropic/claude-sonnet-4"
    return settings.run_model


class Brain:
    """Local-first chat with an explicit, logged connected fallback."""

    def __init__(
        self,
        settings: Settings,
        *,
        local_client: Any | None = None,
        runtime_chain: LocalRuntimeChain | None = None,
        connected_post: Any | None = None,
        corpus_path: Any | None = None,
    ) -> None:
        self.settings = settings
        self.local_client = local_client
        self.runtime_chain = runtime_chain or (None if local_client is not None else LocalRuntimeChain(settings))
        self.connected_post = connected_post or post_chat_completions
        if corpus_path is not None:
            self.corpus_path = Path(corpus_path)
        else:
            vault = getattr(settings, "vault_dir", None)
            self.corpus_path = (
                Path(vault) / "train-corpus" / "qlora.jsonl" if vault else None
            )

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        engagement: Engagement,
        tools: list[dict] | None = None,
        issue_class: str | None = None,
        tool_trace: list[dict[str, Any]] | None = None,
    ) -> BrainTurn:
        refuse_forbidden_cli(None)
        local_error = ""
        try:
            local_provider = LOCAL_PROVIDER
            local_log = "llm_provider=ollama fallback=false runtime_start=not-needed"
            client = self.local_client
            if client is None:
                selection = self.runtime_chain.select() if self.runtime_chain else None
                if selection is None:
                    raise LocalRuntimeUnavailable("no local runtime client configured")
                client = selection.client
                local_provider = selection.provider
                local_log = selection.log
            payload = client.chat(messages, tools=tools)
            turn = BrainTurn(
                payload=payload if isinstance(payload, dict) else {"message": {"content": str(payload)}},
                provider=local_provider,
                fallback=False,
                log=local_log,
            )
            capture_turn(
                messages=messages,
                response_text=turn.content(),
                provider=turn.provider,
                fallback=False,
                outcome="success",
                issue_class=issue_class,
                tool_trace=tool_trace,
                corpus_path=self.corpus_path,
            )
            return turn
        except Exception as exc:
            if not _local_unavailable(exc):
                raise
            local_error = str(exc)

        if not has_cloud_llm_fallback_waiver(engagement):
            raise BrainDenied(
                f"Local Qwythos unavailable ({local_error or 'unknown'}). "
                "Cloud fallback requires ROE token cloud-llm-fallback-waived-this-run. "
                "Do not send the prompt to a cloud API."
            )

        sanitized: list[ChatMessage] = []
        try:
            for msg in messages:
                sanitized.append(
                    ChatMessage(
                        role=msg.role,
                        content=sanitize_outbound(msg.content or ""),
                        name=msg.name,
                    )
                )
        except OutboundRefused as exc:
            raise BrainDenied(
                f"Local Qwythos unavailable; fallback refused because sanitization failed: {exc}"
            ) from exc

        last_err = ""
        for provider in FALLBACK_ORDER:
            url = PROVIDER_URLS[provider]
            key = _api_key(provider)
            try:
                payload = self.connected_post(
                    url,
                    sanitized,
                    api_key=key,
                    model=_model_for(provider, self.settings),
                )
                turn = BrainTurn(
                    payload=payload,
                    provider=provider,
                    fallback=True,
                    log=(
                        f"llm_provider={provider} fallback=true "
                        f"local_error={local_error or 'unavailable'}"
                    ),
                )
                capture_turn(
                    messages=sanitized,
                    response_text=turn.content(),
                    provider=turn.provider,
                    fallback=True,
                    outcome="success",
                    issue_class=issue_class,
                    tool_trace=tool_trace,
                    corpus_path=self.corpus_path,
                )
                return turn
            except (ConnectedDenied, OutboundRefused, httpx.HTTPError, OSError, ValueError, TypeError) as exc:
                last_err = f"{provider}: {exc}"
                continue
        raise BrainDenied(
            f"Local Qwythos unavailable ({local_error or 'unknown'}); "
            f"connected fallback failed ({last_err or 'no provider'}). "
            "Fallback was attempted and logged, not silent."
        )
