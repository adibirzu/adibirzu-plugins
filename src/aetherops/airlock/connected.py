"""Exact-URL connected-LLM POST. Not a general internet hole.

Only the URLs listed in configs/airlock.yaml `fallback_llm_urls` may be
contacted, and only after sanitize_outbound. Adding a URL is a reviewed PR.
No wildcards. Redirects are not followed. The cursor CLI is never invoked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from aetherops.airlock.classifier import OutboundRefused, sanitize_outbound
from aetherops.config import ROOT
from aetherops.types import ChatMessage

_WILDCARD_CHARS = ("*", "?", "[", "]", "{", "}")
DEFAULT_FALLBACK_URLS = (
    "https://api.x.ai/v1/chat/completions",
    "https://openrouter.ai/api/v1/chat/completions",
)
PROVIDER_URLS = {
    "grok": "https://api.x.ai/v1/chat/completions",
    "cline": "https://openrouter.ai/api/v1/chat/completions",
}
FORBIDDEN_CLI = frozenset({"cursor", "cursor-agent"})


class ConnectedDenied(ValueError):
    """Connected-LLM request refused (URL, sanitization, or CLI)."""


def load_fallback_urls(airlock_file: Path | None = None) -> list[str]:
    path = airlock_file or (ROOT / "configs" / "airlock.yaml")
    urls: list[str] = []
    if path.exists():
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        urls.extend(str(u) for u in (raw.get("fallback_llm_urls") or []) if u)
    if not urls:
        urls.extend(DEFAULT_FALLBACK_URLS)
    return urls


def is_exact_fallback_url(url: str, allowlist: list[str] | None = None) -> tuple[bool, str]:
    if not url or not isinstance(url, str):
        return False, "empty"
    stripped = url.strip()
    if any(ch in stripped for ch in _WILDCARD_CHARS):
        return False, "wildcard"
    parsed = urlparse(stripped)
    if parsed.scheme != "https":
        return False, "not-https"
    if parsed.username or parsed.password:
        return False, "userinfo"
    if not parsed.hostname:
        return False, "no-host"
    allowed = allowlist if allowlist is not None else load_fallback_urls()
    if stripped not in allowed:
        return False, "not-allowlisted"
    return True, "ok"


def refuse_forbidden_cli(binary: str | None) -> None:
    name = (binary or "").strip().lower()
    if name in FORBIDDEN_CLI:
        raise ConnectedDenied("cursor CLI is privacy-revoked; use an allowlisted HTTPS API only")


def _as_ollama(data: dict[str, Any]) -> dict[str, Any]:
    if isinstance(data.get("message"), dict):
        return data
    choices = data.get("choices") or []
    content = ""
    if choices and isinstance(choices[0], dict):
        content = str((choices[0].get("message") or {}).get("content") or "")
    return {"message": {"content": content}}


def post_chat_completions(
    url: str,
    messages: list[ChatMessage],
    *,
    api_key: str,
    model: str,
    timeout: float = 60.0,
    allowlist: list[str] | None = None,
    http_client: httpx.Client | None = None,
) -> dict[str, Any]:
    """POST an OpenAI-shaped chat body to an exact allowlisted URL."""
    refuse_forbidden_cli(None)
    ok, reason = is_exact_fallback_url(url, allowlist)
    if not ok:
        raise ConnectedDenied(f"fallback URL refused: {reason}")
    if not (api_key or "").strip():
        raise ConnectedDenied("fallback API key is empty")
    payload_messages = []
    for msg in messages:
        payload_messages.append(
            {"role": msg.role, "content": sanitize_outbound(msg.content or "")}
        )
    body = {"model": model, "messages": payload_messages}
    if "tools" in body or "functions" in body or "tool_choice" in body:
        raise ConnectedDenied(
            "connected fallback is text-only; tool definitions must not be forwarded"
        )
    sanitize_outbound(str(body))
    send_headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }
    try:
        if http_client is not None:
            resp = http_client.post(url, headers=send_headers, json=body)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                resp = client.post(url, headers=send_headers, json=body)
        resp.raise_for_status()
        data = resp.json()
    except OutboundRefused:
        raise
    except (httpx.HTTPError, OSError, ValueError, TypeError) as exc:
        raise ConnectedDenied(f"connected LLM POST failed: {exc}") from exc
    if not isinstance(data, dict):
        raise ConnectedDenied("connected LLM returned a non-object")
    return _as_ollama(data)
