"""Loopback-only local model runtime selection.

The engagement brain always prefers the configured local model.  It checks
Ollama first, then vLLM, then LM Studio; unavailable services get one explicit
local start attempt before the caller may consider the separately-gated cloud
fallback.  This module never downloads a model and never contacts a non-
loopback host.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from aetherops.airlock.egress import EgressSession
from aetherops.config import Settings
from aetherops.llm.client import model_is_present
from aetherops.types import ChatMessage


class LocalRuntimeUnavailable(OSError):
    """No configured local runtime can serve the preferred model."""


def _loopback_host_port(url: str, default_host: str, default_port: int) -> tuple[str, int]:
    """Split a configured loopback host URL into an (address, port) pair."""
    parts = urlsplit(url)
    return (parts.hostname or default_host, parts.port or default_port)


class LocalChatClient(Protocol):
    def chat(self, messages: list[ChatMessage], tools: list[dict] | None = None) -> dict[str, Any]: ...


class RuntimeBackend(Protocol):
    name: str

    def available(self, model: str) -> bool: ...

    def start(self, model: str) -> str: ...

    def client(self, model: str) -> LocalChatClient: ...


@dataclass(frozen=True)
class RuntimeSelection:
    provider: str
    model: str
    client: LocalChatClient
    started: bool
    log: str


class _OllamaClient:
    def __init__(self, host: str, model: str, temperature: float) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature

    def chat(self, messages: list[ChatMessage], tools: list[dict] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [message.model_dump(exclude_none=True) for message in messages],
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if tools:
            payload["tools"] = tools
        with EgressSession(timeout=180.0) as session:
            response = session.post(f"{self.host}/api/chat", json=payload)
            response.raise_for_status()
            return response.json()


class _OpenAICompatibleClient:
    def __init__(self, host: str, model: str, temperature: float) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature

    def chat(self, messages: list[ChatMessage], tools: list[dict] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [message.model_dump(exclude_none=True) for message in messages],
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
        with EgressSession(timeout=180.0) as session:
            response = session.post(f"{self.host}/v1/chat/completions", json=payload)
            response.raise_for_status()
            data = response.json()
        if isinstance(data.get("message"), dict):
            return data
        choices = data.get("choices") or []
        message = choices[0].get("message") if choices and isinstance(choices[0], dict) else {}
        return {"message": message if isinstance(message, dict) else {"content": ""}}


class OllamaBackend:
    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.host = settings.ollama_host.rstrip("/")

    def available(self, model: str) -> bool:
        try:
            with EgressSession(timeout=2.0) as session:
                response = session.get(f"{self.host}/api/tags")
                response.raise_for_status()
                names = [str(item.get("name") or "") for item in response.json().get("models") or []]
            return model_is_present(model, names)
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            return False

    def start(self, model: str) -> str:
        # `ollama serve` only starts the local daemon; it does not pull a model.
        if not self.settings.local_runtime_start or which("ollama") is None:
            return "unavailable"
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return "attempted"
        except OSError:
            return "failed"

    def client(self, model: str) -> LocalChatClient:
        return _OllamaClient(self.host, model, self.settings.temperature)


class VllmBackend:
    name = "vllm"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.host = settings.vllm_host.rstrip("/")

    def available(self, model: str) -> bool:
        try:
            with EgressSession(timeout=2.0) as session:
                response = session.get(f"{self.host}/v1/models")
                response.raise_for_status()
                names = [str(item.get("id") or "") for item in response.json().get("data") or []]
            return model_is_present(model, names)
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            return False

    def start(self, model: str) -> str:
        model_path = self.settings.vllm_model_path
        if not self.settings.local_runtime_start or which("vllm") is None:
            return "unavailable"
        if model_path is None or not Path(model_path).exists():
            return "skipped-no-local-model-path"
        host, port = _loopback_host_port(self.settings.vllm_host, "127.0.0.1", 8000)
        try:
            subprocess.Popen(
                ["vllm", "serve", str(model_path), "--host", host, "--port", str(port)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return "attempted"
        except OSError:
            return "failed"

    def client(self, model: str) -> LocalChatClient:
        return _OpenAICompatibleClient(self.host, model, self.settings.temperature)


class LmStudioBackend:
    name = "lm-studio"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.host = settings.lm_studio_host.rstrip("/")

    def available(self, model: str) -> bool:
        try:
            with EgressSession(timeout=2.0) as session:
                response = session.get(f"{self.host}/v1/models")
                response.raise_for_status()
                names = [str(item.get("id") or "") for item in response.json().get("data") or []]
            return model_is_present(model, names)
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            return False

    def start(self, model: str) -> str:
        if not self.settings.local_runtime_start or which("lms") is None:
            return "unavailable"
        _host, port = _loopback_host_port(self.settings.lm_studio_host, "127.0.0.1", 1234)
        try:
            subprocess.Popen(
                ["lms", "server", "start", "--port", str(port)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return "attempted"
        except OSError:
            return "failed"

    def client(self, model: str) -> LocalChatClient:
        return _OpenAICompatibleClient(self.host, model, self.settings.temperature)


class LocalRuntimeChain:
    """Choose the first loopback runtime that can serve the preferred model."""

    def __init__(self, settings: Settings, backends: list[RuntimeBackend] | None = None) -> None:
        self.settings = settings
        self.backends = backends or [OllamaBackend(settings), VllmBackend(settings), LmStudioBackend(settings)]

    def _await_ready(self, backend: RuntimeBackend, model: str) -> bool:
        """Poll a just-started local runtime for bounded readiness.

        A freshly launched daemon is not yet bound to its loopback port, so a
        single immediate probe would falsely report it unavailable and let the
        chain fall through toward the gated cloud fallback. This waits up to the
        configured timeout for the local runtime to warm up. It performs no
        download and only probes loopback via the backend's own check.
        """
        if backend.available(model):
            return True
        timeout = max(0.0, self.settings.local_runtime_ready_timeout)
        interval = max(0.05, self.settings.local_runtime_ready_interval)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
            if backend.available(model):
                return True
        return False

    def available_selection(self) -> RuntimeSelection | None:
        """Read-only probe: first loopback runtime already serving the model.

        Performs no start attempt, spawns no daemon, and never waits for
        readiness. Suitable for diagnostics that must stay side-effect free.
        Returns None when no configured local runtime currently serves the
        preferred model.
        """
        model = self.settings.run_model
        for backend in self.backends:
            if backend.available(model):
                return RuntimeSelection(
                    provider=backend.name,
                    model=model,
                    client=backend.client(model),
                    started=False,
                    log=f"llm_provider={backend.name} fallback=false runtime_start=not-needed",
                )
        return None

    def select(self) -> RuntimeSelection:
        model = self.settings.run_model
        attempts: list[str] = []
        for backend in self.backends:
            if backend.available(model):
                return RuntimeSelection(
                    provider=backend.name,
                    model=model,
                    client=backend.client(model),
                    started=False,
                    log=f"llm_provider={backend.name} fallback=false runtime_start=not-needed",
                )
            result = backend.start(model)
            attempts.append(f"{backend.name}:{result}")
            ready = (
                self._await_ready(backend, model)
                if result == "attempted"
                else backend.available(model)
            )
            if ready:
                return RuntimeSelection(
                    provider=backend.name,
                    model=model,
                    client=backend.client(model),
                    started=True,
                    log=f"llm_provider={backend.name} fallback=false runtime_start={result}",
                )
        detail = ", ".join(attempts) or "no local runtimes configured"
        raise LocalRuntimeUnavailable(
            f"preferred local model {model!r} is unavailable after local runtime chain ({detail})"
        )
