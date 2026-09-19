from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from aetherops.airlock.egress import EgressDenied, EgressSession
from aetherops.config import Settings
from aetherops.i18n import t
from aetherops.types import ChatMessage, Observation, ToolCall

SYSTEM_PREAMBLE = """You are AetherOps, a local authorized Red/Blue/Purple security agent.
Hard rules:
- Work only inside a signed engagement (scope + ROE).
- Do not generate exploits, payloads, malware, reverse shells, or C2.
- Prefer existing local tools via adapters (HexStrike allowlist, nmap, garak, Praxen).
- Engagement data never leaves the local vault. Never include findings, IPs, or secrets in evolve/research payloads.
- Air-gap first: if a step needs the internet, stop and use a local pack.
- English is the working language. Romanian is only used when the operator loads the romanian-reporting skill to translate a finished English report.
- Call run_adapter for local tools. Prefer read-only verbs: health, inventory.
- If a tool returns SCOPE DENIED or Denied, stop. Do not retry around the gate.
- Keep replies short. This path is a local 9B model.
"""


class QwythosClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def list_models(self) -> Observation:
        try:
            with EgressSession(timeout=5.0) as client:
                resp = client.get(f"{self.settings.ollama_host}/api/tags")
                resp.raise_for_status()
                models = [m.get("name", "") for m in resp.json().get("models", [])]
        except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError) as exc:
            return Observation(
                status="error",
                summary=f"Ollama unreachable at {self.settings.ollama_host}: {exc}",
                retry="Start `ollama serve` on this host.",
                stop_condition="Do not fall back to a cloud model.",
            )
        qwythos = [m for m in models if "qwythos" in m.lower() or "empero" in m.lower()]
        configured = self.settings.run_model
        present = model_is_present(configured, models)
        if not present:
            return Observation(
                status="error",
                summary=t(self.settings.lang, "qwythos_missing"),
                data={"models": models, "qwythos": qwythos, "configured": configured, "present": False},
                retry="Make the configured local model available, then set AETHEROPS_PREFERRED_RUN_MODEL.",
                stop_condition="Do not fall back to a cloud model.",
                next_actions=[
                    f"ollama pull {configured}",
                    "ollama create qwythos-purple -f models/Modelfile.qwythos-purple",
                ],
            )
        return Observation(
            status="success",
            summary=t(self.settings.lang, "qwythos_ok") + (": " + ", ".join(qwythos) if qwythos else f": {configured}"),
            data={"models": models, "qwythos": qwythos, "configured": configured, "present": True},
            next_actions=["aetherops chat", "aetherops adapters"],
        )

    def chat(self, messages: list[ChatMessage], tools: list[dict] | None = None) -> dict:
        payload = {
            "model": self.settings.run_model,
            "messages": [m.model_dump(exclude_none=True) for m in messages],
            "stream": False,
            "options": {"temperature": self.settings.temperature},
        }
        if tools:
            payload["tools"] = tools
        with EgressSession(timeout=180.0) as client:
            resp = client.post(f"{self.settings.ollama_host}/api/chat", json=payload)
            resp.raise_for_status()
            return resp.json()

    def parse_tool_calls(self, data: dict) -> list[ToolCall]:
        raw = (data.get("message") or {}).get("tool_calls") or []
        out: list[ToolCall] = []
        for i, tc in enumerate(raw):
            fn = tc.get("function") or {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            out.append(ToolCall(id=f"ollama_{i}", name=fn.get("name", ""), arguments=args))
        if not out:
            text = (data.get("message") or {}).get("content") or ""
            out.extend(parse_text_tool_calls(text))
        return out


_TOOL_BLOCK = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL | re.IGNORECASE)
_JSON_OBJECT = re.compile(r"\{[^{}]+\}", re.DOTALL)


def model_is_present(configured: str, names: list[str]) -> bool:
    """True when the configured Ollama tag (or a Qwythos role alias) is listed."""
    if not configured or not names:
        return False
    wanted = configured.lower()
    listed = [n.lower() for n in names if n]
    if wanted in listed:
        return True
    wanted_tail = wanted.rsplit("/", 1)[-1]
    for name in listed:
        name_tail = name.rsplit("/", 1)[-1]
        if wanted_tail == name_tail:
            return True
        if "qwythos" in wanted and "qwythos" in name:
            return True
        if "empero" in wanted and "empero" in name:
            return True
    return False


def parse_text_tool_calls(text: str) -> list[ToolCall]:
    """Parse Qwen/Hermes-style <tool_call> blocks so a 9B without native tools still loops."""
    out: list[ToolCall] = []
    if not text:
        return out
    blocks = _TOOL_BLOCK.findall(text)
    if not blocks:
        # Bare JSON tool call the model sometimes emits without tags.
        stripped = text.strip()
        if stripped.startswith("{") and "name" in stripped and (
            "run_adapter" in stripped or "hexstrike" in stripped
        ):
            blocks = [stripped]
    for i, block in enumerate(blocks):
        parsed = _parse_tool_block(block)
        if parsed is None:
            continue
        name, args = parsed
        if not name:
            continue
        out.append(ToolCall(id=f"text_{i}", name=name, arguments=args))
    return out


def _parse_tool_block(block: str) -> tuple[str, dict] | None:
    blob = (block or "").strip()
    if not blob:
        return None
    try:
        data = json.loads(blob)
        if isinstance(data, dict):
            name = str(data.get("name") or data.get("function") or "")
            args = data.get("arguments") or data.get("parameters") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if not isinstance(args, dict):
                args = {}
            return name, args
    except json.JSONDecodeError:
        pass
    # "run_adapter\n{...}" or "hexstrike.health\n{...}"
    lines = [ln.strip() for ln in blob.splitlines() if ln.strip()]
    name = lines[0] if lines else ""
    args: dict = {}
    match = _JSON_OBJECT.search(blob)
    if match:
        try:
            loaded = json.loads(match.group(0))
            if isinstance(loaded, dict):
                if "name" in loaded and not name.startswith("run_adapter"):
                    name = str(loaded.get("name") or name)
                    raw_args = loaded.get("arguments") or loaded.get("parameters") or loaded
                    args = raw_args if isinstance(raw_args, dict) else {}
                else:
                    args = loaded
        except json.JSONDecodeError:
            args = {}
    if name in {"{", "}"}:
        return None
    return (name, args) if name else None


def load_role_prompt(root: Path, role: str) -> str:
    path = root / "models" / f"SYSTEM_{role.upper()}.md"
    extra = path.read_text(encoding="utf-8") if path.exists() else ""
    return SYSTEM_PREAMBLE + "\n\n" + extra
