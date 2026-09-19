from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HEXSTRIKE_URL = "http://127.0.0.1:8888"


def resolve_hexstrike_url(
    *,
    configured: str = DEFAULT_HEXSTRIKE_URL,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Engage-path HexStrike/HexForge URL from HEXSTRIKE_URL or HEXSTRIKE_PORT.

    `HEXSTRIKE_URL` wins when set. Otherwise `http://127.0.0.1:${HEXSTRIKE_PORT:-8888}`,
    including operator port **8889** for HexForge v6.5 beside a legacy :8888 listener.
    """
    env = os.environ if environ is None else environ
    explicit = (env.get("HEXSTRIKE_URL") or "").strip()
    if explicit:
        return explicit
    port = (env.get("HEXSTRIKE_PORT") or "").strip()
    if port:
        return f"http://127.0.0.1:{port}"
    return (configured or "").strip() or DEFAULT_HEXSTRIKE_URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AETHEROPS_",
        env_file=".env",
        extra="ignore",
    )

    ollama_host: str = "http://127.0.0.1:11434"
    # The operator may replace this with a locally-created run model without
    # changing the harness default used by older deployments.
    preferred_run_model: str = "hf.co/empero-ai/Qwythos-9B-v2-GGUF:Q4_K_M"
    model: str = "hf.co/empero-ai/Qwythos-9B-v2-GGUF:Q4_K_M"
    vllm_host: str = "http://127.0.0.1:8000"
    lm_studio_host: str = "http://127.0.0.1:1234"
    # vLLM is only started with an explicit existing local path. This avoids a
    # runtime check becoming an implicit model download.
    vllm_model_path: Path | None = None
    local_runtime_start: bool = True
    local_runtime_ready_timeout: float = 20.0
    local_runtime_ready_interval: float = 0.5
    role: str = "purple"
    lang: str = "en"
    temperature: float = 0.6
    airgap: bool = True
    engagement_file: Path = ROOT / "configs" / "engagement.example.yaml"
    hexstrike_url: str = DEFAULT_HEXSTRIKE_URL
    # Tool trees are optional. No host-specific path is portable across
    # Linux, macOS, and Linux containers running on Windows Docker Desktop.
    hexstrike_path: Path | None = None
    tempest_path: Path | None = None
    redamon_path: Path | None = None
    dvllm_path: Path | None = None
    agentdojo_path: Path | None = None
    eval_oss_tasks_dir: Path | None = None
    knowledge_dir: Path = ROOT / "knowledge"
    skills_dir: Path = ROOT / "skills"
    adapters_file: Path = ROOT / "configs" / "adapters.yaml"
    mcp_file: Path = ROOT / "configs" / "mcp.example.json"
    # Explicit JSON array; empty example is the safe default. Never auto-discover configs/mcp.json.
    strix_mcp_file: Path = ROOT / "configs" / "strix.mcp.example.json"
    reports_dir: Path = ROOT / "reports"
    vault_dir: Path = ROOT / "vault"
    evolve_cache: Path = ROOT / ".evolve-cache"
    max_turns: int = 12
    native_tools: bool = True
    deterministic_first: bool = True
    embed_model: str = "nomic-embed-text"
    use_embeddings: bool = False
    retrieval_char_budget: int = 8000
    harvest_lessons: bool = True

    @field_validator("hexstrike_path", "tempest_path", "redamon_path", mode="before")
    @classmethod
    def blank_optional_paths_are_unset(cls, value: object) -> object:
        """Keep blank .env values from becoming Path('.')."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def get_hexstrike_url(self) -> str:
        """HEXSTRIKE_URL, else http://127.0.0.1:${HEXSTRIKE_PORT:-configured/8888}."""
        return resolve_hexstrike_url(configured=self.hexstrike_url)

    @property
    def run_model(self) -> str:
        """Configured local model for an engagement run (never a cloud alias).

        Precedence: an explicit ``AETHEROPS_MODEL`` pin overrides the standing
        ``AETHEROPS_PREFERRED_RUN_MODEL`` config, which overrides the built-in
        default. Values sourced from the environment count as configured, so
        presence is judged against the declared field defaults rather than
        ``model_fields_set`` (env-file loading marks every sourced field as set).
        """
        model_default = type(self).model_fields["model"].default
        if self.model != model_default:
            return self.model
        preferred_default = type(self).model_fields["preferred_run_model"].default
        if self.preferred_run_model != preferred_default:
            return self.preferred_run_model
        return self.preferred_run_model or self.model


def load_settings() -> Settings:
    return Settings()
