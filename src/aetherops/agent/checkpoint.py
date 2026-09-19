"""Checkpoint and resume persistence for AetherOps ReAct agent loop.

Stores ReAct state snapshots after each halt (success, max_turns, scope deny, error)
in `vault/checkpoints/` (air-gapped and gitignored).

Only explicit signed-host resume commands (`aetherops chat --resume`) read these snapshots
into active session context. Capability retrieval strictly excludes vault/ at all times.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aetherops.types import ChatMessage, Observation

CHECKPOINTS_DIR_NAME = "checkpoints"


def ensure_checkpoints_dir(vault_dir: Path) -> Path:
    """Ensure vault/checkpoints/ exists with isolation notice."""
    cp_dir = vault_dir / CHECKPOINTS_DIR_NAME
    cp_dir.mkdir(parents=True, exist_ok=True)
    readme = cp_dir / "README"
    if not readme.exists():
        readme.write_text(
            "AETHEROPS REAC-T CHECKPOINTS — persistent agent snapshots.\n"
            "Never commit, never upload, never include in evolve payloads.\n",
            encoding="utf-8",
        )
    return cp_dir


def save_checkpoint(
    vault_dir: Path,
    *,
    engagement_id: str,
    turn: int,
    halt_reason: str,
    messages: list[ChatMessage],
    trace: list[dict[str, Any]],
    last_observation: Observation | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> Path:
    """Save ReAct loop snapshot to vault/checkpoints/."""
    cp_dir = ensure_checkpoints_dir(vault_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    unique_id = uuid.uuid4().hex[:8]
    filename = f"checkpoint-{stamp}-{unique_id}.json"
    checkpoint_path = cp_dir / filename

    payload: dict[str, Any] = {
        "engagement_id": engagement_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "turn": turn,
        "halt_reason": halt_reason,
        "messages": [m.model_dump() for m in messages],
        "tool_trace": trace,
        "last_observation": last_observation.model_dump() if last_observation else None,
        "findings": findings or [],
    }

    serialized = json.dumps(payload, indent=2, ensure_ascii=False)
    checkpoint_path.write_text(serialized, encoding="utf-8")

    # Update latest.json pointer
    latest_path = cp_dir / "latest.json"
    latest_path.write_text(serialized, encoding="utf-8")

    return checkpoint_path


def list_checkpoints(vault_dir: Path) -> list[Path]:
    """List all checkpoint files in vault/checkpoints/ sorted oldest to newest."""
    cp_dir = vault_dir / CHECKPOINTS_DIR_NAME
    if not cp_dir.is_dir():
        return []
    checkpoints = [
        p for p in cp_dir.glob("checkpoint-*.json") if p.is_file()
    ]
    return sorted(checkpoints, key=lambda p: p.stat().st_mtime)


def load_latest_checkpoint(vault_dir: Path) -> dict[str, Any] | None:
    """Load the most recent checkpoint payload from vault/checkpoints/."""
    cp_dir = vault_dir / CHECKPOINTS_DIR_NAME
    if not cp_dir.is_dir():
        return None

    # First try latest.json if present
    latest_path = cp_dir / "latest.json"
    if latest_path.is_file():
        try:
            data = json.loads(latest_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass

    # Fall back to latest by file modification time
    checkpoints = list_checkpoints(vault_dir)
    if not checkpoints:
        return None

    latest_file = checkpoints[-1]
    try:
        data = json.loads(latest_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
