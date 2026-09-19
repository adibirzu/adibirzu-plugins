from pathlib import Path
from typing import Any

from aetherops.airlock.vault import store
from aetherops.types import FindingCard, Observation


def ok(summary: str, **kwargs) -> Observation:
    return Observation(status="success", summary=summary, **kwargs)


def warn(summary: str, **kwargs) -> Observation:
    return Observation(status="warning", summary=summary, **kwargs)


def err(summary: str, **kwargs) -> Observation:
    return Observation(status="error", summary=summary, **kwargs)


def create_finding_card(
    *,
    observation: str,
    asset: str | None = None,
    target: str | None = None,
    evidence_status: str = "Potential",
    technique: str = "unknown",
    purple_pair: dict[str, Any] | None = None,
    vault_ref: str | None = None,
    adapter: str | None = None,
    verb: str | None = None,
    status: str = "Potential",
    severity: str = "Medium",
    title: str | None = None,
    domain: str = "Infrastructure",
    access_posture: str = "Unauthenticated",
    prod_blocker: bool = False,
    raw_excerpt: str | None = None,
    detection_name: str | None = None,
    data_source: str | None = None,
    logic: str | None = None,
    control: str | None = None,
    **kwargs: Any,
) -> FindingCard:
    """Create a structured finding card with standard evidence discipline."""
    resolved_target = asset or target
    return FindingCard(
        kind="finding",
        observation=observation,
        asset=resolved_target,
        target=resolved_target,
        evidence_status=evidence_status,
        technique=technique,
        purple_pair=purple_pair,
        vault_ref=vault_ref,
        adapter=adapter,
        verb=verb,
        status=status,
        severity=severity,
        title=title or (observation[:60] if observation else "Potential finding"),
        domain=domain,
        access_posture=access_posture,
        prod_blocker=prod_blocker,
        raw_excerpt=raw_excerpt,
        detection_name=detection_name,
        data_source=data_source,
        logic=logic,
        control=control,
        **kwargs,
    )


def store_finding_card(
    vault_dir: Path, card: FindingCard | dict[str, Any], name_prefix: str = "observation"
) -> Path:
    """Persist a FindingCard to the local vault as a JSON artifact."""
    payload = card.model_dump() if isinstance(card, FindingCard) else dict(card)
    slug = (
        str(payload.get("target") or payload.get("asset") or "unspecified")
        .replace("/", "_")
        .replace(":", "_")
        .replace(".", "_")
    )
    verb = str(payload.get("verb") or "scan")
    name = f"{name_prefix}-{verb}-{slug}"
    stored_path = store(vault_dir, name, payload)
    if isinstance(card, FindingCard):
        card.vault_ref = str(stored_path)
    return stored_path


def create_clean_negative_card(
    *,
    check_name: str,
    asset: str | None = None,
    target: str | None = None,
    observation: str | None = None,
    technique: str = "unknown",
    round_name: str = "R1",
    adapter: str | None = None,
    verb: str | None = None,
    vault_ref: str | None = None,
    **kwargs: Any,
) -> FindingCard:
    """Create a clean negative card documenting a verified absent vulnerability or active control."""
    resolved_target = asset or target or "in-scope"
    obs_text = observation or f"Clean negative: {check_name} verified absent on {resolved_target}"
    return FindingCard(
        kind="clean_negative",
        check_name=check_name,
        observation=obs_text,
        asset=resolved_target,
        target=resolved_target,
        evidence_status="clean-negative",
        status="clean-negative",
        severity="Informational",
        technique=technique,
        adapter=adapter,
        verb=verb,
        round=round_name,
        vault_ref=vault_ref,
        title=f"Clean negative: {check_name}",
        **kwargs,
    )


def store_clean_negative_card(
    vault_dir: Path, card: FindingCard | dict[str, Any], name_prefix: str = "clean-negative"
) -> Path:
    """Persist a clean negative card to the vault."""
    payload = card.model_dump() if isinstance(card, FindingCard) else dict(card)
    check = str(payload.get("check_name") or "").strip().lower().replace(" ", "_").replace("/", "_")[:30]
    prefix = f"{name_prefix}-{check}" if check else name_prefix
    return store_finding_card(vault_dir, card, name_prefix=prefix)

