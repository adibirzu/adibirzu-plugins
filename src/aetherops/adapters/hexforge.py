"""HexForge / HexStrike identity probe for the engage-path health contract.

GET `/health/identity` first, then fall back to `/health`. Never POSTs.
Non-loopback URLs fail closed via `EgressSession` (`EgressDenied`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aetherops.airlock.egress import EgressDenied, EgressSession
from aetherops.harness.observation import err, ok, warn
from aetherops.types import Observation

HEXFORGE_PIN = "99db165"
HEXFORGE_ENGINE = "hexforge"
LEGACY_ENGINE = "hexstrike-v6.0-or-unknown"


@dataclass(frozen=True)
class HexstrikeIdentity:
    """Recorded product identity from a loopback health probe."""

    url: str
    source: str
    product: str
    edition: str
    version: str
    v2_enabled: bool
    enhanced_modules: tuple[str, ...]
    rag_backends: tuple[str, ...]
    engine: str
    pin: str | None = None
    identity_status: int | None = None
    health_status: int | None = None
    error: str | None = None

    def as_data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "url": self.url,
            "product": self.product,
            "edition": self.edition,
            "version": self.version,
            "v2_enabled": self.v2_enabled,
            "enhanced_modules": list(self.enhanced_modules),
            "rag_backends": list(self.rag_backends),
            "engine": self.engine,
            "identity_source": self.source,
        }
        if self.pin:
            data["hexforge_pin"] = self.pin
        if self.identity_status is not None:
            data["identity_status"] = self.identity_status
        if self.health_status is not None:
            data["health_status"] = self.health_status
        return data


def _json_object(resp: httpx.Response) -> dict[str, Any] | None:
    try:
        payload = resp.json()
    except (ValueError, TypeError, httpx.DecodingError):
        return None
    return payload if isinstance(payload, dict) else None


def _str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _try_get(session: EgressSession, url: str) -> tuple[httpx.Response | None, BaseException | None]:
    try:
        return session.get(url), None
    except EgressDenied:
        raise
    except (httpx.HTTPError, OSError, ValueError, TypeError) as exc:
        return None, exc


def _from_identity_payload(base: str, payload: dict[str, Any], status: int) -> HexstrikeIdentity:
    product = str(payload.get("product") or "unknown")
    edition = str(payload.get("edition") or "unknown")
    version = str(payload.get("version") or "unknown")
    is_hexforge = product.lower() == "hexforge"
    return HexstrikeIdentity(
        url=f"{base}/health/identity",
        source="identity",
        product=product,
        edition=edition,
        version=version,
        v2_enabled=bool(payload.get("v2_enabled", False)),
        enhanced_modules=_str_tuple(payload.get("enhanced_modules")),
        rag_backends=_str_tuple(payload.get("rag_backends")),
        engine=HEXFORGE_ENGINE if is_hexforge else LEGACY_ENGINE,
        pin=HEXFORGE_PIN if is_hexforge else None,
        identity_status=status,
    )


def _from_health_payload(
    base: str, payload: dict[str, Any] | None, status: int
) -> HexstrikeIdentity:
    version = "unknown"
    if payload is not None:
        raw = payload.get("version")
        if raw is not None and str(raw).strip():
            version = str(raw)
    return HexstrikeIdentity(
        url=f"{base}/health",
        source="health",
        product="unknown",
        edition="unknown",
        version=version,
        v2_enabled=False,
        enhanced_modules=(),
        rag_backends=(),
        engine=LEGACY_ENGINE,
        pin=None,
        health_status=status,
    )


def _unreachable(base: str, exc: BaseException | None) -> HexstrikeIdentity:
    return HexstrikeIdentity(
        url=f"{base}/health",
        source="none",
        product="unknown",
        edition="unknown",
        version="unknown",
        v2_enabled=False,
        enhanced_modules=(),
        rag_backends=(),
        engine=LEGACY_ENGINE,
        error=str(exc) if exc is not None else "unreachable",
    )


def probe_hexstrike_identity(
    base_url: str,
    *,
    timeout: float = 3.0,
    client: httpx.Client | None = None,
    transport: httpx.BaseTransport | None = None,
) -> HexstrikeIdentity:
    """GET `/health/identity`, then `/health`. Raises `EgressDenied` off-loopback."""
    base = (base_url or "").rstrip("/")
    identity_url = f"{base}/health/identity"
    health_url = f"{base}/health"
    with EgressSession(timeout=timeout, client=client, transport=transport) as session:
        ident_resp, ident_err = _try_get(session, identity_url)
        ident_status = ident_resp.status_code if ident_resp is not None else None
        if ident_resp is not None and ident_resp.status_code == 200:
            payload = _json_object(ident_resp)
            if payload is not None:
                return _from_identity_payload(base, payload, ident_resp.status_code)
        health_resp, health_err = _try_get(session, health_url)
        if health_resp is not None:
            identity = _from_health_payload(base, _json_object(health_resp), health_resp.status_code)
            if ident_status is not None:
                return HexstrikeIdentity(
                    url=identity.url,
                    source=identity.source,
                    product=identity.product,
                    edition=identity.edition,
                    version=identity.version,
                    v2_enabled=identity.v2_enabled,
                    enhanced_modules=identity.enhanced_modules,
                    rag_backends=identity.rag_backends,
                    engine=identity.engine,
                    pin=identity.pin,
                    identity_status=ident_status,
                    health_status=identity.health_status,
                    error=identity.error,
                )
            return identity
        return _unreachable(base, ident_err or health_err)


def observation_from_probe(
    identity: HexstrikeIdentity,
    *,
    local_path: Path | None = None,
) -> Observation:
    """Map a probe result onto the adapter Observation contract."""
    if identity.source == "none":
        local = local_path
        hint = (
            f"Local tree present at {local}"
            if local and Path(local).exists()
            else "No local HexStrike path"
        )
        detail = identity.error or "unreachable"
        return warn(
            f"HexStrike API unreachable ({detail}). {hint}.",
            root_cause_hint="Start hexstrike_server.py on 127.0.0.1:8888 or stay inventory-only.",
            retry="Start the local HexStrike server, then retry health.",
            stop_condition="Do not fall back to a remote 172.16.x host on an air-gapped engagement.",
            data=identity.as_data(),
        )
    if identity.engine == HEXFORGE_ENGINE:
        return ok(
            f"HexForge {identity.version} identified (edition: {identity.edition})",
            data=identity.as_data(),
            artifacts=[],
        )
    status = identity.health_status if identity.health_status is not None else identity.identity_status
    return ok(
        f"HexStrike health HTTP {status}",
        data=identity.as_data(),
        artifacts=[],
    )


def denied_non_loopback(base_url: str, exc: EgressDenied) -> Observation:
    return err(
        f"SCOPE DENIED: HexStrike engage-path is not loopback ({exc}).",
        root_cause_hint="Engage-path HTTP must be loopback-only.",
        stop_condition="Non-loopback engage path denied.",
        data={"scope_refused": True, "url": base_url, "executed": False, "engine": LEGACY_ENGINE},
    )
