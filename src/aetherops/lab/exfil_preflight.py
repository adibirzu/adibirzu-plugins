"""Box-route exfil preflight. Do not silently drop the rule.

Operators must prove the guest has no public default route, or record an
explicit ROE waiver token. The HTTP airlock stays loopback-only either way.
"""

from __future__ import annotations

from aetherops.types import Engagement, Observation

BOX_ROUTE_EXFIL_WAIVER = "box-route-exfil-waived-this-run"
CLOUD_LLM_FALLBACK_WAIVER = "cloud-llm-fallback-waived-this-run"


def _roe_tokens(engagement: Engagement) -> list[str]:
    return [str(item).strip() for item in (engagement.roe or [])]


def has_box_route_waiver(engagement: Engagement) -> bool:
    return BOX_ROUTE_EXFIL_WAIVER in _roe_tokens(engagement)


def has_cloud_llm_fallback_waiver(engagement: Engagement) -> bool:
    return CLOUD_LLM_FALLBACK_WAIVER in _roe_tokens(engagement)


def check_box_route_exfil(
    engagement: Engagement,
    *,
    public_default_route: bool,
) -> Observation:
    """Fail closed when the guest can reach the public internet unless waived."""
    waived = has_box_route_waiver(engagement)
    if public_default_route and not waived:
        return Observation(
            status="error",
            summary="STOP: guest has a public default route and ROE has no box-route waiver.",
            stop_condition="STOP. Isolate the guest or record box-route-exfil-waived-this-run on the signed ROE.",
            data={
                "public_default_route": True,
                "waived": False,
                "executed": False,
                "airlock": "loopback-only",
            },
        )
    if public_default_route and waived:
        return Observation(
            status="warning",
            summary="Box-route exfil stop waived for this run; HTTP airlock stays loopback-only.",
            data={
                "public_default_route": True,
                "waived": True,
                "waiver": BOX_ROUTE_EXFIL_WAIVER,
                "executed": False,
                "airlock": "loopback-only",
            },
            next_actions=["Do not treat the waiver as a general RFC1918 hole"],
        )
    return Observation(
        status="success",
        summary="Guest has no public default route.",
        data={
            "public_default_route": False,
            "waived": waived,
            "executed": False,
            "airlock": "loopback-only",
        },
    )
