"""Loopback-only HTTP session for the engagement path.

Chat, adapters, and any future validator talk only to loopback. This module
raises before a socket is opened if the URL host is not loopback. It does
not resolve public DNS names (that would itself be egress).

`aetherops evolve` does not use this session — it is GET-only to exact
allowlisted URLs (see `aetherops.evolve.updater`).
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Self
from urllib.parse import urlparse

import httpx

LOOPBACK_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)


class EgressDenied(ValueError):
    """Engage-path request targeted a host outside loopback."""


def is_loopback_host(host: str | None) -> bool:
    """True only for literal loopback names or addresses. No DNS lookup."""
    raw = (host or "").strip().lower()
    if not raw:
        return False
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    if raw in LOOPBACK_NAMES:
        return True
    try:
        return ip_address(raw).is_loopback
    except ValueError:
        return False


def assert_loopback_url(url: str) -> str:
    """Raise EgressDenied unless `url` is http(s) to a loopback host."""
    if not url or not isinstance(url, str):
        raise EgressDenied("engage-path refuses empty URL")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise EgressDenied(f"engage-path refuses scheme {parsed.scheme or 'missing'!r}")
    if parsed.username or parsed.password:
        raise EgressDenied("engage-path refuses URLs with userinfo")
    host = parsed.hostname
    if not host:
        raise EgressDenied("engage-path URL has no host")
    if not is_loopback_host(host):
        raise EgressDenied(f"engage-path refuses non-loopback host {host!r}")
    return url


class EgressSession:
    """httpx-shaped client that refuses any host outside loopback.

    Pass `client=` to reuse an injected test double; the URL is still
    checked first. Redirects are never followed.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.timeout = timeout
        self._transport = transport
        self._external = client

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        assert_loopback_url(url)
        if self._external is not None:
            return self._external.request(method, url, **kwargs)
        client_kwargs: dict[str, object] = {
            "timeout": self.timeout,
            "follow_redirects": False,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport
        with httpx.Client(**client_kwargs) as client:
            return client.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: object) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: object) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: object) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)
