"""Pre-network-action scope guard.

Asserts that a target matches the engagement scope before any network action
is permitted.  Raises ``ScopeViolation`` (never returns a denied Observation)
so callers get a hard stop, not a soft log.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from aetherops.types import Engagement


class ScopeViolation(Exception):
    """Raised when a target is outside the signed engagement scope."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"SCOPE DENIED: {target} — {reason}")


def _normalize_target(raw: str) -> str:
    """Strip scheme, port, path to get a bare hostname or IP."""
    text = (raw or "").strip()
    if not text:
        return text
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or parsed.path
    text = text.split(":")[0].split("/")[0].strip()
    return text


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _cidr_contains(cidr: str, target: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(target)
        return addr in net
    except (ValueError, TypeError):
        return False


def _host_matches(host_pattern: str, target: str) -> bool:
    """Simple glob-free hostname match (exact or wildcard suffix)."""
    pat = host_pattern.strip().lower()
    tgt = target.strip().lower()
    if pat == tgt:
        return True
    if pat.startswith("*."):
        suffix = pat[1:]
        return tgt.endswith(suffix)
    return False


class ScopeGuard:
    """Reusable scope check for an engagement.  Call ``assert_in_scope`` before
    every network action.

    ``assert_in_scope`` raises ``ScopeViolation`` on denial (hard stop).
    ``check`` returns ``True``/``False`` for conditional logic.
    """

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement
        self._cidrs = list(engagement.scope_cidrs or [])
        self._hosts = list(engagement.scope_hosts or [])
        self._oos = list(engagement.out_of_scope or [])

    def check(self, target: str) -> bool:
        """Return True if *target* is in scope."""
        return self._check(target) is None

    def assert_in_scope(self, target: str) -> None:
        """Raise ``ScopeViolation`` if *target* is out of scope."""
        reason = self._check(target)
        if reason:
            raise ScopeViolation(target, reason)

    def _check(self, target: str) -> str | None:
        """Return denial reason string, or None if allowed."""
        bare = _normalize_target(target)
        if not bare:
            return "empty target"

        # Out-of-scope check first
        for oos in self._oos:
            if _host_matches(oos, bare):
                return f"target matches out-of-scope pattern '{oos}'"

        # CIDR matching
        if _is_ip(bare):
            for cidr in self._cidrs:
                if _cidr_contains(cidr, bare):
                    return None
            # If we have CIDRs but none matched
            if self._cidrs:
                return f"IP {bare} not in any scope CIDR"
        else:
            # Hostname matching
            for host in self._hosts:
                if _host_matches(host, bare):
                    return None
            if self._hosts:
                return f"hostname {bare} not in any scope host pattern"

        # If scope lists are empty, deny (never allow blind)
        if not self._cidrs and not self._hosts:
            return "engagement has no scope_cidrs or scope_hosts defined"

        return None
