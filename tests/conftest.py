"""Shared test fixtures and mock builders."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from controld_blade_mcp.models import Config


@pytest.fixture
def config() -> Config:
    """Test configuration."""
    return Config(api_key="test-api-key-1234", write_enabled=False)


@pytest.fixture
def write_config() -> Config:
    """Test configuration with writes enabled."""
    return Config(api_key="test-api-key-1234", write_enabled=True)


@pytest.fixture
def mock_client() -> MagicMock:
    """Mock ControlDClient with patched singleton."""
    from unittest.mock import patch

    client = MagicMock()
    with patch("controld_blade_mcp.server._get_client", return_value=client):
        yield client


# ── Mock data builders ──────────────────────────────────────────────


# NOTE (DD-385 Phase 2): these builders encode the SHAPES CAPTURED FROM THE LIVE
# Control-D API on 2026-06-06 — not docs, not guesses. The pre-hardening mocks
# encoded wrong shapes (flat `do`, `stats.{rules,devices}`, top-level filter
# `status`) and a 100%-green suite shipped a fully-broken formatter layer.


def make_profile(
    pk: str = "abc123",
    name: str = "Main Profile",
    counts: dict[str, int] | None = None,
    lock: int | None = None,
) -> dict[str, Any]:
    """Build a mock profile dict (live shape: counts nest under ``profile``)."""
    counts = counts or {"flt": 8, "rule": 47, "svc": 1, "grp": 4}
    return {
        "PK": pk,
        "name": name,
        "lock": lock,
        "profile": {key: {"count": val} for key, val in counts.items()},
    }


def make_device(
    pk: str = "dev001",
    name: str = "MacBook Pro",
    profile_id: str = "abc123",
    profile_name: str = "Main Profile",
    icon: str = "desktop-mac",
    status: int = 1,
) -> dict[str, Any]:
    """Build a mock device dict (live shape: device class is ``icon``)."""
    return {
        "PK": pk,
        "name": name,
        "profile": {"PK": profile_id, "name": profile_name},
        "icon": icon,
        "status": status,
        "resolvers": {
            "doh": f"https://dns.controld.com/{pk}",
            "dot": f"{pk}.dns.controld.com",
        },
    }


def make_rule(
    pk: str = "example.com",
    action: int = 0,
    via: str = "",
    group: int = 0,
) -> dict[str, Any]:
    """Build a mock custom rule dict.

    Live shape: ``{PK, order, group, action: {do, status, via}}`` — for a rule
    the spoof/redirect target nests under ``action.via`` (services instead use
    a top-level ``unlock_location``).
    """
    act: dict[str, Any] = {"do": action, "status": 1}
    if via:
        act["via"] = via
    return {"PK": pk, "order": 1, "group": group, "action": act}


def make_filter(
    pk: str = "ads",
    name: str = "Ads & Trackers",
    status: int = 1,
) -> dict[str, Any]:
    """Build a mock native filter dict (live shape: enabled state is per-``levels``)."""
    return {
        "PK": pk,
        "name": name,
        "levels": [
            {"title": "Relaxed", "name": f"{pk}_small", "status": status},
            {"title": "Strict", "name": f"{pk}_big", "status": 0},
        ],
    }


def make_service(
    pk: str = "youtube",
    name: str = "YouTube",
    action: int = 1,
    category: str = "video",
    status: int = 1,
) -> dict[str, Any]:
    """Build a mock service rule dict (live shape: ``action.{do,status}`` + string category)."""
    return {
        "PK": pk,
        "name": name,
        "category": category,
        "unlock_location": "JFK",
        "action": {"do": action, "status": status},
    }


def make_access_entry(
    ip: str = "203.0.113.1",
    ts: str = "2026-04-12T10:30:00",
    country: str = "AU",
) -> dict[str, Any]:
    """Build a mock IP access entry.

    The live ``/access`` list was empty on the audited account, so this item
    shape (ip/ts/country) is NOT live-verified — flagged for the e2e tier.
    """
    return {"ip": ip, "ts": ts, "country": country}
