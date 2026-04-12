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


def make_profile(
    pk: str = "abc123",
    name: str = "Main Profile",
    stats: dict[str, Any] | None = None,
    lock: int = 0,
) -> dict[str, Any]:
    """Build a mock profile dict."""
    return {
        "PK": pk,
        "name": name,
        "stats": stats or {"rules": 47, "devices": 3, "filters": 8},
        "lock": lock,
    }


def make_device(
    pk: str = "dev001",
    name: str = "MacBook Pro",
    profile_id: str = "abc123",
    profile_name: str = "Main Profile",
    device_type: str = "macos",
    status: int = 1,
) -> dict[str, Any]:
    """Build a mock device dict."""
    return {
        "PK": pk,
        "name": name,
        "profile": {"PK": profile_id, "name": profile_name},
        "profile_id": profile_id,
        "device_type": device_type,
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
    group: int | None = None,
) -> dict[str, Any]:
    """Build a mock custom rule dict."""
    result: dict[str, Any] = {"PK": pk, "do": action}
    if via:
        result["via"] = via
    if group is not None:
        result["group"] = group
    return result


def make_filter(
    pk: str = "ads",
    name: str = "Ads & Trackers",
    status: int = 1,
) -> dict[str, Any]:
    """Build a mock filter dict."""
    return {"PK": pk, "title": name, "status": status}


def make_service(
    pk: str = "youtube",
    name: str = "YouTube",
    action: int = 1,
    category: str = "Video Streaming",
) -> dict[str, Any]:
    """Build a mock service rule dict."""
    return {
        "PK": pk,
        "name": name,
        "do": action,
        "category": {"name": category},
    }


def make_access_entry(
    ip: str = "203.0.113.1",
    ts: str = "2026-04-12T10:30:00",
    country: str = "AU",
) -> dict[str, Any]:
    """Build a mock IP access entry."""
    return {"ip": ip, "ts": ts, "country": country}
