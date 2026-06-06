"""CONV-29 ``_meta`` audit-tail envelope tests (S-AUD-001).

Every successful tool return carries the canonical ``_meta: {...}`` JSON tail
appended after a blank line; error / write-gate / confirm-gate returns stay
plain. These exercise one representative read tool, the write tools (gate +
success), and an error path through the server layer (the client is mocked).
"""

from __future__ import annotations

import json
import re
from typing import Any
from unittest.mock import MagicMock

import pytest

from controld_blade_mcp.models import ControlDError
from controld_blade_mcp.server import (
    cd_access_update,
    cd_devices,
    cd_profiles,
    cd_rule_create,
    cd_rule_delete,
)
from tests.conftest import make_device, make_profile

_META_RE = re.compile(r"\n\n_meta: (\{.*\})\s*$", re.DOTALL)


def _split_meta(out: str) -> tuple[str, dict[str, Any]]:
    """Split a tool output into (payload, parsed_meta_json). Asserts presence."""
    m = _META_RE.search(out)
    assert m is not None, f"expected a _meta tail, got: {out!r}"
    return out[: m.start()], json.loads(m.group(1))


def _assert_no_meta(out: str) -> None:
    assert _META_RE.search(out) is None, f"did not expect a _meta tail, got: {out!r}"


class TestMetaTail:
    async def test_read_tool_carries_meta(self, mock_client: MagicMock) -> None:
        mock_client.list_profiles.return_value = [make_profile(), make_profile(pk="p2", name="Kids")]
        payload, meta = _split_meta(await cd_profiles())
        assert "Main Profile" in payload and "Kids" in payload
        assert meta["matched_total"] == 2
        assert meta["returned"] == 2
        assert "latency_ms" in meta

    async def test_empty_read_still_carries_meta(self, mock_client: MagicMock) -> None:
        mock_client.list_devices.return_value = []
        payload, meta = _split_meta(await cd_devices())
        assert payload == "(no devices)"
        assert meta["matched_total"] == 0

    async def test_write_success_carries_meta_with_target(
        self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CONTROLD_WRITE_ENABLED", "true")
        mock_client.create_rule.return_value = {"message": "created"}
        out = await cd_rule_create(profile_id="abc123", hostnames=["a.com", "b.com"], action=0)
        payload, meta = _split_meta(out)
        assert payload.startswith("OK:")
        assert meta["target_id"] == "abc123"
        assert meta["rows_affected"] == 2

    async def test_delete_success_carries_meta(self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_WRITE_ENABLED", "true")
        mock_client.delete_rule.return_value = {"message": "deleted"}
        out = await cd_rule_delete(profile_id="abc123", hostname="x.com", confirm=True)
        _, meta = _split_meta(out)
        assert meta["target_id"] == "x.com"
        assert meta["rows_affected"] == 1

    async def test_device_create_dict_path_carries_meta(
        self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from controld_blade_mcp.server import cd_device_create

        monkeypatch.setenv("CONTROLD_WRITE_ENABLED", "true")
        mock_client.create_device.return_value = make_device()
        payload, meta = _split_meta(await cd_device_create(name="Mac", profile_id="abc123"))
        assert "Device:" in payload
        assert meta["target_id"] == "dev001"


class TestPlainPaths:
    """Gate / confirm / error returns must NOT carry a _meta tail."""

    async def test_write_gate_is_plain(self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CONTROLD_WRITE_ENABLED", raising=False)
        out = await cd_rule_create(profile_id="abc123", hostnames=["a.com"], action=0)
        assert out.startswith("Error: Write operations are disabled")
        _assert_no_meta(out)

    async def test_confirm_gate_is_plain(self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_WRITE_ENABLED", "true")
        out = await cd_rule_delete(profile_id="abc123", hostname="x.com", confirm=False)
        assert "requires explicit confirmation" in out
        _assert_no_meta(out)

    async def test_error_path_is_plain(self, mock_client: MagicMock) -> None:
        mock_client.list_profiles.side_effect = ControlDError("boom")
        out = await cd_profiles()
        assert out.startswith("Error:")
        _assert_no_meta(out)

    async def test_invalid_action_is_plain(self, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_WRITE_ENABLED", "true")
        out = await cd_access_update(device_id="dev001", ips=["1.1.1.1"], action="nonsense", confirm=True)
        assert out.startswith("Error: action must be")
        _assert_no_meta(out)
