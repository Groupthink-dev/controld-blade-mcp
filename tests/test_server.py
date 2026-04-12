"""Tests for MCP tool behavior."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from controld_blade_mcp.server import (
    cd_access,
    cd_analytics_config,
    cd_default_rule,
    cd_device_create,
    cd_devices,
    cd_filters,
    cd_info,
    cd_network,
    cd_profile,
    cd_profile_create,
    cd_profiles,
    cd_rule_create,
    cd_rule_delete,
    cd_rules,
    cd_services,
)
from tests.conftest import make_access_entry, make_device, make_profile, make_rule, make_service


class TestReadTools:
    async def test_cd_info(self, mock_client: MagicMock) -> None:
        mock_client.get_user.return_value = {"email": "test@example.com", "status": 1}
        mock_client.get_ip.return_value = {"ip": "1.2.3.4", "datacenter": "syd"}
        result = await cd_info()
        assert "test@example.com" in result
        assert "1.2.3.4" in result

    async def test_cd_network(self, mock_client: MagicMock) -> None:
        mock_client.get_network.return_value = {"dns": {"status": "operational"}}
        result = await cd_network()
        assert "operational" in result

    async def test_cd_profiles(self, mock_client: MagicMock) -> None:
        mock_client.list_profiles.return_value = [make_profile()]
        result = await cd_profiles()
        assert "Main Profile" in result

    async def test_cd_profile(self, mock_client: MagicMock) -> None:
        mock_client.list_profiles.return_value = [make_profile()]
        mock_client.get_profile_options.return_value = []
        result = await cd_profile(profile_id="abc123")
        assert "Main Profile" in result

    async def test_cd_profile_not_found(self, mock_client: MagicMock) -> None:
        mock_client.list_profiles.return_value = [make_profile()]
        result = await cd_profile(profile_id="nonexistent")
        assert "Error" in result

    async def test_cd_filters(self, mock_client: MagicMock) -> None:
        mock_client.list_filters.return_value = {
            "native": [{"PK": "ads", "title": "Ads", "status": 1}],
            "external": [],
        }
        result = await cd_filters(profile_id="p1")
        assert "ads" in result

    async def test_cd_services(self, mock_client: MagicMock) -> None:
        mock_client.list_services.return_value = [make_service()]
        result = await cd_services(profile_id="p1")
        assert "YouTube" in result

    async def test_cd_rules(self, mock_client: MagicMock) -> None:
        mock_client.list_rules.return_value = [make_rule()]
        mock_client.list_rule_folders.return_value = []
        result = await cd_rules(profile_id="p1")
        assert "example.com" in result

    async def test_cd_default_rule(self, mock_client: MagicMock) -> None:
        mock_client.get_default_rule.return_value = {"do": 0, "status": 1}
        result = await cd_default_rule(profile_id="p1")
        assert "BLOCK" in result

    async def test_cd_devices(self, mock_client: MagicMock) -> None:
        mock_client.list_devices.return_value = [make_device()]
        result = await cd_devices()
        assert "MacBook Pro" in result

    async def test_cd_access(self, mock_client: MagicMock) -> None:
        mock_client.list_access.return_value = [make_access_entry()]
        result = await cd_access(device_id="dev1")
        assert "203.0.113.1" in result

    async def test_cd_analytics_config(self, mock_client: MagicMock) -> None:
        mock_client.get_analytics_levels.return_value = [{"PK": "full"}]
        mock_client.get_analytics_endpoints.return_value = [{"PK": "syd"}]
        result = await cd_analytics_config()
        assert "full" in result


class TestWriteToolsBlocked:
    """Write tools must return an error when CONTROLD_WRITE_ENABLED is not set."""

    async def test_profile_create_blocked(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value="Error: disabled"):
            result = await cd_profile_create(name="Test")
            assert "Error" in result
            mock_client.create_profile.assert_not_called()

    async def test_rule_create_blocked(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value="Error: disabled"):
            result = await cd_rule_create(profile_id="p1", hostnames=["example.com"], action=0)
            assert "Error" in result

    async def test_rule_delete_blocked(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value="Error: disabled"):
            result = await cd_rule_delete(profile_id="p1", hostname="example.com", confirm=True)
            assert "Error" in result

    async def test_device_create_blocked(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value="Error: disabled"):
            result = await cd_device_create(name="Test", profile_id="p1")
            assert "Error" in result


class TestWriteToolsAllowed:
    """Write tools must succeed when write gate returns None."""

    async def test_profile_create(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value=None):
            mock_client.create_profile.return_value = {"message": "Profile created"}
            result = await cd_profile_create(name="New")
            assert "OK" in result

    async def test_rule_create(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value=None):
            mock_client.create_rule.return_value = {"message": "Rule created"}
            result = await cd_rule_create(profile_id="p1", hostnames=["test.com"], action=0)
            assert "OK" in result

    async def test_rule_delete_requires_confirm(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value=None):
            result = await cd_rule_delete(profile_id="p1", hostname="test.com", confirm=False)
            assert "confirm=true" in result
            mock_client.delete_rule.assert_not_called()

    async def test_rule_delete_confirmed(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value=None):
            mock_client.delete_rule.return_value = {"message": "Deleted"}
            result = await cd_rule_delete(profile_id="p1", hostname="test.com", confirm=True)
            assert "OK" in result

    async def test_device_create(self, mock_client: MagicMock) -> None:
        with patch("controld_blade_mcp.server.require_write", return_value=None):
            mock_client.create_device.return_value = make_device()
            result = await cd_device_create(name="Router", profile_id="p1")
            assert "OK" in result
