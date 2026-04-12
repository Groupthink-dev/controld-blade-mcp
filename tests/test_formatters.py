"""Tests for token-efficient output formatters."""

from __future__ import annotations

from controld_blade_mcp.formatters import (
    _action_label,
    _on_off,
    _safe,
    _truncate,
    format_access,
    format_analytics_config,
    format_default_rule,
    format_devices,
    format_filters,
    format_info,
    format_network,
    format_profiles,
    format_rules,
    format_services,
    format_write_result,
)
from tests.conftest import (
    make_access_entry,
    make_device,
    make_filter,
    make_profile,
    make_rule,
    make_service,
)


class TestHelpers:
    def test_safe_none(self) -> None:
        assert _safe(None) == ""

    def test_safe_value(self) -> None:
        assert _safe(42) == "42"

    def test_truncate_short(self) -> None:
        assert _truncate("hello") == "hello"

    def test_truncate_long(self) -> None:
        result = _truncate("a" * 250, max_len=100)
        assert len(result) == 100
        assert result.endswith("...")

    def test_action_labels(self) -> None:
        assert _action_label(0) == "BLOCK"
        assert _action_label(1) == "BYPASS"
        assert _action_label(2) == "SPOOF"
        assert _action_label(3) == "REDIRECT"
        assert "UNKNOWN" in _action_label(99)

    def test_on_off(self) -> None:
        assert _on_off(1) == "ON"
        assert _on_off(0) == "OFF"
        assert _on_off(None) == ""


class TestFormatInfo:
    def test_basic_info(self) -> None:
        user = {"email": "test@example.com", "status": 1, "tfa": 1}
        ip_data = {"ip": "1.2.3.4", "datacenter": "syd"}
        result = format_info(user, ip_data)
        assert "test@example.com" in result
        assert "active" in result
        assert "1.2.3.4" in result
        assert "syd" in result

    def test_empty_info(self) -> None:
        assert format_info({}, {}) == "(no account info)"


class TestFormatNetwork:
    def test_empty(self) -> None:
        assert format_network({}) == "(no network data)"

    def test_with_data(self) -> None:
        result = format_network({"dns": {"status": "operational", "latency": 5}})
        assert "dns" in result
        assert "operational" in result


class TestFormatProfiles:
    def test_empty(self) -> None:
        assert format_profiles([]) == "(no profiles)"

    def test_single_profile(self) -> None:
        result = format_profiles([make_profile()])
        assert "abc123" in result
        assert "Main Profile" in result
        assert "rules: 47" in result

    def test_locked_profile(self) -> None:
        result = format_profiles([make_profile(lock=1)])
        assert "locked" in result

    def test_multiple_profiles(self) -> None:
        profiles = [make_profile(pk="p1", name="Alpha"), make_profile(pk="p2", name="Beta")]
        result = format_profiles(profiles)
        assert "Alpha" in result
        assert "Beta" in result
        assert result.count("\n") == 1


class TestFormatFilters:
    def test_native_only(self) -> None:
        native = [make_filter(pk="ads", status=1), make_filter(pk="malware", status=0)]
        result = format_filters(native, [])
        assert "1/2 enabled" in result
        assert "ads" in result

    def test_with_external(self) -> None:
        native = [make_filter()]
        external = [make_filter(pk="ext1", name="Custom List", status=1)]
        result = format_filters(native, external)
        assert "Native Filters" in result
        assert "External Filters" in result

    def test_dict_wrapper(self) -> None:
        result = format_filters({"filters": [make_filter()]}, {"filters": []})
        assert "1/1 enabled" in result


class TestFormatServices:
    def test_empty(self) -> None:
        assert format_services([]) == "(no active service rules)"

    def test_with_services(self) -> None:
        result = format_services([make_service(), make_service(pk="tiktok", name="TikTok", action=0)])
        assert "YouTube" in result
        assert "BYPASS" in result
        assert "TikTok" in result
        assert "BLOCK" in result


class TestFormatRules:
    def test_empty(self) -> None:
        assert format_rules([]) == "(no custom rules)"

    def test_block_rule(self) -> None:
        result = format_rules([make_rule()])
        assert "example.com" in result
        assert "BLOCK" in result

    def test_spoof_rule(self) -> None:
        result = format_rules([make_rule(pk="netflix.com", action=2, via="uk-lon")])
        assert "SPOOF -> uk-lon" in result

    def test_with_folders(self) -> None:
        folders = [{"PK": 1, "name": "Ads"}]
        rules = [make_rule(group=1)]
        result = format_rules(rules, folders)
        assert "folder: Ads" in result


class TestFormatDefaultRule:
    def test_block(self) -> None:
        result = format_default_rule({"do": 0, "status": 1})
        assert "BLOCK" in result
        assert "ON" in result

    def test_spoof_with_via(self) -> None:
        result = format_default_rule({"do": 2, "via": "de-fra"})
        assert "SPOOF -> de-fra" in result


class TestFormatDevices:
    def test_empty(self) -> None:
        assert format_devices([]) == "(no devices)"

    def test_single_device(self) -> None:
        result = format_devices([make_device()])
        assert "dev001" in result
        assert "MacBook Pro" in result
        assert "Main Profile" in result
        assert "macos" in result

    def test_multiple(self) -> None:
        devices = [make_device(pk="d1", name="Mac"), make_device(pk="d2", name="Router")]
        result = format_devices(devices)
        assert result.count("\n") == 1


class TestFormatAccess:
    def test_empty(self) -> None:
        assert format_access([]) == "(no IPs recorded)"

    def test_with_entries(self) -> None:
        result = format_access([make_access_entry()])
        assert "203.0.113.1" in result
        assert "AU" in result


class TestFormatAnalyticsConfig:
    def test_empty(self) -> None:
        assert format_analytics_config([], []) == "(no analytics configuration)"

    def test_with_data(self) -> None:
        levels = [{"PK": "full", "description": "Full query logging"}]
        endpoints = [{"PK": "syd", "location": "Sydney"}]
        result = format_analytics_config(levels, endpoints)
        assert "Log Levels" in result
        assert "Storage Regions" in result
        assert "full" in result
        assert "Sydney" in result


class TestFormatWriteResult:
    def test_with_message(self) -> None:
        result = format_write_result({"message": "Profile created"}, "create")
        assert result == "OK: Profile created"

    def test_fallback(self) -> None:
        result = format_write_result({}, "Profile created")
        assert "OK: Profile created" in result
