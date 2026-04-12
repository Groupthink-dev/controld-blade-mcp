"""Tests for configuration, write gates, and exceptions."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from controld_blade_mcp.models import (
    AuthError,
    Config,
    ControlDError,
    is_write_enabled,
    require_confirm,
    require_write,
    resolve_config,
)


class TestResolveConfig:
    def test_valid_config(self) -> None:
        env = {"CONTROLD_API_KEY": "test-key-123", "CONTROLD_WRITE_ENABLED": "true"}
        with patch.dict("os.environ", env, clear=True):
            config = resolve_config()
            assert config.api_key == "test-key-123"
            assert config.write_enabled is True

    def test_missing_api_key(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="CONTROLD_API_KEY"):
                resolve_config()

    def test_empty_api_key(self) -> None:
        with patch.dict("os.environ", {"CONTROLD_API_KEY": "  "}, clear=True):
            with pytest.raises(ValueError, match="CONTROLD_API_KEY"):
                resolve_config()

    def test_write_disabled_by_default(self) -> None:
        env = {"CONTROLD_API_KEY": "key"}
        with patch.dict("os.environ", env, clear=True):
            config = resolve_config()
            assert config.write_enabled is False

    def test_write_case_insensitive(self) -> None:
        env = {"CONTROLD_API_KEY": "key", "CONTROLD_WRITE_ENABLED": "TRUE"}
        with patch.dict("os.environ", env, clear=True):
            config = resolve_config()
            assert config.write_enabled is True


class TestWriteGate:
    def test_write_disabled(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            assert is_write_enabled() is False
            result = require_write()
            assert result is not None
            assert "Error" in result

    def test_write_enabled(self) -> None:
        with patch.dict("os.environ", {"CONTROLD_WRITE_ENABLED": "true"}):
            assert is_write_enabled() is True
            result = require_write()
            assert result is None


class TestConfirmGate:
    def test_not_confirmed(self) -> None:
        result = require_confirm(False, "Deleting a rule")
        assert result is not None
        assert "confirm=true" in result
        assert "Deleting a rule" in result

    def test_confirmed(self) -> None:
        result = require_confirm(True, "Deleting a rule")
        assert result is None


class TestExceptions:
    def test_base_error(self) -> None:
        err = ControlDError("something failed", details="extra info")
        assert str(err) == "something failed"
        assert err.details == "extra info"

    def test_auth_error_is_controld_error(self) -> None:
        err = AuthError("unauthorized")
        assert isinstance(err, ControlDError)

    def test_config_dataclass(self) -> None:
        config = Config(api_key="key", write_enabled=True)
        assert config.api_key == "key"
        assert config.write_enabled is True
