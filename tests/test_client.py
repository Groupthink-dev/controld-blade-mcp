"""Tests for the Control-D API client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from controld_blade_mcp.client import (
    ControlDClient,
    _classify_error,
    _scrub_credentials,
)
from controld_blade_mcp.models import (
    AuthError,
    Config,
    ControlDConnectionError,
    ControlDError,
    NotFoundError,
    RateLimitError,
)


class TestScrubCredentials:
    def test_scrub_bearer_token(self) -> None:
        text = "Authorization: Bearer abc123def456"
        result = _scrub_credentials(text)
        assert "abc123" not in result
        assert "****" in result

    def test_scrub_api_key_param(self) -> None:
        text = "url?api_key=secret123&other=value"
        result = _scrub_credentials(text)
        assert "secret123" not in result
        assert "api_key=****" in result

    def test_no_credentials(self) -> None:
        text = "simple error message"
        assert _scrub_credentials(text) == text


class TestClassifyError:
    def test_auth_error(self) -> None:
        assert isinstance(_classify_error("unauthorized access"), AuthError)
        assert isinstance(_classify_error("Authentication failed"), AuthError)
        assert isinstance(_classify_error("Forbidden"), AuthError)

    def test_not_found(self) -> None:
        assert isinstance(_classify_error("Resource not found"), NotFoundError)
        assert isinstance(_classify_error("Profile does not exist"), NotFoundError)

    def test_rate_limit(self) -> None:
        assert isinstance(_classify_error("Rate limit exceeded"), RateLimitError)
        assert isinstance(_classify_error("Too many requests"), RateLimitError)

    def test_connection_error(self) -> None:
        assert isinstance(_classify_error("Connection refused"), ControlDConnectionError)
        assert isinstance(_classify_error("Request timeout"), ControlDConnectionError)

    def test_generic_error(self) -> None:
        err = _classify_error("Something unexpected")
        assert type(err) is ControlDError


class TestControlDClient:
    @pytest.fixture
    def client(self) -> ControlDClient:
        config = Config(api_key="test-key", write_enabled=False)
        return ControlDClient(config)

    def test_init(self, client: ControlDClient) -> None:
        assert client._config.api_key == "test-key"
        assert client._http is not None

    def test_parse_response_success(self, client: ControlDClient) -> None:
        response = MagicMock(spec=httpx.Response)
        response.json.return_value = {"success": True, "body": {"profiles": []}}
        result = client._parse_response(response)
        assert result == {"profiles": []}

    def test_parse_response_error(self, client: ControlDClient) -> None:
        response = MagicMock(spec=httpx.Response)
        response.json.return_value = {
            "success": False,
            "error": {"message": "Profile not found"},
        }
        with pytest.raises(NotFoundError):
            client._parse_response(response)

    def test_parse_response_non_json(self, client: ControlDClient) -> None:
        response = MagicMock(spec=httpx.Response)
        response.json.side_effect = ValueError("No JSON")
        response.text = "<html>Internal Server Error</html>"
        response.status_code = 500
        with pytest.raises(ControlDError, match="Non-JSON"):
            client._parse_response(response)

    def test_parse_response_auth_error(self, client: ControlDClient) -> None:
        response = MagicMock(spec=httpx.Response)
        response.json.return_value = {
            "success": False,
            "error": {"message": "Unauthorized"},
        }
        with pytest.raises(AuthError):
            client._parse_response(response)

    def test_list_profiles(self, client: ControlDClient) -> None:
        profiles = [{"PK": "p1", "name": "Test"}]
        with patch.object(client, "_request", return_value=profiles):
            result = client.list_profiles()
            assert result == profiles

    def test_list_profiles_wrapped(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={"profiles": [{"PK": "p1"}]}):
            result = client.list_profiles()
            assert len(result) == 1

    def test_list_filters_merges(self, client: ControlDClient) -> None:
        native = [{"PK": "ads", "status": 1}]
        external = [{"PK": "ext1", "status": 0}]
        with patch.object(client, "_request", side_effect=[native, external]):
            result = client.list_filters("profile1")
            assert "native" in result
            assert "external" in result

    def test_create_profile(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={"PK": "new"}) as mock:
            client.create_profile("New Profile")
            mock.assert_called_once_with("POST", "/profiles", data={"name": "New Profile"})

    def test_create_profile_with_clone(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={"PK": "new"}) as mock:
            client.create_profile("Clone", clone_profile_id="p1")
            mock.assert_called_once_with("POST", "/profiles", data={"name": "Clone", "clone_from": "p1"})

    def test_update_profile_partial(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={}) as mock:
            client.update_profile("p1", name="Renamed")
            mock.assert_called_once_with("PUT", "/profiles/p1", data={"name": "Renamed"})

    def test_create_rule(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={}) as mock:
            client.create_rule("p1", ["example.com", "test.com"], 0)
            call_data = mock.call_args[1]["data"]
            assert call_data["hostnames[0]"] == "example.com"
            assert call_data["hostnames[1]"] == "test.com"
            assert call_data["do"] == 0

    def test_delete_rule(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={}) as mock:
            client.delete_rule("p1", "example.com")
            mock.assert_called_once_with("DELETE", "/profiles/p1/rules/example.com")

    def test_service_catalog_cache(self, client: ControlDClient) -> None:
        with patch.object(client, "_request", return_value={"categories": []}) as mock:
            client.get_service_catalog()
            client.get_service_catalog()
            assert mock.call_count == 2  # First call makes 2 requests (categories + proxies)
