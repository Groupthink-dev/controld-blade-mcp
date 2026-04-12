"""Control-D API client with retry, error classification, and credential scrubbing."""

from __future__ import annotations

import logging
import random
import re
import time
from typing import Any

import httpx

from controld_blade_mcp.models import (
    AuthError,
    Config,
    ControlDConnectionError,
    ControlDError,
    NotFoundError,
    RateLimitError,
    resolve_config,
)

logger = logging.getLogger(__name__)

BASE_URL = "https://api.controld.com"

_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE = 1.0
_RETRY_MAX = 30.0
_TIMEOUT = 30.0

# ── Error classification ────────────────────────────────────────────

_ERROR_PATTERNS: list[tuple[str, type[ControlDError]]] = [
    ("unauthorized", AuthError),
    ("authentication", AuthError),
    ("forbidden", AuthError),
    ("invalid api key", AuthError),
    ("not found", NotFoundError),
    ("does not exist", NotFoundError),
    ("rate limit", RateLimitError),
    ("too many requests", RateLimitError),
    ("connection", ControlDConnectionError),
    ("timeout", ControlDConnectionError),
]


def _classify_error(message: str) -> ControlDError:
    """Classify an error message into a specific exception type."""
    lower = message.lower()
    for pattern, exc_cls in _ERROR_PATTERNS:
        if pattern in lower:
            return exc_cls(message)
    return ControlDError(message)


def _scrub_credentials(text: str) -> str:
    """Remove API keys and sensitive data from error text."""
    text = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer ****", text)
    text = re.sub(r"api[_-]?key=[^\s&]+", "api_key=****", text, flags=re.IGNORECASE)
    return text


# ── Service catalog cache ───────────────────────────────────────────

_catalog_cache: dict[str, Any] | None = None
_catalog_ts: float = 0.0
_CATALOG_TTL = 3600.0  # 1 hour


# ── Client ──────────────────────────────────────────────────────────


class ControlDClient:
    """Synchronous Control-D API client."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or resolve_config()
        self._http = httpx.Client(
            base_url=BASE_URL,
            headers={
                "Authorization": f"Bearer {self._config.api_key}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    # ── HTTP primitives ─────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an API request with retry and error handling."""
        last_error: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                if json_body is not None:
                    response = self._http.request(method, path, json=json_body, params=params)
                elif data is not None:
                    response = self._http.request(method, path, data=data, params=params)
                else:
                    response = self._http.request(method, path, params=params)

                if response.status_code in _RETRY_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                    delay = min(_RETRY_BASE * (2**attempt) + random.uniform(0, 1), _RETRY_MAX)
                    retry_after = response.headers.get("retry-after")
                    if retry_after:
                        try:
                            delay = max(delay, float(retry_after))
                        except ValueError:
                            pass
                    time.sleep(delay)
                    continue

                return self._parse_response(response)

            except httpx.ConnectError as e:
                last_error = ControlDConnectionError(_scrub_credentials(str(e)))
                if attempt < _MAX_RETRIES - 1:
                    delay = min(_RETRY_BASE * (2**attempt) + random.uniform(0, 1), _RETRY_MAX)
                    time.sleep(delay)
                    continue
            except httpx.TimeoutException as e:
                last_error = ControlDConnectionError(f"Request timed out: {_scrub_credentials(str(e))}")
                if attempt < _MAX_RETRIES - 1:
                    delay = min(_RETRY_BASE * (2**attempt) + random.uniform(0, 1), _RETRY_MAX)
                    time.sleep(delay)
                    continue

        if last_error:
            raise last_error
        raise ControlDError("Request failed after retries")

    def _parse_response(self, response: httpx.Response) -> dict[str, Any]:
        """Parse API envelope: { body, success, error }."""
        try:
            data = response.json()
        except ValueError:
            text = _scrub_credentials(response.text[:200])
            raise ControlDError(f"Non-JSON response (HTTP {response.status_code}): {text}")

        if not isinstance(data, dict):
            raise ControlDError(f"Unexpected response format (HTTP {response.status_code})")

        if not data.get("success", False):
            error = data.get("error", {})
            msg = error.get("message", "Unknown API error") if isinstance(error, dict) else str(error)
            raise _classify_error(_scrub_credentials(str(msg)))

        body: dict[str, Any] = data.get("body", {})
        return body

    @staticmethod
    def _as_list(body: dict[str, Any] | list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        """Extract a list from an API response body."""
        if isinstance(body, list):
            return body
        result = body.get(key, [])
        return result if isinstance(result, list) else []

    # ── Info ────────────────────────────────────────────────────────

    def get_user(self) -> dict[str, Any]:
        """Get account information."""
        return self._request("GET", "/users")

    def get_ip(self) -> dict[str, Any]:
        """Get caller IP and datacenter."""
        return self._request("GET", "/ip")

    def get_network(self) -> dict[str, Any]:
        """Get network stats for services across PoPs."""
        return self._request("GET", "/network")

    # ── Profiles ────────────────────────────────────────────────────

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all profiles."""
        body = self._request("GET", "/profiles")
        return self._as_list(body, "profiles")

    def get_profile_options(self) -> list[dict[str, Any]]:
        """List configurable profile options."""
        body = self._request("GET", "/profiles/options")
        return self._as_list(body, "options")

    def create_profile(self, name: str, clone_profile_id: str | None = None) -> dict[str, Any]:
        """Create a new profile (blank or cloned)."""
        data: dict[str, Any] = {"name": name}
        if clone_profile_id:
            data["clone_from"] = clone_profile_id
        return self._request("POST", "/profiles", data=data)

    def update_profile(
        self,
        profile_id: str,
        *,
        name: str | None = None,
        ttl: int | None = None,
        lock: bool | None = None,
        disable_until: int | None = None,
    ) -> dict[str, Any]:
        """Update a profile's settings."""
        data: dict[str, Any] = {}
        if name is not None:
            data["name"] = name
        if ttl is not None:
            data["ttl"] = ttl
        if lock is not None:
            data["lock"] = 1 if lock else 0
        if disable_until is not None:
            data["disable_until"] = disable_until
        return self._request("PUT", f"/profiles/{profile_id}", data=data)

    # ── Filters ─────────────────────────────────────────────────────

    def list_filters(self, profile_id: str) -> dict[str, Any]:
        """List native and external filters for a profile."""
        native = self._request("GET", f"/profiles/{profile_id}/filters")
        external = self._request("GET", f"/profiles/{profile_id}/filters/external")
        return {"native": native, "external": external}

    def update_filters_batch(self, profile_id: str, filters: dict[str, int]) -> dict[str, Any]:
        """Batch enable/disable multiple filters. JSON body: {filter_id: 0|1, ...}."""
        return self._request("PUT", f"/profiles/{profile_id}/filters", json_body=filters)

    def update_filter(self, profile_id: str, filter_id: str, status: int) -> dict[str, Any]:
        """Enable (1) or disable (0) a single filter."""
        return self._request("PUT", f"/profiles/{profile_id}/filters/filter/{filter_id}", data={"status": status})

    # ── Services ────────────────────────────────────────────────────

    def list_services(self, profile_id: str) -> list[dict[str, Any]]:
        """List active service rules for a profile."""
        body = self._request("GET", f"/profiles/{profile_id}/services")
        return self._as_list(body, "services")

    def get_service_catalog(self) -> dict[str, Any]:
        """Get service categories and services (cached 1hr)."""
        global _catalog_cache, _catalog_ts
        now = time.monotonic()
        if _catalog_cache is not None and (now - _catalog_ts) < _CATALOG_TTL:
            return _catalog_cache

        categories = self._request("GET", "/services/categories")
        proxies = self._request("GET", "/proxies")
        result = {"categories": categories, "proxies": proxies}
        _catalog_cache = result
        _catalog_ts = now
        return result

    def update_service(
        self,
        profile_id: str,
        service_id: str,
        action: int,
        via: str | None = None,
    ) -> dict[str, Any]:
        """Set a service rule: 0=block, 1=bypass, 2=spoof, 3=redirect."""
        data: dict[str, Any] = {"do": action}
        if via is not None:
            data["via"] = via
        return self._request("PUT", f"/profiles/{profile_id}/services/{service_id}", data=data)

    # ── Custom Rules ────────────────────────────────────────────────

    def list_rules(self, profile_id: str, folder_id: int = 0) -> list[dict[str, Any]]:
        """List custom rules in a folder (0 = root)."""
        body = self._request("GET", f"/profiles/{profile_id}/rules/{folder_id}")
        return self._as_list(body, "rules")

    def list_rule_folders(self, profile_id: str) -> list[dict[str, Any]]:
        """List rule folders for a profile."""
        body = self._request("GET", f"/profiles/{profile_id}/groups")
        return self._as_list(body, "groups")

    def create_rule(
        self,
        profile_id: str,
        hostnames: list[str],
        action: int,
        *,
        via: str | None = None,
        group: int | None = None,
    ) -> dict[str, Any]:
        """Create custom rule(s). action: 0=block, 1=bypass, 2=spoof, 3=redirect."""
        data: dict[str, Any] = {"do": action}
        for i, h in enumerate(hostnames):
            data[f"hostnames[{i}]"] = h
        if via is not None:
            data["via"] = via
        if group is not None:
            data["group"] = group
        return self._request("POST", f"/profiles/{profile_id}/rules", data=data)

    def update_rule(
        self,
        profile_id: str,
        hostnames: list[str],
        *,
        action: int | None = None,
        via: str | None = None,
        group: int | None = None,
    ) -> dict[str, Any]:
        """Update existing custom rule(s)."""
        data: dict[str, Any] = {}
        for i, h in enumerate(hostnames):
            data[f"hostnames[{i}]"] = h
        if action is not None:
            data["do"] = action
        if via is not None:
            data["via"] = via
        if group is not None:
            data["group"] = group
        return self._request("PUT", f"/profiles/{profile_id}/rules", data=data)

    def delete_rule(self, profile_id: str, hostname: str) -> dict[str, Any]:
        """Delete a custom rule by hostname."""
        return self._request("DELETE", f"/profiles/{profile_id}/rules/{hostname}")

    # ── Default Rule ────────────────────────────────────────────────

    def get_default_rule(self, profile_id: str) -> dict[str, Any]:
        """Get the default rule for a profile."""
        return self._request("GET", f"/profiles/{profile_id}/default")

    def set_default_rule(
        self,
        profile_id: str,
        action: int,
        via: str | None = None,
    ) -> dict[str, Any]:
        """Set the default rule. action: 0=block, 1=bypass, 2=spoof, 3=redirect."""
        data: dict[str, Any] = {"do": action}
        if via is not None:
            data["via"] = via
        return self._request("PUT", f"/profiles/{profile_id}/default", data=data)

    # ── Devices / Endpoints ─────────────────────────────────────────

    def list_devices(self) -> list[dict[str, Any]]:
        """List all DNS endpoints (devices)."""
        body = self._request("GET", "/devices")
        return self._as_list(body, "devices")

    def create_device(
        self,
        name: str,
        profile_id: str,
        device_type: str | None = None,
    ) -> dict[str, Any]:
        """Create a new DNS endpoint."""
        data: dict[str, Any] = {"name": name, "profile_id": profile_id}
        if device_type:
            data["device_type"] = device_type
        return self._request("POST", "/devices", data=data)

    def update_device(
        self,
        device_id: str,
        *,
        profile_id: str | None = None,
        name: str | None = None,
        status: int | None = None,
    ) -> dict[str, Any]:
        """Update a device's settings."""
        data: dict[str, Any] = {}
        if profile_id is not None:
            data["profile_id"] = profile_id
        if name is not None:
            data["name"] = name
        if status is not None:
            data["status"] = status
        return self._request("PUT", f"/devices/{device_id}", data=data)

    # ── Access / IP Auth ────────────────────────────────────────────

    def list_access(self, device_id: str) -> list[dict[str, Any]]:
        """List last 50 IPs that queried a device."""
        body = self._request("GET", "/access", params={"device_id": device_id})
        return self._as_list(body, "ips")

    def authorize_ips(self, device_id: str, ips: list[str]) -> dict[str, Any]:
        """Authorize IPs on a device."""
        data: dict[str, Any] = {"device_id": device_id}
        for i, ip in enumerate(ips):
            data[f"ips[{i}]"] = ip
        return self._request("POST", "/access", data=data)

    def deauthorize_ips(self, device_id: str, ips: list[str]) -> dict[str, Any]:
        """Deauthorize IPs from a device."""
        data: dict[str, Any] = {"device_id": device_id}
        for i, ip in enumerate(ips):
            data[f"ips[{i}]"] = ip
        return self._request("DELETE", "/access", data=data)

    # ── Analytics ───────────────────────────────────────────────────

    def get_analytics_levels(self) -> list[dict[str, Any]]:
        """List available analytics log levels."""
        body = self._request("GET", "/analytics/levels")
        return self._as_list(body, "levels")

    def get_analytics_endpoints(self) -> list[dict[str, Any]]:
        """List analytics storage regions."""
        body = self._request("GET", "/analytics/endpoints")
        return self._as_list(body, "endpoints")
