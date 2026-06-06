"""Control-D MCP Server — DNS filtering, privacy profiles, and device management."""

from __future__ import annotations

import asyncio
import functools
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from controld_blade_mcp.client import ControlDClient
from controld_blade_mcp.formatters import (
    format_access,
    format_analytics_config,
    format_default_rule,
    format_device_detail,
    format_devices,
    format_filters,
    format_info,
    format_network,
    format_profile_detail,
    format_profiles,
    format_rules,
    format_service_catalog,
    format_services,
    format_write_result,
    mark_call_start,
    meta_tail,
)
from controld_blade_mcp.models import ControlDError, require_confirm, require_write

logger = logging.getLogger(__name__)

TRANSPORT = os.environ.get("CONTROLD_MCP_TRANSPORT", "stdio")
HTTP_HOST = os.environ.get("CONTROLD_MCP_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("CONTROLD_MCP_PORT", "8767"))

mcp = FastMCP(
    "ControlDBlade",
    instructions=(
        "Control-D DNS filtering and privacy operations. Manage profiles, "
        "filters, services, custom rules, and devices. "
        "Write operations require CONTROLD_WRITE_ENABLED=true."
    ),
)

# ── Client singleton ───────────────────────────────────��────────────

_client: ControlDClient | None = None


def _get_client() -> ControlDClient:
    """Get or create the singleton client."""
    global _client  # noqa: PLW0603
    if _client is None:
        _client = ControlDClient()
    return _client


def _error_response(e: ControlDError) -> str:
    """Format an error as a user-facing string."""
    return f"Error: {e}"


async def _run(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a blocking client method in a thread to avoid blocking the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


def _audited(fn: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[str]]:
    """Stamp call-start so each tool's ``meta_tail`` reports real latency (CONV-29)."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        mark_call_start()
        return await fn(*args, **kwargs)

    return wrapper


# ── Read Tools ───────────────────────────────���──────────────────────


@mcp.tool()
@_audited
async def cd_info() -> str:
    """Account info and caller IP — health check for connectivity."""
    try:
        client = _get_client()
        user, ip_data = await asyncio.gather(
            _run(client.get_user),
            _run(client.get_ip),
        )
        return meta_tail(format_info(user, ip_data), 1)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_network() -> str:
    """Service availability across Control-D points of presence."""
    try:
        result = await _run(_get_client().get_network)
        return meta_tail(format_network(result), len(result) if isinstance(result, dict) else 0)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_profiles() -> str:
    """List all DNS profiles with rule/device counts."""
    try:
        profiles = await _run(_get_client().list_profiles)
        return meta_tail(format_profiles(profiles), len(profiles))
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_profile(
    profile_id: Annotated[str, Field(description="Profile ID (PK)")],
) -> str:
    """Get full detail for a single profile including active options."""
    try:
        client = _get_client()
        profiles = await _run(client.list_profiles)
        profile = next((p for p in profiles if str(p.get("PK")) == profile_id), None)
        if not profile:
            return f"Error: Profile {profile_id} not found"
        options = await _run(client.get_profile_options)
        return meta_tail(format_profile_detail(profile, options), 1, target_id=profile_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_filters(
    profile_id: Annotated[str, Field(description="Profile ID")],
) -> str:
    """List native and external filters for a profile, grouped by type."""
    try:
        result = await _run(_get_client().list_filters, profile_id)
        native = result.get("native", [])
        external = result.get("external", [])
        count = (len(native) if isinstance(native, list) else 0) + (len(external) if isinstance(external, list) else 0)
        return meta_tail(format_filters(native, external), count, target_id=profile_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_services(
    profile_id: Annotated[str, Field(description="Profile ID")],
) -> str:
    """List active service rules (block/bypass/spoof/redirect) for a profile."""
    try:
        services = await _run(_get_client().list_services, profile_id)
        return meta_tail(format_services(services), len(services), target_id=profile_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_service_catalog() -> str:
    """Full Control-D service catalog — categories and proxy locations. Cached 1hr."""
    try:
        catalog = await _run(_get_client().get_service_catalog)
        return meta_tail(format_service_catalog(catalog), 1)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_rules(
    profile_id: Annotated[str, Field(description="Profile ID")],
    folder_id: Annotated[int, Field(description="Folder ID (0 for root)")] = 0,
) -> str:
    """List custom DNS rules in a folder. Use folder_id=0 for root."""
    try:
        client = _get_client()
        rules, folders = await asyncio.gather(
            _run(client.list_rules, profile_id, folder_id),
            _run(client.list_rule_folders, profile_id),
        )
        return meta_tail(format_rules(rules, folders), len(rules), target_id=profile_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_default_rule(
    profile_id: Annotated[str, Field(description="Profile ID")],
) -> str:
    """Get the default (catch-all) rule for a profile."""
    try:
        result = await _run(_get_client().get_default_rule, profile_id)
        return meta_tail(format_default_rule(result), 1, target_id=profile_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_devices() -> str:
    """List all DNS endpoints (devices) with profiles and resolver addresses."""
    try:
        devices = await _run(_get_client().list_devices)
        return meta_tail(format_devices(devices), len(devices))
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_access(
    device_id: Annotated[str, Field(description="Device ID")],
) -> str:
    """List last 50 IPs that queried a device."""
    try:
        ips = await _run(_get_client().list_access, device_id)
        return meta_tail(format_access(ips), len(ips), target_id=device_id)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_analytics_config() -> str:
    """Analytics configuration — available log levels and storage regions."""
    try:
        client = _get_client()
        levels, endpoints = await asyncio.gather(
            _run(client.get_analytics_levels),
            _run(client.get_analytics_endpoints),
        )
        return meta_tail(format_analytics_config(levels, endpoints), len(levels) + len(endpoints))
    except ControlDError as e:
        return _error_response(e)


# ── Write Tools ────────────────────────────��────────────────────────


@mcp.tool()
@_audited
async def cd_profile_create(
    name: Annotated[str, Field(description="Profile name")],
    clone_profile_id: Annotated[str | None, Field(description="Profile ID to clone from")] = None,
) -> str:
    """Create a new DNS profile (blank or cloned from existing)."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().create_profile, name, clone_profile_id)
        new_id = str(result.get("PK")) if isinstance(result, dict) and result.get("PK") else None
        return meta_tail(format_write_result(result, f"Profile '{name}' created"), 1, target_id=new_id, rows_affected=1)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_profile_update(
    profile_id: Annotated[str, Field(description="Profile ID")],
    name: Annotated[str | None, Field(description="New profile name")] = None,
    ttl: Annotated[int | None, Field(description="Default TTL in seconds")] = None,
    lock: Annotated[bool | None, Field(description="Lock the profile")] = None,
) -> str:
    """Update a profile's name, TTL, or lock status."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().update_profile, profile_id, name=name, ttl=ttl, lock=lock)
        return meta_tail(
            format_write_result(result, f"Profile {profile_id} updated"), 1, target_id=profile_id, rows_affected=1
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_filters_update(
    profile_id: Annotated[str, Field(description="Profile ID")],
    filter_id: Annotated[str | None, Field(description="Single filter ID to toggle")] = None,
    status: Annotated[int | None, Field(description="1=enable, 0=disable (for single filter)")] = None,
    batch: Annotated[str | None, Field(description="JSON object of {filter_id: 0|1, ...} for batch update")] = None,
) -> str:
    """Enable/disable filters. Use filter_id+status for one, or batch for many."""
    gate = require_write()
    if gate:
        return gate
    try:
        client = _get_client()
        affected = 1
        if batch:
            import json

            filters = json.loads(batch)
            affected = len(filters) if isinstance(filters, dict) else 1
            result = await _run(client.update_filters_batch, profile_id, filters)
        elif filter_id is not None and status is not None:
            result = await _run(client.update_filter, profile_id, filter_id, status)
        else:
            return "Error: Provide either filter_id+status or batch JSON"
        return meta_tail(
            format_write_result(result, "Filters updated"), 1, target_id=profile_id, rows_affected=affected
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_service_update(
    profile_id: Annotated[str, Field(description="Profile ID")],
    service_id: Annotated[str, Field(description="Service ID from catalog")],
    action: Annotated[int, Field(description="0=block, 1=bypass, 2=spoof, 3=redirect")],
    via: Annotated[
        str | None, Field(description="spoof (action 2): target IP; redirect (action 3): proxy location PK")
    ] = None,
    status: Annotated[int, Field(description="1=active (default), 0=inactive")] = 1,
) -> str:
    """Set a service rule — block, bypass, spoof, or redirect."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().update_service, profile_id, service_id, action, via, status)
        return meta_tail(
            format_write_result(result, f"Service {service_id} rule set"), 1, target_id=service_id, rows_affected=1
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_rule_create(
    profile_id: Annotated[str, Field(description="Profile ID")],
    hostnames: Annotated[list[str], Field(description="Hostnames to create rules for")],
    action: Annotated[int, Field(description="0=block, 1=bypass, 2=spoof, 3=redirect")],
    via: Annotated[
        str | None, Field(description="spoof (action 2): target IP; redirect (action 3): proxy location PK")
    ] = None,
    group: Annotated[int | None, Field(description="Folder ID to place rules in")] = None,
) -> str:
    """Create custom DNS rule(s) for one or more hostnames."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().create_rule, profile_id, hostnames, action, via=via, group=group)
        return meta_tail(
            format_write_result(result, f"Rule created for {', '.join(hostnames)}"),
            1,
            target_id=profile_id,
            rows_affected=len(hostnames),
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_rule_update(
    profile_id: Annotated[str, Field(description="Profile ID")],
    hostnames: Annotated[list[str], Field(description="Hostnames to update rules for")],
    action: Annotated[int | None, Field(description="0=block, 1=bypass, 2=spoof, 3=redirect")] = None,
    via: Annotated[
        str | None, Field(description="spoof (action 2): target IP; redirect (action 3): proxy location PK")
    ] = None,
    group: Annotated[int | None, Field(description="Folder ID to move rules to")] = None,
) -> str:
    """Update existing custom DNS rule(s)."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().update_rule, profile_id, hostnames, action=action, via=via, group=group)
        return meta_tail(
            format_write_result(result, f"Rule updated for {', '.join(hostnames)}"),
            1,
            target_id=profile_id,
            rows_affected=len(hostnames),
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_rule_delete(
    profile_id: Annotated[str, Field(description="Profile ID")],
    hostname: Annotated[str, Field(description="Hostname to delete rule for")],
    confirm: Annotated[bool, Field(description="Must be true to confirm deletion")] = False,
) -> str:
    """Delete a custom DNS rule. Requires confirm=true."""
    gate = require_write()
    if gate:
        return gate
    conf = require_confirm(confirm, "Deleting a DNS rule")
    if conf:
        return conf
    try:
        result = await _run(_get_client().delete_rule, profile_id, hostname)
        return meta_tail(
            format_write_result(result, f"Rule deleted for {hostname}"), 1, target_id=hostname, rows_affected=1
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_default_rule_set(
    profile_id: Annotated[str, Field(description="Profile ID")],
    action: Annotated[int, Field(description="0=block, 1=bypass, 2=spoof, 3=redirect")],
    via: Annotated[
        str | None, Field(description="spoof (action 2): target IP; redirect (action 3): proxy location PK")
    ] = None,
) -> str:
    """Set the default (catch-all) rule for a profile."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().set_default_rule, profile_id, action, via)
        return meta_tail(format_write_result(result, "Default rule updated"), 1, target_id=profile_id, rows_affected=1)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_device_create(
    name: Annotated[str, Field(description="Device name")],
    profile_id: Annotated[str, Field(description="Profile ID to assign")],
    device_type: Annotated[str | None, Field(description="Device type (e.g. macos, windows, router)")] = None,
) -> str:
    """Create a new DNS endpoint (device)."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().create_device, name, profile_id, device_type)
        if isinstance(result, dict):
            new_id = str(result.get("PK")) if result.get("PK") else None
            device_detail = format_device_detail(result)
            return meta_tail(f"OK: Device '{name}' created\n{device_detail}", 1, target_id=new_id, rows_affected=1)
        return meta_tail(format_write_result(result, f"Device '{name}' created"), 1, rows_affected=1)
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_device_update(
    device_id: Annotated[str, Field(description="Device ID")],
    profile_id: Annotated[str | None, Field(description="New profile ID")] = None,
    name: Annotated[str | None, Field(description="New device name")] = None,
    status: Annotated[int | None, Field(description="1=active, 0=inactive")] = None,
) -> str:
    """Update a device's profile assignment, name, or status."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _run(_get_client().update_device, device_id, profile_id=profile_id, name=name, status=status)
        return meta_tail(
            format_write_result(result, f"Device {device_id} updated"), 1, target_id=device_id, rows_affected=1
        )
    except ControlDError as e:
        return _error_response(e)


@mcp.tool()
@_audited
async def cd_access_update(
    device_id: Annotated[str, Field(description="Device ID")],
    ips: Annotated[list[str], Field(description="IP addresses to authorize or deauthorize")],
    action: Annotated[str, Field(description="'authorize' or 'deauthorize'")],
    confirm: Annotated[bool, Field(description="Must be true to confirm")] = False,
) -> str:
    """Authorize or deauthorize IPs on a device. Requires confirm=true."""
    gate = require_write()
    if gate:
        return gate
    conf = require_confirm(confirm, f"{action.capitalize()} IP access")
    if conf:
        return conf
    try:
        client = _get_client()
        if action == "authorize":
            result = await _run(client.authorize_ips, device_id, ips)
        elif action == "deauthorize":
            result = await _run(client.deauthorize_ips, device_id, ips)
        else:
            return "Error: action must be 'authorize' or 'deauthorize'"
        return meta_tail(
            format_write_result(result, f"IPs {action}d on device {device_id}"),
            1,
            target_id=device_id,
            rows_affected=len(ips),
        )
    except ControlDError as e:
        return _error_response(e)


# ── Entry point ───────────────────────────────────────────────────��─


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _require_secure_http(host: str, token: str | None) -> None:
    """Enforce the blade-mcp http transport policy (DD-242 / access-policy).

    HTTP transport is a manual loopback path only: it MUST carry a bearer token
    and bind to loopback. Raises ``SystemExit`` (never returns) when either
    invariant is violated, so an http-enabled Control-D blade can never serve
    DNS-policy write operations unauthenticated or on a public interface.
    """
    if token is None:
        raise SystemExit(
            "Refusing to start HTTP transport without auth. "
            "Set CONTROLD_MCP_API_TOKEN to a non-empty value (the bearer "
            "token clients must send), or use the default stdio transport."
        )
    if host not in _LOOPBACK_HOSTS:
        raise SystemExit(
            f"Refusing to bind HTTP transport to non-loopback host {host!r}. "
            "Control-D blade tools mutate DNS-filtering policy; the http path "
            "is loopback-only. Front it with a reverse proxy if remote access "
            "is genuinely required."
        )


def main() -> None:
    """Run the MCP server."""
    if TRANSPORT == "http":
        from controld_blade_mcp.auth import BearerAuthMiddleware, get_bearer_token

        _require_secure_http(HTTP_HOST, get_bearer_token())

        mcp.settings.http_app_kwargs = {"middleware": [BearerAuthMiddleware]}  # type: ignore[attr-defined]
        mcp.run(transport="streamable-http", host=HTTP_HOST, port=HTTP_PORT)
    else:
        mcp.run(transport="stdio")
