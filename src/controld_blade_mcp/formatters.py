"""Token-efficient output formatters.

All formatters return compact pipe-delimited strings. Null fields are omitted.
"""

from __future__ import annotations

import contextvars
import time as _time
from typing import Any

from stallari_mcp_helpers import append_meta as _lib_append_meta
from stallari_mcp_helpers import meta_envelope as _lib_meta_envelope

_MAX_TEXT_LEN = 200

_ACTION_LABELS = {0: "BLOCK", 1: "BYPASS", 2: "SPOOF", 3: "REDIRECT"}

# ── CONV-29 audit-surface (_meta tail) ──────────────────────────────

_call_started: contextvars.ContextVar[float] = contextvars.ContextVar("_call_started", default=0.0)


def mark_call_start() -> None:
    """Stamp the start of the current tool call (read by :func:`meta_tail`)."""
    _call_started.set(_time.monotonic())


def meta_tail(
    payload: str,
    matched_total: int,
    *,
    returned: int | None = None,
    target_id: str | None = None,
    rows_affected: int | None = None,
) -> str:
    """Append the CONV-29 ``_meta`` audit envelope as a JSON tail line.

    Control-D tools do no scope-filtering/pagination, so for reads
    ``matched_total == returned`` and ``filtered_by`` is empty. Write tools
    pass ``target_id``/``rows_affected`` to make the mutation auditable.
    ``latency_ms`` is derived from the contextvar stamped by
    :func:`mark_call_start` (0 if unstamped, e.g. a formatter called directly
    in a unit test).
    """
    t0 = _call_started.get()
    latency_ms = int((_time.monotonic() - t0) * 1000) if t0 else 0
    envelope = str(
        _lib_meta_envelope(
            matched_total=matched_total,
            returned=matched_total if returned is None else returned,
            latency_ms=latency_ms,
            target_id=target_id,
            rows_affected=rows_affected,
        )
    )
    return str(_lib_append_meta(payload, envelope))


def _safe(value: Any) -> str:
    """Convert value to string, empty string for None."""
    if value is None:
        return ""
    return str(value)


def _truncate(text: str, max_len: int = _MAX_TEXT_LEN) -> str:
    """Truncate with ellipsis."""
    if not text or len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _action_label(action: int | str | None) -> str:
    """Map action integer to human-readable label."""
    if action is None:
        return ""
    try:
        return _ACTION_LABELS.get(int(action), f"UNKNOWN({action})")
    except (ValueError, TypeError):
        return str(action)


def _on_off(status: int | bool | None) -> str:
    """Convert status to ON/OFF."""
    if status is None:
        return ""
    return "ON" if int(status) == 1 else "OFF"


# ── Info ────────────────────────────────────────────────────────────


def format_info(user: dict[str, Any], ip_data: dict[str, Any]) -> str:
    """Format account info + caller IP."""
    parts = []
    email = user.get("email", "")
    if email:
        parts.append(f"Account: {email}")
    status = user.get("status")
    if status is not None:
        parts.append(f"Status: {'active' if status == 1 else 'inactive'}")
    tfa = user.get("tfa")
    if tfa is not None:
        parts.append(f"2FA: {'enabled' if tfa == 1 else 'disabled'}")

    caller_ip = ip_data.get("ip", "")
    if caller_ip:
        parts.append(f"IP: {caller_ip}")
    dc = ip_data.get("datacenter", "")
    if dc:
        parts.append(f"PoP: {dc}")

    return "\n".join(parts) if parts else "(no account info)"


def format_network(network: dict[str, Any]) -> str:
    """Format Control-D PoP availability.

    Wire shape: ``{"network": [{iata_code, city_name, country_name,
    status: {api, dns, pxy}}, ...]}`` where each status value is ``1`` (up),
    ``-1`` (down/unavailable) or ``0``. Summarise totals + list any PoP that is
    not fully healthy (keeps output token-cheap; healthy PoPs are the norm).
    """
    pops = network.get("network", network) if isinstance(network, dict) else network
    if not isinstance(pops, list) or not pops:
        return "(no network data)"

    up = {"api": 0, "dns": 0, "pxy": 0}
    degraded = []
    for pop in pops:
        status = pop.get("status", {}) if isinstance(pop, dict) else {}
        for svc in ("api", "dns", "pxy"):
            if status.get(svc) == 1:
                up[svc] += 1
        bad = [s for s in ("api", "dns", "pxy") if status.get(s) is not None and status.get(s) != 1]
        if bad:
            loc = f"{pop.get('iata_code', '?')} {pop.get('city_name', '')}".strip()
            degraded.append(f"{loc} | down: {', '.join(bad)}")

    lines = [f"PoPs: {len(pops)} | api up: {up['api']} | dns up: {up['dns']} | proxy up: {up['pxy']}"]
    if degraded:
        lines.append(f"\n## Degraded ({len(degraded)})")
        lines.extend(degraded)
    return "\n".join(lines)


# ── Profiles ────────────────────────────────────────────────────────


# Profile count nodes live under the ``profile`` envelope as ``{key: {count: N}}``.
# (label shown to the user, wire key under profile.*)
_PROFILE_COUNTS = (("rules", "rule"), ("filters", "flt"), ("services", "svc"), ("folders", "grp"))


def _profile_counts(profile: dict[str, Any]) -> list[str]:
    """Extract ``label: N`` count parts from a profile's ``profile.{key}.count`` block."""
    prof = profile.get("profile", {})
    if not isinstance(prof, dict):
        return []
    parts = []
    for label, key in _PROFILE_COUNTS:
        node = prof.get(key)
        if isinstance(node, dict) and node.get("count") is not None:
            parts.append(f"{label}: {node['count']}")
    return parts


def format_profiles(profiles: list[dict[str, Any]]) -> str:
    """Format profile list — one line per profile."""
    if not profiles:
        return "(no profiles)"
    lines = []
    for p in profiles:
        parts = [f"ID: {_safe(p.get('PK'))}", _safe(p.get("name"))]
        parts.extend(_profile_counts(p))
        if p.get("lock"):
            parts.append("locked")
        if p.get("disable"):
            parts.append("disabled")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_profile_detail(profile: dict[str, Any], options: list[dict[str, Any]] | None = None) -> str:
    """Format single profile with full detail.

    ``options`` is the *global* option catalog (``/profiles/options``); the
    profile's actually-enabled options live in ``profile.opt.data``. We surface
    the enabled set and use the catalog only to resolve human titles.
    """
    lines = [
        f"Profile: {_safe(profile.get('name'))}",
        f"ID: {_safe(profile.get('PK'))}",
    ]
    if profile.get("lock"):
        lines.append("Locked: yes")
    if profile.get("disable"):
        lines.append("Disabled: yes")

    stats = _profile_counts(profile)
    if stats:
        lines.append("Stats: " + ", ".join(stats))

    prof = profile.get("profile", {})
    opt_data = prof.get("opt", {}).get("data", []) if isinstance(prof, dict) else []
    if isinstance(opt_data, list) and opt_data:
        titles = {str(o.get("PK")): o.get("title", o.get("PK")) for o in (options or [])}
        enabled = [f"{titles.get(str(o.get('PK')), o.get('PK'))}={o.get('value')}" for o in opt_data]
        lines.append(f"Options: {', '.join(str(e) for e in enabled)}")

    return "\n".join(lines)


# ── Filters ─────────────────────────────────────────────────────────


def _filter_enabled(f: dict[str, Any]) -> bool:
    """A filter is on when one of its ``levels`` is active, or (external) when
    its own ``status`` is 1."""
    levels = f.get("levels")
    if isinstance(levels, list):
        return any(isinstance(lvl, dict) and lvl.get("status") == 1 for lvl in levels)
    return f.get("status") == 1


def _active_level(f: dict[str, Any]) -> str:
    """Name of the active level, if any (e.g. ``Balanced``)."""
    levels = f.get("levels")
    if isinstance(levels, list):
        for lvl in levels:
            if isinstance(lvl, dict) and lvl.get("status") == 1:
                return str(lvl.get("title", lvl.get("name", "")))
    return ""


def _filter_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        inner = value.get("filters", [])
        return inner if isinstance(inner, list) else []
    return []


def _format_filter_group(filters: list[dict[str, Any]], heading: str) -> list[str]:
    enabled = sum(1 for f in filters if _filter_enabled(f))
    lines = [f"## {heading} ({enabled}/{len(filters)} enabled)"]
    for f in filters:
        on = _filter_enabled(f)
        parts = [_safe(f.get("PK", f.get("name", "?"))), "ON" if on else "OFF"]
        title = f.get("name", "")
        if title:
            parts.append(title)
        level = _active_level(f) if on else ""
        if level:
            parts.append(f"level: {level}")
        lines.append(" | ".join(parts))
    return lines


def format_filters(native: Any, external: Any) -> str:
    """Format native + external filters grouped by type."""
    native_list = _filter_list(native)
    ext_list = _filter_list(external)
    lines = _format_filter_group(native_list, "Native Filters")
    if ext_list:
        lines.append("")
        lines.extend(_format_filter_group(ext_list, "External Filters"))
    return "\n".join(lines)


# ── Services ────────────────────────────────────────────────────────


def _do_via(item: dict[str, Any]) -> tuple[int | None, int | None, str]:
    """Extract (do, status, via) from an item whose action lives under
    ``action: {do, status, via}`` (live shape), falling back to flat keys.

    ``via`` is the spoof target / redirect location and appears in three places
    across the API: nested ``action.via`` (custom rules), top-level
    ``unlock_location`` (services), or top-level ``via`` (legacy/flat payloads).
    For a rule, spoof (do=2) stores an IP and redirect (do=3) a proxy location.
    """
    act = item.get("action")
    if isinstance(act, dict):
        do, status, act_via = act.get("do"), act.get("status"), act.get("via")
    else:
        do, status, act_via = item.get("do"), item.get("status"), None
    via = item.get("unlock_location") or item.get("via") or act_via or ""
    return do, status, via


def format_services(services: list[dict[str, Any]]) -> str:
    """Format active service rules."""
    if not services:
        return "(no active service rules)"
    lines = []
    for s in services:
        name = _safe(s.get("name", s.get("PK", "?")))
        do, status, via = _do_via(s)
        parts = [name, _action_label(do)]
        if status is not None:
            parts.append(_on_off(status))
        cat = s.get("category", {})
        if isinstance(cat, dict) and cat.get("name"):
            parts.append(f"category: {cat['name']}")
        elif isinstance(cat, str) and cat:
            parts.append(f"category: {cat}")
        if via:
            parts.append(f"via: {via}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_service_catalog(catalog: dict[str, Any]) -> str:
    """Format service catalog (categories + services)."""
    categories = catalog.get("categories", [])
    if not categories:
        return "(no service categories)"

    lines = []
    cat_list = categories if isinstance(categories, list) else categories.get("categories", [])
    for cat in cat_list:
        cat_name = _safe(cat.get("name", cat.get("PK", "?")))
        # The categories endpoint returns a per-category ``count`` but not the
        # inline service list (there is no per-category service endpoint).
        services = cat.get("services", [])
        count = cat.get("count", len(services))
        pk = _safe(cat.get("PK", ""))
        lines.append(f"## {cat_name} [{pk}] ({count} services)")
        for svc in services[:10]:
            lines.append(f"  {_safe(svc.get('PK', '?'))} | {_safe(svc.get('name', ''))}")
        if len(services) > 10:
            lines.append(f"  ... and {len(services) - 10} more")

    proxies = catalog.get("proxies", [])
    if proxies:
        proxy_list = proxies if isinstance(proxies, list) else proxies.get("proxies", [])
        lines.append(f"\n## Proxy Locations ({len(proxy_list)})")
        for p in proxy_list[:20]:
            lines.append(f"  {_safe(p.get('PK', '?'))} | {_safe(p.get('city', ''))} {_safe(p.get('country', ''))}")
        if len(proxy_list) > 20:
            lines.append(f"  ... and {len(proxy_list) - 20} more")

    return "\n".join(lines)


# ── Custom Rules ────────────────────────────────────────────────────


def format_rules(rules: list[dict[str, Any]], folders: list[dict[str, Any]] | None = None) -> str:
    """Format custom rules — one line per rule."""
    if not rules:
        return "(no custom rules)"

    folder_map: dict[int, str] = {}
    if folders:
        for f in folders:
            fid = f.get("PK", f.get("group"))
            # Folder name is the ``group`` key on the live API (``name`` on
            # legacy/flat payloads).
            fname = f.get("group") if isinstance(f.get("group"), str) else f.get("name", "")
            if fid is not None and fname:
                folder_map[int(fid)] = fname

    lines = []
    for r in rules:
        hostname = _safe(r.get("PK", r.get("hostname", "?")))
        do, _status, via = _do_via(r)
        action = _action_label(do)
        parts = [hostname, action]
        if via and action in ("SPOOF", "REDIRECT"):
            parts[-1] = f"{action} -> {via}"
        group = r.get("group")
        if group:  # group 0 = ungrouped, not worth a label
            fname = folder_map.get(int(group), str(group))
            parts.append(f"folder: {fname}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_default_rule(rule: dict[str, Any]) -> str:
    """Format default rule status. Live shape nests under ``default``."""
    default = rule.get("default")
    inner: dict[str, Any] = default if isinstance(default, dict) else rule
    do, status, via = _do_via(inner)
    action = _action_label(do)
    parts = [f"Default rule: {action}"]
    if via and action in ("SPOOF", "REDIRECT"):
        parts[0] = f"Default rule: {action} -> {via}"
    if status is not None:
        parts.append(f"status: {_on_off(status)}")
    return " | ".join(parts)


# ── Devices ─────────────────────────────────────────────────────────


def format_devices(devices: list[dict[str, Any]]) -> str:
    """Format device list — one line per device."""
    if not devices:
        return "(no devices)"
    lines = []
    for d in devices:
        parts = [f"ID: {_safe(d.get('PK'))}", _safe(d.get("name", "(unnamed)"))]
        profile = d.get("profile", {})
        if isinstance(profile, dict) and profile.get("name"):
            parts.append(f"profile: {profile['name']}")
        elif d.get("profile_id"):
            parts.append(f"profile_id: {d['profile_id']}")
        # Live API names the device class ``icon`` (e.g. mobile-ios, desktop);
        # legacy/flat payloads used ``device_type``.
        dtype = d.get("device_type") or d.get("icon")
        if dtype:
            parts.append(f"type: {dtype}")
        status = d.get("status")
        if status is not None:
            parts.append(f"status: {'active' if status == 1 else 'inactive'}")
        resolvers = d.get("resolvers", {})
        if isinstance(resolvers, dict):
            doh = resolvers.get("doh", "")
            if doh:
                parts.append(f"DoH: {_truncate(doh, 60)}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_device_detail(device: dict[str, Any]) -> str:
    """Format single device with full detail."""
    lines = [
        f"Device: {_safe(device.get('name', '(unnamed)'))}",
        f"ID: {_safe(device.get('PK'))}",
    ]
    profile = device.get("profile", {})
    if isinstance(profile, dict) and profile.get("name"):
        lines.append(f"Profile: {profile['name']} (ID: {profile.get('PK', '?')})")
    dtype = device.get("device_type") or device.get("icon")
    if dtype:
        lines.append(f"Type: {dtype}")
    status = device.get("status")
    if status is not None:
        lines.append(f"Status: {'active' if status == 1 else 'inactive'}")

    resolvers = device.get("resolvers", {})
    if isinstance(resolvers, dict):
        for proto in ("doh", "dot", "doh3", "legacy"):
            val = resolvers.get(proto)
            if val:
                lines.append(f"{proto.upper()}: {val}")

    return "\n".join(lines)


# ── Access ──────────────────────────────────────────────────────────


def format_access(ips: list[dict[str, Any]]) -> str:
    """Format IP access list."""
    if not ips:
        return "(no IPs recorded)"
    lines = []
    for entry in ips:
        ip = _safe(entry.get("ip", entry.get("PK", "?")))
        ts = entry.get("ts", "")
        parts = [ip]
        if ts:
            parts.append(f"last_seen: {ts}")
        country = entry.get("country", "")
        if country:
            parts.append(f"country: {country}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


# ── Analytics ───────────────────────────────────────────────────────


def format_analytics_config(levels: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> str:
    """Format analytics configuration (levels + regions)."""
    lines = []
    if levels:
        lines.append("## Log Levels")
        for lvl in levels:
            parts = [_safe(lvl.get("PK", lvl.get("name", "?")))]
            label = lvl.get("title") or lvl.get("description", "")
            if label:
                parts.append(_truncate(label, 80))
            lines.append(" | ".join(parts))

    if endpoints:
        lines.append("\n## Storage Regions")
        for ep in endpoints:
            parts = [_safe(ep.get("PK", ep.get("name", "?")))]
            loc = ep.get("title") or ep.get("location") or ep.get("description", "")
            if loc:
                parts.append(loc)
            cc = ep.get("country_code")
            if cc:
                parts.append(cc)
            lines.append(" | ".join(parts))

    return "\n".join(lines) if lines else "(no analytics configuration)"


# ── Write confirmations ─────────────────────────────────────────────


def format_write_result(result: Any, action: str) -> str:
    """Format a write operation result.

    Control-D write endpoints are inconsistent: some return a dict (optionally
    with a ``message``), but several (e.g. ``DELETE /rules/{host}``) return a
    bare list ``[]`` on success. Guard against non-dict bodies.
    """
    if isinstance(result, dict):
        msg = result.get("message", f"{action} completed")
        return f"OK: {msg}" if isinstance(msg, str) else f"OK: {action} completed"
    return f"OK: {action} completed"
