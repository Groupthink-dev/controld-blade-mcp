"""Token-efficient output formatters.

All formatters return compact pipe-delimited strings. Null fields are omitted.
"""

from __future__ import annotations

from typing import Any

_MAX_TEXT_LEN = 200

_ACTION_LABELS = {0: "BLOCK", 1: "BYPASS", 2: "SPOOF", 3: "REDIRECT"}


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
    """Format network stats."""
    if not network:
        return "(no network data)"
    lines = []
    for service, stats in network.items():
        if isinstance(stats, dict):
            status = stats.get("status", "unknown")
            latency = stats.get("latency", "")
            line = f"{service} | {status}"
            if latency:
                line += f" | {latency}ms"
            lines.append(line)
        else:
            lines.append(f"{service} | {stats}")
    return "\n".join(lines) if lines else "(no network data)"


# ── Profiles ────────────────────────────────────────────────────────


def format_profiles(profiles: list[dict[str, Any]]) -> str:
    """Format profile list — one line per profile."""
    if not profiles:
        return "(no profiles)"
    lines = []
    for p in profiles:
        parts = [f"ID: {_safe(p.get('PK'))}", _safe(p.get("name"))]
        stats = p.get("stats", {})
        if isinstance(stats, dict):
            rules = stats.get("rules")
            if rules is not None:
                parts.append(f"rules: {rules}")
            devices = stats.get("devices")
            if devices is not None:
                parts.append(f"devices: {devices}")
        if p.get("lock"):
            parts.append("locked")
        if p.get("disable_until"):
            parts.append(f"disabled-until: {p['disable_until']}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_profile_detail(profile: dict[str, Any], options: list[dict[str, Any]] | None = None) -> str:
    """Format single profile with full detail."""
    lines = [
        f"Profile: {_safe(profile.get('name'))}",
        f"ID: {_safe(profile.get('PK'))}",
    ]
    if profile.get("lock"):
        lines.append("Locked: yes")
    if profile.get("disable_until"):
        lines.append(f"Disabled until: {profile['disable_until']}")

    stats = profile.get("stats", {})
    if isinstance(stats, dict):
        stat_parts = []
        for key in ("rules", "devices", "filters"):
            val = stats.get(key)
            if val is not None:
                stat_parts.append(f"{key}: {val}")
        if stat_parts:
            lines.append("Stats: " + ", ".join(stat_parts))

    if options:
        enabled = [o.get("name", o.get("PK", "?")) for o in options if o.get("status") == 1]
        if enabled:
            lines.append(f"Options: {', '.join(enabled)}")

    return "\n".join(lines)


# ── Filters ─────────────────────────────────────────────────────────


def format_filters(native: Any, external: Any) -> str:
    """Format native + external filters grouped by type."""
    lines = []
    if isinstance(native, list):
        native_list = native
    elif isinstance(native, dict):
        native_list = native.get("filters", [])
    else:
        native_list = []

    if isinstance(external, list):
        ext_list = external
    elif isinstance(external, dict):
        ext_list = external.get("filters", [])
    else:
        ext_list = []

    enabled_native = sum(1 for f in native_list if f.get("status") == 1)
    lines.append(f"## Native Filters ({enabled_native}/{len(native_list)} enabled)")
    for f in native_list:
        parts = [_safe(f.get("PK", f.get("name", "?"))), _on_off(f.get("status"))]
        title = f.get("title", f.get("name", ""))
        if title:
            parts.append(title)
        lines.append(" | ".join(parts))

    if ext_list:
        enabled_ext = sum(1 for f in ext_list if f.get("status") == 1)
        lines.append(f"\n## External Filters ({enabled_ext}/{len(ext_list)} enabled)")
        for f in ext_list:
            parts = [_safe(f.get("PK", f.get("name", "?"))), _on_off(f.get("status"))]
            title = f.get("title", f.get("name", ""))
            if title:
                parts.append(title)
            lines.append(" | ".join(parts))

    return "\n".join(lines)


# ── Services ────────────────────────────────────────────────────────


def format_services(services: list[dict[str, Any]]) -> str:
    """Format active service rules."""
    if not services:
        return "(no active service rules)"
    lines = []
    for s in services:
        name = _safe(s.get("name", s.get("PK", "?")))
        action = _action_label(s.get("do"))
        parts = [name, action]
        cat = s.get("category", {})
        if isinstance(cat, dict) and cat.get("name"):
            parts.append(f"category: {cat['name']}")
        elif isinstance(cat, str) and cat:
            parts.append(f"category: {cat}")
        via = s.get("via")
        if via:
            parts[-1] = f"{parts[-1]}"
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
        services = cat.get("services", [])
        lines.append(f"## {cat_name} ({len(services)} services)")
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
            fname = f.get("name", "")
            if fid is not None and fname:
                folder_map[int(fid)] = fname

    lines = []
    for r in rules:
        hostname = _safe(r.get("PK", r.get("hostname", "?")))
        action = _action_label(r.get("do"))
        parts = [hostname, action]
        via = r.get("via")
        if via and action in ("SPOOF", "REDIRECT"):
            parts[-1] = f"{action} -> {via}"
        group = r.get("group")
        if group is not None:
            fname = folder_map.get(int(group), str(group))
            parts.append(f"folder: {fname}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def format_default_rule(rule: dict[str, Any]) -> str:
    """Format default rule status."""
    action = _action_label(rule.get("do"))
    via = rule.get("via", "")
    status = _on_off(rule.get("status"))
    parts = [f"Default rule: {action}"]
    if via and action in ("SPOOF", "REDIRECT"):
        parts[0] = f"Default rule: {action} -> {via}"
    if status:
        parts.append(f"status: {status}")
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
        dtype = d.get("device_type")
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
    dtype = device.get("device_type")
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
            desc = lvl.get("description", "")
            if desc:
                parts.append(_truncate(desc, 80))
            lines.append(" | ".join(parts))

    if endpoints:
        lines.append("\n## Storage Regions")
        for ep in endpoints:
            parts = [_safe(ep.get("PK", ep.get("name", "?")))]
            loc = ep.get("location", ep.get("description", ""))
            if loc:
                parts.append(loc)
            lines.append(" | ".join(parts))

    return "\n".join(lines) if lines else "(no analytics configuration)"


# ── Write confirmations ─────────────────────────────────────────────


def format_write_result(result: dict[str, Any], action: str) -> str:
    """Format a write operation result."""
    msg = result.get("message", f"{action} completed")
    return f"OK: {msg}" if isinstance(msg, str) else f"OK: {action} completed"
