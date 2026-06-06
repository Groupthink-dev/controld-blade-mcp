# controld-blade-mcp

MCP server for [Control-D](https://controld.com) DNS filtering and privacy management. 23 tools covering profiles, filters, services, custom rules, devices, and analytics.

## Install

```bash
uv sync
```

## Configure

| Env var | Required | Description |
|---------|----------|-------------|
| `CONTROLD_API_KEY` | Yes | API token from [controld.com/dashboard/api](https://controld.com/dashboard/api) |
| `CONTROLD_WRITE_ENABLED` | No | Set `true` to enable write operations (default: `false`) |
| `CONTROLD_MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `CONTROLD_MCP_HOST` | No | HTTP bind address (default: `127.0.0.1`) |
| `CONTROLD_MCP_PORT` | No | HTTP port (default: `8767`) |
| `CONTROLD_MCP_API_TOKEN` | When `http` | Bearer token clients must send. **Required to start `http` transport** (loopback-only, never unauthenticated). |

> **Transport policy.** The default `stdio` transport needs no token. The `http`
> transport is a manual loopback path only: the server **refuses to start**
> unless `CONTROLD_MCP_API_TOKEN` is set and `CONTROLD_MCP_HOST` is loopback
> (`127.0.0.1`/`::1`/`localhost`). Control-D tools mutate DNS-filtering policy —
> never expose this surface unauthenticated or on a public interface.

## Usage

### Claude Code

```json
{
  "mcpServers": {
    "controld": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/controld-blade-mcp", "controld-blade-mcp"],
      "env": {
        "CONTROLD_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Stallari

Automatically configured via the pack system. See `stallari-plugin.yaml`.

## Tools (23)

### Read (12)
| Tool | Description |
|------|-------------|
| `cd_info` | Account info + caller IP (health check) |
| `cd_network` | Service availability across PoPs |
| `cd_profiles` | List all profiles |
| `cd_profile` | Single profile detail with options |
| `cd_filters` | Native + external filters (merged) |
| `cd_services` | Active service rules |
| `cd_service_catalog` | Full service catalog (cached 1hr) |
| `cd_rules` | Custom DNS rules by folder |
| `cd_default_rule` | Catch-all rule status |
| `cd_devices` | All DNS endpoints |
| `cd_access` | IPs querying a device |
| `cd_analytics_config` | Log levels + storage regions |

### Write (11, gated)
| Tool | Gate | Description |
|------|------|-------------|
| `cd_profile_create` | write | Create profile |
| `cd_profile_update` | write | Update profile settings |
| `cd_filters_update` | write | Toggle filters (single or batch) |
| `cd_service_update` | write | Set service rule |
| `cd_rule_create` | write | Create custom rule(s) |
| `cd_rule_update` | write | Update custom rule(s) |
| `cd_rule_delete` | write+confirm | Delete custom rule |
| `cd_default_rule_set` | write | Set default rule |
| `cd_device_create` | write | Create DNS endpoint |
| `cd_device_update` | write | Update device settings |
| `cd_access_update` | write+confirm | Authorize/deauthorize IPs |

## Development

```bash
make install-dev    # Install with dev dependencies
make test           # Run unit tests
make check          # Lint + format check + type check
make test-cov       # Tests with coverage
```

## Token Efficiency

Responses use compact pipe-delimited format. Typical costs:

| Operation | ~Tokens |
|-----------|---------|
| `cd_info` | ~40 |
| `cd_profiles` (5 profiles) | ~150 |
| `cd_rules` (20 rules) | ~500 |
| `cd_devices` (10 devices) | ~200 |

## Conformance & hardening (DD-385)

- **Audit surface (CONV-29 / S-AUD-001).** Every tool appends a canonical
  `_meta: {...}` JSON tail on the success path via `stallari-mcp-helpers`
  (`append_meta`/`meta_envelope`). Write tools carry `target_id` + `rows_affected`.
  Gate / confirm / error returns stay plain (no tail). All 23 tools verify
  `match` under `stallari-mcp-lint --strict`.
- **Risk class (DD-280).** The catalog entry declares per-tool `risk_class`:
  12 `read_only`, 9 `external_side_effect`, 2 `high_risk` (`cd_rule_delete`,
  `cd_access_update` — both `write+confirm`).
- **Transport (DD-242).** `http` transport is bearer-mandatory + loopback-only
  (see Transport policy above); `stdio` is the default.
- **Readiness: `production` — live-hardening certification PASSED (v0.4.0).**
  The DD-385 live-capture audit ran against a real Control-D account and fixed
  **12 wire-fidelity defects a 100%-green mocked suite passed straight through**
  — every formatter read keys the API doesn't emit (`stats.rules` vs
  `profile.rule.count`, flat `do` vs `action.do`, top-level filter `status` vs
  per-`levels[]`, `device_type` vs `icon`, …); `cd_rules` 400'd on every default
  call (`/rules/0`); `update_service` silently no-op'd without a required
  `status` field; `format_write_result` crashed on the bare-list delete
  response. The mocks now encode the **captured wire shapes**. 11/11 read tools
  and 6/7 write tools are live-verified end-to-end; `cd_access_update` (device
  IP auth) was not live-fired (real-device blast) but uses the verified
  indexed-array form (`ips[i]`, same as the proven `hostnames[i]`).

## Licence

MIT
