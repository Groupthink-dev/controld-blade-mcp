# controld-blade-mcp

MCP server for [Control-D](https://controld.com) DNS filtering and privacy management. 22 tools covering profiles, filters, services, custom rules, devices, and analytics.

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
| `CONTROLD_MCP_API_TOKEN` | No | Bearer token for HTTP transport auth |

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

### Sidereal

Automatically configured via pack system. See `sidereal-plugin.yaml`.

## Tools (22)

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

### Write (10, gated)
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

## Licence

MIT
