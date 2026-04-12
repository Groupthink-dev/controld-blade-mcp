# Control-D Blade MCP — Skill Reference

## Token Efficiency Rules (mandatory)

1. Use `cd_profiles` for overview, `cd_profile` only for single-profile detail
2. Use `cd_filters` to see all filters at once (native + external merged)
3. Use `cd_service_catalog` sparingly — it's cached but large. Prefer `cd_services` for active rules
4. Use `cd_rules` with `folder_id` to scope to a specific folder
5. Never fetch all profiles then filter client-side — read the one you need via `cd_profile`

## Quick Start (5 most common)

```
cd_info                                    # Health check + account info
cd_profiles                                # List all profiles
cd_rules profile_id="abc123"               # List rules on a profile
cd_devices                                 # List all DNS endpoints
cd_filters profile_id="abc123"             # See filter status
```

## Common Workflows

### Audit a profile's DNS policy
```
cd_profile profile_id="abc123"             # Profile overview
cd_filters profile_id="abc123"             # Filter status
cd_services profile_id="abc123"            # Active service rules
cd_rules profile_id="abc123"               # Custom rules
cd_default_rule profile_id="abc123"        # Catch-all rule
```

### Block a domain
```
cd_rule_create profile_id="abc123" hostnames=["ads.example.com"] action=0
```
Action codes: 0=BLOCK, 1=BYPASS, 2=SPOOF, 3=REDIRECT

### Route a service through a proxy
```
cd_service_catalog                         # Find service ID + proxy location
cd_service_update profile_id="abc123" service_id="netflix" action=2 via="uk-lon"
```

### Manage devices
```
cd_devices                                 # List all endpoints
cd_device_create name="Router" profile_id="abc123" device_type="router"
cd_access device_id="dev001"               # See which IPs are querying
```

### Check connectivity
```
cd_info                                    # Account + IP + PoP
cd_network                                 # Service status across PoPs
```

## Output Format

All tools return compact pipe-delimited strings:

```
# Profiles
ID: abc123 | Main Profile | rules: 47 | devices: 3
ID: def456 | Kids Profile | rules: 12 | devices: 2 | locked

# Rules
example.com | BLOCK | folder: Ads
netflix.com | SPOOF -> uk-lon | folder: Streaming

# Devices
ID: dev001 | MacBook Pro | profile: Main Profile | type: macos | status: active
```

## Security Notes

- Write operations blocked unless `CONTROLD_WRITE_ENABLED=true`
- `cd_rule_delete` and `cd_access_update` require `confirm=true` (double gate)
- API key never appears in tool output (credential scrubbing)
- Bearer token auth available for HTTP transport (`CONTROLD_MCP_API_TOKEN`)
- Retry with exponential backoff on 429/5xx (max 3 attempts)
