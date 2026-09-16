# Experimental

!!! quote "Changes in sing-box 1.8.0"

    :material-plus: [cache_file](#cache_file)  
    :material-alert-decagram: [clash_api](#clash_api)

### Structure

```json
{
  "experimental": {
    "cache_file": {},
    "clash_api": {},
    "observability": {},
    "v2ray_api": {},
    "health_check_concurrency": 32
  }
}
```

### Fields

| Key          | Format                     |
|--------------|----------------------------|
| `cache_file` | [Cache File](./cache-file/) |
| `clash_api`  | [Clash API](./clash-api/)   |
| `observability` | [Observability](observability.md) |
| `v2ray_api`  | [V2Ray API](./v2ray-api/)   |
| `health_check_concurrency` | Integer |

#### health_check_concurrency

Limits concurrent URLTest and provider health-check probes across this sing-box instance. `0` disables the global limit and preserves the default per-group behavior. This limit does not affect proxied application traffic.
