# 实验性

!!! quote "sing-box 1.8.0 中的更改"

    :material-plus: [cache_file](#cache_file)  
    :material-alert-decagram: [clash_api](#clash_api)

### 结构

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

### 字段

| 键            | 格式                       |
|--------------|--------------------------|
| `cache_file` | [缓存文件](./cache-file/)     |
| `clash_api`  | [Clash API](./clash-api/) |
| `observability` | [可观测性](observability.md) |
| `v2ray_api`  | [V2Ray API](./v2ray-api/) |
| `health_check_concurrency` | 整数 |

#### health_check_concurrency

限制当前 sing-box 实例内所有 URLTest 和 Provider 健康检查探测的总并发数。`0` 表示不设置全局限制，保留原有的分组内并发行为。该限制不影响应用代理流量。
