# ding-direct 免流通道支持 —— 修改说明与致谢

本仓库（`sing-box-ding`）在 CHIZI-0618/sing-box 的 `testing-ebpf-tc-rewrite` 分支基础上，
新增了对 HTTP CONNECT 代理「直连（ding-direct）的支持。

## 修改了什么

新增 `protocol/http/ding.go`（183 行），并在 `protocol/http/outbound.go` 中接入。

原版 sing-box 使用上游 `sagernet/sing` 的 HTTP 客户端。当配置里出现自定义头
`With-At: gw.alicdn.com` 时，原版会把它当成一个**普通请求头**原样发给代理服务器，
运营商免流网关根本不识别，因此一直无法免流。

本修改的行为是：当出站配置带 `With-At` 头时，**把它从普通头里摘出来**，
拼到 CONNECT 请求行的目标后面，形成这样的报文：

```
CONNECT xxxxxx:443@xxxxxxx HTTP/1.1
Host: xxxxxxxx:443
X-T5-Auth: 683556433
```

原理：代理端按 `userinfo@host` 解析，取 `@` 前面作为真实目标去转发；
> 未配置 `With-At` 头时，行为与原版完全一致（字节级相同），不影响正常使用。

## 使用方法

在 http 出站的 `headers` 里加一行即可，例如：

```jsonc
{
  "type": "http",
  "server": "xxxxxxx",
  "server_port": 443,
  "headers": {
    "Host":       "xxxxxx",
    "X-T5-Auth":  "683556433",
    "With-At":    "xxxxxxx"
  }
}
```

注意：`Host` 与 `X-T5-Auth` 不可省略（二者缺一即 403），`With-At` 为直连叠加项。

## 代码来源与致谢

本功能**核心逻辑并非原创**，移植自开源作者 PuerNya 的既有实现，特此致谢：

| 来源 | 仓库 | 提交 | 说明 | 许可证 |
|---|---|---|---|---|
| 基础实现 | [SagerNet/sing](https://github.com/SagerNet/sing) | `v0.9.0-beta.4` (`02ea509`) | 全部 HTTP CONNECT 客户端代码，作为 `ding.go` 的 vendored 底稿 | Apache-2.0 |
| ding 逻辑 | [puernya/sing](https://github.com/puernya/sing) | `6e86c4f` (2023-10-12) · `c7a2473` (2024-01-25) · `b282450` (2024-12-25) | `ding` 字段 + `目标 + "@" + 域名` 的拼接实现，作者 PuerNya | Apache-2.0 |
| 配置示例 | [SingBox_For_Magisk](https://github.com/PuerNya/sing-box)（`building` 分支模块） | `067c81a7` (2024-08-14) | `百度直连.yaml` 揭示 `With-At` 与 `X-T5-Auth`/`Host` 的真实用法 | AGPL-3.0 |

由衷感谢 **PuerNya**（safarier@outlook.com）多年对 sing-box 生态的贡献，
本仓库的 ding-direct 支持完全建立在 TA 的原创工作之上。
