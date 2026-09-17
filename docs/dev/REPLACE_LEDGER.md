# go.mod replace 台账

本仓库在 `go.mod` 里用 `replace` 把两个上游模块指向第三方 fork。**每一条都必须在此登记**，否则时间一长没人记得它们为什么存在，也就没人敢删。

## 当前在册

| 模块 | 指向 | 引入日期 | 原因 | 删除条件 | 复查日期 |
|---|---|---|---|---|---|
| `github.com/sagernet/sing-anytls` | `github.com/reF1nd/sing-anytls` | 待补 | fork 的 `reF1nd-main` 分支相对上游多 5 个 commit：client metadata 空覆盖恢复（`9101d82`）、AnyTLS 0.0.13 互操作、session 复用与空闲生命周期、fallback 请求保留、lazy TFO 地址兼容等 | fork 独有改动已进入上游 | 2026-09-18 |
| `github.com/sagernet/sing-snell` | `github.com/reF1nd/sing-snell` | 待补 | fork 的 `reF1nd-main` 分支相对上游多 7 个 commit：Snell keep-once session draining（`d8a791b`）、UoT framing 修复、UDP/QUIC proxy 处理、defer handshake、协议兼容扩展等。注意 replace 锁定的 `48a266f` 已被 fork 历史重写、不可达，go.mod 的 require 伪版本 `bc5a12a` 已与上游 HEAD 同步，建议后续将 replace 升级到 fork 当前 HEAD | fork 独有改动已进入上游 | 2026-09-18 |

> 已移除：`github.com/sagernet/sing-tun` 的 replace 已由 `f095386b`（build: use upstream sing-tun instead of the reF1nd fork）移除，go.mod 现用上游 `v0.9.4-0.20260916043548-e842d006fa65`，不再登记。
>
> 锁定版本（随每次升级更新）：
> - sing-anytls `v0.0.0-20260905062301-7eeaaeb4fb19`
> - sing-snell `v0.0.0-20260905064728-48a266fb2745`

## 维护规则

1. **新增 replace 必须先在此登记**，并在 commit message 里说明原因。
2. 每次升级依赖时复查"删除条件"列——上游一旦合入对应修复，就删掉 replace 并删本表对应行。
3. 台账行数与 `go.mod` 里 `replace` 的数量由 CI 校验（见 `.github/workflows/lint.yml` 的 *replace ledger check* 步骤），不一致直接失败。

## 如何查证某条 replace 的原因

```sh
# 1. 看 fork 相对上游多出哪些 commit（以 sing-anytls 为例）
git clone --quiet https://github.com/reF1nd/sing-anytls /tmp/fork
cd /tmp/fork
git fetch --quiet https://github.com/sagernet/sing-anytls main:refs/remotes/upstream/main
git log --oneline $(git merge-base upstream/main origin/reF1nd-main)..origin/reF1nd-main

# 2. 对比 go.mod replace 的伪版本号，确认它对应 fork 的哪个提交
#    伪版本末段 7eeaaeb4fb19 就是 commit 前缀
git show 7eeaaeb4fb19 --stat
```

把结论填回"原因"列，并附上上游 issue / PR 链接（如果有）。
