# go.mod replace 台账

本仓库在 `go.mod` 里用 `replace` 把三个上游模块指向第三方 fork。**每一条都必须在此登记**，否则时间一长没人记得它们为什么存在，也就没人敢删。

## 当前在册

| 模块 | 指向 | 引入日期 | 原因 | 删除条件 | 复查日期 |
|---|---|---|---|---|---|
| `github.com/sagernet/sing-tun` | `github.com/reF1nd/sing-tun` | 待补 | **待补**：查 fork 相对上游多出的 commit 后填写（见下方"如何查证"） | fork 独有改动已进入上游 | 2026-09-11 |
| `github.com/sagernet/sing-anytls` | `github.com/reF1nd/sing-anytls` | 待补 | 同上 | 同上 | 2026-09-11 |
| `github.com/sagernet/sing-snell` | `github.com/reF1nd/sing-snell` | 待补 | 同上 | 同上 | 2026-09-11 |

> 锁定版本（随每次升级更新）：
> - sing-tun `v0.9.1-0.20260904094216-8ac41c38bd38`
> - sing-anytls `v0.0.0-20260905062301-7eeaaeb4fb19`
> - sing-snell `v0.0.0-20260905064728-48a266fb2745`

## 维护规则

1. **新增 replace 必须先在此登记**，并在 commit message 里说明原因。
2. 每次升级依赖时复查"删除条件"列——上游一旦合入对应修复，就删掉 replace 并删本表对应行。
3. 台账行数与 `go.mod` 里 `replace` 的数量由 CI 校验（见 `.github/workflows/lint.yml` 的 *replace ledger check* 步骤），不一致直接失败。

## 如何查证某条 replace 的原因

```sh
# 1. 看 fork 相对上游多出哪些 commit（以 sing-tun 为例）
git clone --quiet https://github.com/reF1nd/sing-tun /tmp/fork
cd /tmp/fork
git log --oneline $(git merge-base HEAD origin/main)..HEAD 2>/dev/null || git log --oneline -20

# 2. 对比 go.mod replace 的伪版本号，确认它对应 fork 的哪个提交
#    伪版本末段 8ac41c38bd38 就是 commit 前缀
git show 8ac41c38bd38 --stat
```

把结论填回"原因"列，并附上上游 issue / PR 链接（如果有）。
