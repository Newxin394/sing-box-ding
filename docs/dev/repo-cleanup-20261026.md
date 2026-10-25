# 仓库整理记录 2026-10-26

本次整理只做「减面」：删掉对本 fork 无用的构建脚本、收敛分支、把一次性测试文档归档到 `docs/dev/`。
所有被删除的历史提交仍然可达，见文末归档标签。

## 一、根目录清理

| 文件 | 处理 | 理由 |
| --- | --- | --- |
| `build_a9.sh` | 删除 | 硬编码 `/var/minis/shared/singme-build`，只在临时构建机上成立 |
| `build_v30.sh` | 删除 | 同上，且版本号已过时 |
| `build_tc.sh` | 删除 | 硬编码 `/var/minis/workspace/align/sbding` 与 `/opt/go126` |
| `migrate_build.sh` | 删除 | 一次性迁移实验（gVisor→sing-tun 覆盖 17 文件），已完成 |
| `tc-tun-bench-20261001.md` | → `docs/dev/tc-vs-tun-bench-20261001.md` | 有实测数据，保留但不应占据根目录 |
| `tc-tun-test-summary-20261001.md` | → `docs/dev/tc-vs-tun-summary-20261001.md` | 同上 |

四个脚本里唯一需要留存的其实是**编译参数**，已收敛为：

```sh
sh scripts/build-android-arm64.sh            # 版本号默认取 git describe
sh scripts/build-android-arm64.sh 1.15.0-alpha.13-ding
```

固定保留的 tags：`with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale`。
`with_ebpf` 是纯 TC 入站（`local=tc` + `shared=packet_rewrite`）的前提，缺了它 eBPF 入站根本没有代码。

## 二、分支收敛

远端原有 8 个分支，现在只留 `tc-rewrite-clean`（默认分支，也是唯一在维护的线）。

已并入 `tc-rewrite-clean`、可安全删除的 4 个：

- `ebpf-inbound`（4631d85）
- `tc-rewrite-clean-fixes`（89ac19e）
- `upstream-sync-B`（28df272）
- `sync/official-alpha8`（4cdfecc）

2026-09 中旬留下、内容已被后续重写覆盖的 3 个死支，删除前各打了归档标签：

| 归档标签 | 原分支 | 提交 | 独有提交数 |
| --- | --- | --- | --- |
| `archive/merge-a` | `merge-a` | f9ef7c2 | 11 |
| `archive/port-base-updates` | `port-base-updates` | c3fa393 | 15 |
| `archive/testing-ebpf-tc-rewrite` | `testing-ebpf-tc-rewrite` | 5a34b72 | 12 |

需要翻旧实现时不必恢复分支，直接看标签即可：

```sh
git log --oneline archive/port-base-updates ^HEAD
git diff HEAD archive/port-base-updates -- protocol/ebpf/
```

若确实要恢复成分支：`git push origin archive/port-base-updates:refs/heads/port-base-updates`。
标签确认无用后可用 `git push origin --delete archive/<name>` 清掉。

## 三、忽略规则

`.gitignore` 里原本有两组按日期追加的构建产物条目，合并为一条通配：

```
/sing-box.tc
/sing-box-*
/build2.log
/sb-ding-*
```

`/sing-box-*` 覆盖了 `sing-box-android`、`sing-box-v30`、`sing-box-a9-*` 等所有本地交叉编译产物
（单个 60MB 级别，误提交会直接把仓库撑大）。

## 四、当前形态

```
根目录      只剩 README.md 与上游同构的构建入口
docs/dev/   设计说明、验收标准、实测报告、上游 triage、本文件
scripts/    check-ding-sync.sh、build-android-arm64.sh、vet-baseline
```

上游同步策略仍是「单分支 + 定期 rebase/merge」，不再为每次实验开长期分支；
临时验证用本地分支或 stash，合不进来就删。
