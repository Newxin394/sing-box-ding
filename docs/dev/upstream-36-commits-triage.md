# 上游主线 36 提交 · 吸收记录与取舍

## 基准坐标

- 本仓库基底：mainline **v1.15.0-alpha.2**（`b4b5af50`，2026-09-05 13:51 "Bump version"）
- 上游 tip：**`b84b42bc`**（2026-09-12 18:52 "Add go TUN stack"），挂在 `refs/remotes/official/testing`
- 差距：**36 个提交**（`git rev-list --count b4b5af50..official/testing`）

## 关键约束（决定取舍形式）

1. **remote 里没有官方仓库**。`upstream` 指向 `CHIZI-0618/sing-box`，`origin` 指向 `Newxin394/sing-box-ding`，
   `chizi-fork` 指向 `Newxin394/sing-box`，`ref1nd` 是本地路径 `D:/AI/ref1nd-build`。
   官方 `SagerNet/sing-box` 是另行浅 fetch 的，官方主分支名为 **`testing`**（不是 main）。
2. **依赖链是瓶颈**。`go.mod` 用 replace 指向 reF1nd fork：
   `sing-tun v0.9.1-0.20260904094216-8ac41c38bd38`、`sing-anytls`。
   官方 tip 已到 `sing-tun v0.9.4-0.20260912075549`、`sing v0.9.4`。
   **凡"修复"实质只改 go.mod 升 sing-tun 的提交，本仓库无法直接吸收** ——
   真正要决定的是「reF1nd 的 sing-tun fork 是否跟进上游」，不是逐个 cherry-pick。
3. 本地已有 `tun.Port` 接口（`re!f1nd/sing-tun@v0.9.1-0.20260904094216/flow.go:58`），
   所以依赖该 API 的提交**不需要先升依赖**。

## 已落地：15 条

手工应用（1 条）：

- `f9099970` Fix bypass with outbound not bypassing in pre-match → 本地 `ac60d220`
  - `adapter/router.go` 的 `PreMatchBypass` 补 `Port`/`UDPTimeout`/`NewTracker`
  - `route/route.go` 的 `RuleActionBypass` 先跑 flow、非 `PreMatchFlow` 则降级为 bypass
  - **只取代码，不取 go.mod**（那是把 sing-tun 降到正式版 v0.9.1，与本仓库 replace 冲突）

cherry-pick（14 条，按提交顺序）：

| 上游 SHA | 本地 SHA | 标题 |
|---|---|---|
| `288411b0` | `31202a71` | Fix crash when interface monitor is unavailable |
| `0265f31f` | `bfabdc4d` | Fix Linux process path lookup after privilege drop |
| `d6ec014c` | `445dab7d` | Fix omitempty for JSON struct fields |
| `046c46ea` | `d3602226` | Fix config check sharing service registry with the running instance |
| `f87377cd` | `69c8cb0a` | Add platform metadata to reports |
| `c3c7b2a2` | `953ec3b3` | Record reloads in reports and dump heap on reset |
| `8a0dbdf7` | `e959d454` | Add goroutine dump and hang trigger to libbox |
| `4ef3432c` | `1c85db21` | Fix Linux process search matching the wrong socket |
| `5c849136` | `3238e2fb` | Keep idle connections across short device sleeps |
| `89ca622e` | `fa9aeac3` | Fix WireGuard endpoint stuck after network change on macOS |
| `bcf76878` | `5ecf14ac` | Wake the current instance after device pause on iOS |
| `eee983b3` | `19465f2e` | Use screen state to end device pause on iOS |
| `b7eb49bb` | `596197e8` | Fix cronet-go |
| `378f151c` | `6793fb9c` | documentation: Fix endpoint_independent_nat |

备份分支：`backup/pre-upstream-pick`（= `ac60d220`，即手工提交后的状态）。

## 内容已存在（空补丁，无需动作）：3 条

`59760e6c`、`218ce4b1`、`1111604c` —— cherry-pick 报 "previous cherry-pick is now empty"，
对应的等价改动已在仓库中。

## 搁置：18 条（真冲突，需手工三方合并）

| 上游 SHA | 标题 | 冲突文件 |
|---|---|---|
| `515a73e4` | Fix selector not interrupting routed connections | `protocol/group/selector.go` |
| `c129a806` | Buffer cache file writes | `experimental/cachefile/dns_cache.go` 等 |
| `a93416c8` | Improve process search | `common/process/searcher_linux.go` |
| `5f774fd2` | Report every process sharing a socket in Linux process search | `common/process/searcher_linux.go` |
| `0d7fae13` | Fix process search for socks UDP associate | `go.mod` |
| `6364d9a5` | Fix WireGuard endpoint stopping on device sleep | `transport/wireguard/endpoint.go` |
| `70d0ba72` | Fix network monitor spinning after netlink receive overrun | `go.mod`（修在 sing-tun v0.9.2 内） |
| `8d0500ed` | Fix auto redirect pre-match and L3 forwarding | `go.mod` |
| `2950ce9e` | Implement fully functional auto redirect for Android | `go.mod`、`protocol/tun/inbound.go`、TUN 文档 |
| `b011cf5b` | Close idle connections of unreferenced outbounds and DNS servers | `adapter/outbound.go`、`box.go`、`protocol/*/outbound.go` |
| `86377efc` | Improve idle connection management | `daemon/instance.go` 等 60+ 文件 |
| `a5395a22` | Improve power report attribution and sampling | `common/dialer/default.go`、`daemon/instance.go` |
| `b84b42bc` | Add go TUN stack | `common/interrupt/conn.go`、`route/conn.go`、`constant/network.go` |
| `0c041aa7` | Fix direct inbound UDP on 32-bit Linux before 5.1 | `go.mod` |
| `b2a5ac3f` | Fix Tailscale endpoint not binding IPv6 sockets on Windows | `go.mod` |
| `6d1fc214` | Authorize enabling insecure mode with PolicyKit on Linux | `experimental/boxdd/authorize_linux.go` |
| `a713c4ff` | Load rule-sets through mmap on iOS | `go.mod`、`route/rule/rule_set_*.go` |
| `9a6e6b9b` | Migrate anytls into our own library | `go.mod`、`protocol/anytls/*` |

**处理优先级建议**：`a93416c8` / `5f774fd2`（进程搜索，uid 判定正确性，直接关系 eBPF 分流）
> `70d0ba72`（netlink overrun 空转，与 WiFi 抖动史对应，但受依赖链阻塞）
> `515a73e4` / `c129a806`（单点、低耦合）> 其余（大改或平台无关）。

## 编译验证：通过

必须带工具链约束与链接参数，缺一即误报：

```bash
TAGS="with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0"
GOTOOLCHAIN=go1.25.5 GOOS=android GOARCH=arm64 \
  go build -tags "$TAGS" -ldflags=-checklinkname=0 ./...
```

→ 退出码 0。`linux/amd64` 同样通过。15 条 cherry-pick + 1 条手工提交 + 1 条修复均在树内。

### 三个坑（按暴露顺序）

**1. 工具链版本（根因）**：本机 `go1.27.0`，而 go.mod 声明 `go 1.25.5`。
Go 1.27 解析该模块图失败，把所有依赖包误报为 `no required module provides package`
（130 行错误、零语法错）。加 `GOTOOLCHAIN=go1.25.5` 后单包编译立即通过。
环境值：`GOROOT=C:\Program Files\Go`、`GOMODCACHE=D:\GoCache\mod`、`GOFLAGS` 空、`GOTOOLCHAIN=auto`。

排查中曾误判为 module cache 损坏，`go clean -modcache` 重建了 2.5 G（无害但非必要）；
另有一次手工解压 zip 填空目录的尝试，内层前缀取错，后由重新下载覆盖。
**换用 go1.25.5 后这些都不再相关。**

**2. `-checklinkname=0`**：`experimental/libbox/internal/oomprofile/linkname.go:42`
用 `//go:linkname` 引用 `runtime/pprof.parseProcSelfMaps`，Go 1.23+ 的链接检查会拒绝。
项目本来就依赖 `cmd/internal/build_shared/flags.go:9` 的 `-checklinkname=0` 与
`tfogo_checklinkname0` 标签，只有手动 build 漏带时才暴露。

**3. 一个真实类型错误（已修，`4ea764b5`）**：`provider/parser/clash.go:416-417`。
`445dab7d`（上游 `d6ec014c` "Fix omitempty for JSON struct fields"）把
`option/http.go` 的 `StreamReceiveWindow` / `ConnectionReceiveWindow` 改成
`*byteformats.MemoryBytes`，而 `provider/parser/clash.go` 是本地独有文件
（`863a755b add outbound provider`），上游从未改动它 —— 所以 cherry-pick
不携带对应调用点修改。已把 `clashMemoryBytes` 的返回值改为指针，两处调用点自动适配，
且它们是该函数的全部调用点。

## 复核要点（未逐条读 diff）

多数"是否需要新版依赖"的判断依据是 go.mod 变更，其余按标题与改动范围推断。
落某一批前需展开确认 API 版本门槛。
