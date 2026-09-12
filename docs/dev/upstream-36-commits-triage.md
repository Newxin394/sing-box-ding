# 上游主线 36 提交 · 吸收记录与取舍

## 基准坐标

- 本仓库基底：mainline **v1.15.0-alpha.2**（`b4b5af50`，2026-09-05 13:51 "Bump version"）
- 上游 tip：**`b84b42bc`**（2026-09-12 18:52 "Add go TUN stack"），挂在 `refs/remotes/official/testing`
- 差距：**36 个提交**（`git rev-list --count b4b5af50..official/testing`）

## 关键约束（决定取舍形式）

1. **remote 里没有官方仓库**。`upstream` 指向 `CHIZI-0618/sing-box`，`origin` 指向 `Newxin394/sing-box-ding`，
   `chizi-fork` 指向 `Newxin394/sing-box`，`ref1nd` 是本地路径 `D:/AI/ref1nd-build`。
   官方 `SagerNet/sing-box` 是另行浅 fetch 的，官方主分支名为 **`testing`**（不是 main）。
2. **依赖链已跟进**。`go.mod` 的 replace 一度指向停在 `v0.9.1` 的 reF1nd fork，
   而官方 tip 已到 `sing v0.9.4` / `sing-tun v0.9.4-0.20260912075549`。
   `d78483bd` 把 `sing` 升到 `v0.9.4-0.20260912053229`、`sing-tun` 换到
   `reF1nd/dev`（`25060df`），4 条依赖阻塞提交由此解开。
   **凡"修复"实质只改 go.mod 升依赖的提交，形式上是 cherry-pick、实质是版本对齐** ——
   冲突只落在 go.mod/go.sum，取 HEAD 后净变化为零即说明修复已随新版本到位。
3. 本地已有 `tun.Port` 接口（`re!f1nd/sing-tun@v0.9.1-0.20260909111036/flow.go:58`），
   所以依赖该 API 的提交**不需要先升依赖**。
## 已落地：22 条

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

手工三方合并（6 条，原"搁置"里真正可吸收的部分）：

| 上游 SHA | 本地 SHA | 标题 | 冲突处理 |
|---|---|---|---|
| `a93416c8` | `2e6c2eda` | Improve process search | `searcher_linux.go` 取本地（`completeProcessInfo()` 已覆盖上游内联逻辑）；`connections.go` 取上游（ProcessPaths 优先）；`resolve1.go` 取本地（上游后续 `59760e6c` 正是改回 `ReadFile`） |
| `5f774fd2` | `ef31e1a2` | Report every process sharing a socket | 本地已有多路径实现（`buildProcessPaths` 返回 `map[uint32][]string`），仅 import 行合并 `slices` + `strconv` |
| `515a73e4` | `f81c5d4a` | Fix selector not interrupting routed connections | 取上游 `selected` 优先逻辑（本地已有 `adapter.ConnectionHandler` 接口） |
| `0d7fae13` | `f8dd4344` | Fix process search for socks UDP associate | go.mod/go.sum 取本地；socks/mixed inbound 各加 2 行 |
| `8d0500ed` | `537a9b7c` | Fix auto redirect pre-match and L3 forwarding | go.mod 取本地；`route/route.go` 加 3 行 ICMP 处理 |
| `6d1fc214` | `b740d096` | Authorize enabling insecure mode with PolicyKit | 采纳上游的文件合并结构，PolicyKit action 保留本地品牌前缀 `io.reF1nd.sfl`，补上游新增的 `set-insecure-mode` |

另有 1 条本地独有文件的类型修复（不是上游提交）：

- `4ea764b5` fix(parser): return pointer from clashMemoryBytes

备份分支：`backup/pre-upstream-pick`（= `ac60d220`，即手工提交后的状态）。

## 内容已存在（空补丁，无需动作）：3 条

`59760e6c`、`218ce4b1`、`1111604c` —— cherry-pick 报 "previous cherry-pick is now empty"，
对应的等价改动已在仓库中。
## 语义已存在：11 条（无需吸收）

空补丁（3 条，cherry-pick 报 "previous cherry-pick is now empty"）：

`59760e6c`、`218ce4b1`、`1111604c`

本地基底已有同名提交（6 条，改动都已在 `origin/testing-ebpf-tc-rewrite` 的 2880 条历史里）：

| 上游 SHA | 标题 |
|---|---|
| `a713c4ff` | Load rule-sets through mmap on iOS |
| `2950ce9e` | Implement fully functional auto redirect for Android |
| `b011cf5b` | Close idle connections of unreferenced outbounds and DNS servers |
| `86377efc` | Improve idle connection management |
| `a5395a22` | Improve power report attribution and sampling |
| `9a6e6b9b` | Migrate anytls into our own library |

本地独立实现已覆盖（2 条）：

- `6364d9a5` Fix WireGuard endpoint stopping on device sleep —— 本地
  `transport/wireguard/endpoint.go` 的 `case` 行早已是 `pause.EventNetworkPause` /
  `pause.EventNetworkWake`（不含 `EventDevicePaused`），且本地多了 `networkPaused`
  标志与 `pause.IsPaused() || suspended` 保护。cherry-pick 解决后与 HEAD 完全一致，`--skip`。
- `c129a806` Buffer cache file writes —— 本地 `402bf831` 与上游**同名同规模**
  （都是 `15 files changed, 517 insertions(+), 339 deletions(-)`），且之后还有
  `a1cbb94c DNS: Fix some cache issues` 的进一步修复。

## 依赖阻塞：4 条（已全部解决）

四条都只是「依赖版本」的不同表现，不是取舍问题。先统一依赖，再逐条处理。

### 依赖升级（提交 `d78483bd`）

| 依赖 | 原 | 现 |
|---|---|---|
| `github.com/sagernet/sing` | `v0.9.1-0.20260904133552-ffcabb706b1c` | `v0.9.4-0.20260912053229-7776850263cd` |
| `replace` `sing-tun` | `reF1nd/sing-tun v0.9.1-0.20260904094216-8ac41c38bd38` | `reF1nd/sing-tun v0.9.1-0.20260909111036-25060dfbbb5f`（`dev` 分支 tip） |

选 `reF1nd/dev`（`25060df Add go stack`）而不是官方 `869f0a4`，是因为它带
`tun.MemoryPressure` 且保留 reF1nd 的定制（`81b66829` 引入的虚拟 TUN DNS
ICMP 本地应答）。官方 `869f0a4` 同样包含 `answerEcho`
（`stack_go_engine.go:876`），所以该定制在功能上并不唯一，但**切换 fork 属于
减法，按既定原则留到后面**。

### 逐条结果

| 上游 SHA | 标题 | 处理 | 依据 |
|---|---|---|---|
| `0c041aa7` | Fix direct inbound UDP on 32-bit Linux before privilege drop | **已覆盖** | 实质是 `sing v0.9.1 → v0.9.2`，现为 v0.9.4 |
| `b2a5ac3f` | Fix Tailscale endpoint not binding IPv6 socket | **已覆盖** | 实质是 `sing v0.9.2 → v0.9.3`，现为 v0.9.4 |
| `b84b42bc` | Add go TUN stack | **已吸收** | `c8dc68f3` + `2aba258f` + `80f6901a` |
| `70d0ba72` | Fix network monitor spinning after netlink receive overrun | **未覆盖（待办）** | 实质是 `sing-tun v0.9.1 → v0.9.2`，fork 仍停在 v0.9.1 基线 |

前两条 cherry-pick 时只冲突 `go.mod`/`go.sum`，`git checkout HEAD -- go.mod go.sum`
后净变化为零，`--skip` 收场；因为 `sing` 已升到 v0.9.4，两条修复实际已在。

### 待办：`70d0ba72` 的 netlink overrun 修复

官方 `monitor_linux.go:92`：

```go
_, err := m.socket.Read(buffer)
if err != nil && !errors.Is(err, unix.ENOBUFS) {
```

reF1nd 的 `dev` 分支没有这个 `ENOBUFS` 判断，netlink 接收缓冲区溢出时
`loopRead` 会直接 `return`（reF1nd 的 `main` 分支 `c11c256` 有、`dev` 没有）。
影响面：Linux 上路由/接口消息突发后网络变化监听停摆，Android 切网场景可能触发。

三条可选路线，**全部属于减法或改依赖，按原则留后**：

1. 等 reF1nd 把 `dev` 分支 rebase 到官方 `869f0a4` —— 零成本，被动。
2. 把 `replace` 换成官方 `sing-tun v0.9.4-0.20260912075549-869f0a4` —— 一次拿到
   netlink 修复 + 最新 go stack + `SplicePacketOptions.Offload`，代价是丢掉
   reF1nd fork 的 5 个独有文件与 34 个文件差异。
3. 维持现状 —— 只有这一个已知缺口，其余功能完整。

### `b84b42bc` 的适配

依赖到位后该提交 22 个文件中有 8 个冲突，逐文件解决。另有四处 fork 与官方
`869f0a4` 的 API 漂移需要桥接，**全部按加法处理，不删本地代码**：

| 位置 | 官方 `869f0a4` | reF1nd `dev` | 处理 |
|---|---|---|---|
| `SpliceSocket.Attach` | `Attach(io.Closer) (io.Closer, bool)` | `Attach(io.Closer) bool` | 保留 `socketOwner` 原两值语义为未导出 `attach`，其上叠加满足 fork 接口的 `Attach` 薄包装 |
| `SplicePacketOptions` | 有 `Offload`/`FrontHeadroom`/`RearHeadroom` | 无 | 保留 `offload` 字段与原始 `unwrapSpliceTarget` 分支不动；保护条件加到 splice 调用点（`target.offload == nil &&`），offload 连接走回退路径而不是静默丢描述符 |
| `interrupt.PacketConn` / `trackedPacketConn` 的 `ReadPacket`/`WritePacket` | 无（靠接口提升） | 无 | 保留 `6a66df0e` 加的两个方法，改为读 `NetPacketConn` 字段并保留 `net.PacketConn` 类型断言回退 |
| `PacketConn` 嵌入字段 | `net.PacketConn` → `N.NetPacketConn` | 同官方 | 随上游 |

**对账**：24 吸收（21 + `b84b42bc` + 2 条随 `sing` 升级覆盖）+ 11 语义已存在 +
1 待办（`70d0ba72`）= **36**，与基准差距一致。

## 验证：通过

两个构建目标，必须带工具链约束与链接参数，缺一即误报：

```bash
TAGS="with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0"
GOTOOLCHAIN=go1.25.5 GOOS=android GOARCH=arm64 \
  go build -tags "$TAGS" -ldflags=-checklinkname=0 ./...
```

→ 退出码 0；`linux/amd64` 同样通过。29 个提交全部在树内。

订阅组功能回归（windows/amd64 本机执行；`with_ebpf` 仅 Linux 可用故去掉）：

```bash
GOTOOLCHAIN=go1.25.5 GOOS=windows GOARCH=amd64 go test \
  -tags "with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0" \
  -ldflags=-checklinkname=0 -count=1 ./protocol/group/... ./provider/...
```

→ `ok` 4/4：`protocol/group`、`provider/local`、`provider/parser`、`provider/remote`。

这条必须跑：`515a73e4` 动过 `protocol/group/selector.go`，而该文件是本地 510 行的
定制版（`PreMatchOutboundGroup`、`SelectorUpdateCallback`/`SelectorUpdateGuard`、
`UDPOutbound`/`UDPFallbackOutbound`、`provider` 管理器），一旦被上游覆盖即失去订阅组行为。


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

**工作原则（已定）**：优先加法 —— 不改动本仓库现有实现，只做新增；
确需减法的改动（例如把 `sing-tun` fork 换成官方版本）一律留到后面单独处理。

**剩余唯一待办**：`70d0ba72` 的 netlink overrun 修复（见上文 §待办）。
