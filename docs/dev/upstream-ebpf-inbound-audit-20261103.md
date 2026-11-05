# 上游 `ebpf-inbound` 完整功能审核对比

对比对象：`CHIZI-0618/sing-box` 分支 `ebpf-inbound`（HEAD `3d776177`，2026-11-01）↔ 本 fork `tc-rewrite-clean`（HEAD `6fdd2d4a`，2026-10-26）

对比方法：两仓 `git clone --filter=blob:none` 到本地（`D:\AI\singbox\repo` / `D:\AI\singbox\parent`），文件清单用 `ls-tree -r HEAD` 对拼，共有文件用 `git hash-object --no-filters` 逐字节比对，父独有的符号在全仓回查（排除 `_test`），再按实现语义人工判定。

---

## 0. 结论先说

**上游那两个提交不是"新增功能"，而是把我们 fork 的 eBPF 工作 rebase 到 2026-09-24 之后的新基线，再一次性落成快照。** 证据有三条：

1. `f1a62df` 一次提交就是 104 文件 / +20521 −469，把 `protocol/ebpf/` 整个包（含我们 9 月份就在写的 `udp_nat.go`、`redirect_route.go`、`warning_limiter.go`、`interface_monitor.go`）当作**新文件**重新加了进去；
2. eBPF 相关 55 个共有文件逐个哈希比对，**没有一对是相同的**——不是"我们落后于上游"，而是两边各自演进、形状不同；
3. `git diff af6e64c3 3d776177` 是 682 文件 / +51494 −12396，那才是真实跨度：上游 9-24 之后的所有演进（`transport/http`、`transport/masque`、`tailcat`、`common/kernelports`、`sagernet/sing` 从 9-22 升到 10-23、`sing-tun` 升到 10-28）全在里面。

所以要回答"我们缺什么"，不能按文件名看，得按能力看。真正的跨进程能力缺口只有 **4 项**（第 3 节），其中只有 1 项是 eBPF 相关。

---

## 1. 仓库规模对照

| | fork `tc-rewrite-clean` | upstream `ebpf-inbound` |
|---|---:|---:|
| tracked 文件 | 2,073 | 1,737 |
| `protocol/ebpf/` | 89 文件 / 858 KB | 62 文件 / 537.7 KB |
| `common/ebpf/` | **117 文件 / 1,798.9 KB（内联）** | **0（外部模块 `sing-ebpf`）** |
| `option/ebpf.go` | 9,131 B | 5,112 B |
| `adapter/ebpf.go` | — | 6,416 B |
| `daemon/started_service_ebpf.go` | — | 12,200 B |
| `experimental/clashapi/ebpf.go` | 2,800 B | — |
| `cmd/sing-box/cmd_api_ebpf.go` | — | 1,100 B |
| `protocol/group/urltest.go` | 38.5 KB | 15.7 KB |
| `protocol/http/ding.go` | 6.6 KB | — |
| `sagernet/sing` | `v0.9.7-0.2026**0929**150544-6f21f2425a95` | `v0.9.7-0.2026**1023**115510-03a6cce64bf7` |
| `sagernet/sing-tun` | `v0.9.7-0.2026**1002**083955-3f8acd9da65b` | `v0.9.7-0.2026**1028**024126-5b0a1a7a394e` |
| eBPF 后端来源 | 内联 `common/ebpf` + vendored `cilium/ebpf` | `github.com/CHIZI-0618/sing-ebpf v0.1.0-alpha.13.…-d904cb7932c5` |

同一件事的两种组织方式：**上游把 eBPF 内核对象抽成独立模块、把 DTO 放到 `adapter`；我们把内核对象内联在 `common/ebpf`、把 DTO 放在 `protocol/ebpf/diagnostics.go`，并用 clashapi 的鸭子类型接口对外。**

---

## 2. 同物异名清单（功能相同，名字/位置不同）

这一节回答"哪些看起来缺、其实有"。

| # | upstream | fork | 说明 |
|---|---|---|---|
| 2.1 | `local.data_plane: cgroup \| socket_assign` | `local.data_plane: cgroup \| tc` | **`socket_assign` ≡ `tc`**，同一套 TCX/clsact 数据面，只是取值名不同。fork 默认 `tc`，上游默认 `cgroup`。 |
| 2.2 | `local.bypass_rule_set` + `shared.bypass_rule_set`（两份） | 顶层 `bypass_rule_set`（一份） | fork 用一个列表编译成一份策略喂 3 个 backend（TC / cgroup / shared）；shared 恒喂 `emptyPolicy`（热点链路上不能 bypass，否则 NAT 前的私网源地址会被上游丢弃，理由写在 `inbound_policy.go` 注释里）。 |
| 2.3 | `adapter/ebpf.go`（DTO + `EBPFDiagnosticsProvider`，`SchemaVersion=18`） | `protocol/ebpf/diagnostics.go`（775 行） | 同一个跨进程快照的两种落点：上游放 `adapter`（跨包，gRPC 直接断言），fork 放 `protocol/ebpf`（包内，clashapi 用鸭子接口）。字段集不同（见 2.6）。 |
| 2.4 | `protocol/ebpf/action_policy.go`（262 行，`compileActionPolicy` / `sharedSourceDefault` / `appendPortDecisions`） | `protocol/ebpf/inbound_policy.go`（`compileBypassCIDRPolicy` → `commonEBPF.CompileBypassCIDRPolicy` + `refreshBypassRuleSetsLocked`） | 上游用 `ActionPolicy{Local,Shared}` + `Decision` 结构；fork 用 `CompiledPolicy` + `PolicyConfig`，UID 段减法在 `common/ebpf/policy.go`（`subtractUIDRanges`，policy.go:88 / :161）。 |
| 2.5 | `protocol/ebpf/cgroup_packet_writer.go`（cgroup 侧写作） | `protocol/ebpf/shared_rewrite_connection.go:213 sharedPacketWriter`（shared 侧写作） | **方向相反不是缺功能**：上游要 cgroup 路径回包，fork 的 cgroup 回包走另一条路（`ReserveUDPReplyRedirect`），shared 网络才需要独立 writer。 |
| 2.6 | `EBPFAttachmentDiagnostics.icmpEchoReply` + `slot` | `EBPFAttachmentDiagnostics.fakeIPICMP`（无 Slot） | 语义相同，字段名不同；fork 没有实例槽位概念（见 2.9）。 |
| 2.7 | 19 个 `EBPFCounters`（含 `tcSocketLookupFailures` / `tcSKAssignFailures` / `tcReturnConflicts` / `tcLocalFragmentPasses` …） | 15 个 `EBPFCounters`（含 `RawIPAttempts` / `RawIPHeadFailures` / `DeliveryParseFailures` …） | 计数维度按各自实现暴露，**互有增减，不是子集关系**：fork 的 RawIP 族上游没有；上游的 fragment-return 族 fork 没有。 |
| 2.8 | `PolicyEpoch{localConfirmed/localExpected/sharedConfirmed/sharedExpected/converged}` | `BypassRuleSet{Consistent,Pending,PolicyVersion,ExpectedPolicyVersion,RetryCount,BackendState map[string]{Version,Known}}` | 上游用"确认/期望双轨 + epoch 收敛"描述策略下发；fork 用一个全局版本序列 + 每 backend 的 `{Version,Known}`。**语义等价、形状不同**。 |
| 2.9 | `protocol/ebpf/tc_runtime.go` / `shared_runtime.go`（别名到 `kernelRuntime.*`） | `tc_dataplane.go`（65.7 KB）自带全套 | 上游是转发壳，fork 是实现在本包。 |
| 2.10 | `protocol/ebpf/tc_listener.go`（`tcListenerHandler`） | `protocol/ebpf/listener.go`（8.3 KB） | 同一 handler 的两种拆法。 |
| 2.11 | `common/dialer/udp_conn.go` | `common/dialer/udp_zero_read_linux.go:21` | `type udpConn` 同名不同文件。 |
| 2.12 | `dialer.PrepareEBPFSelfBypass(...)`（`box.go` 调用） | `common/dialer/default.go` 内 `appendEBPFSelfBypass(...)`（匿名接口断言 `SetEBPFSelfBypass`） | 接线点不同，能力相同；fork 版本还读 `MapCapacity.SelfBypass`。 |
| 2.13 | `adapter.NetworkManager.HostPort()` / `RegisterHostPort` | fork 无此方法；endpoint 自己算 | fork 的 `wireguard` / `openvpn` / `masque` / `tailscale` 各自 `JudgeFlow` 里用 `localAddresses` 判断，不要 HostPort 抽象（见 3.2）。 |

---

## 3. 真正的能力缺口（4 项）

### 3.1 gRPC 诊断 API（upstream 有，fork 无）

- 缺：`daemon/started_service.proto` 的 `rpc GetEBPFDiagnostics` + 14 个 message（`EBPFInboundDiagnostics` 81 字段）+ `started_service_ebpf.go`（265 行）+ `cmd/sing-box/cmd_api_ebpf.go`（48 行，`sing-box api ebpf --deep`）
- 影响：**`sing-box api ebpf` 这个进程外诊断通道用不了**；clashapi 的 `GET /ebpf`、`GET /ebpf/maps`（fork 独有）只能给已经在读 HTTP 的人。
- 代价：本机没有 `protoc`，`make proto` → `go run ./cmd/internal/protogen` 会 `exec.Command("protoc")` 失败。要先装 protoc 才能再生 `.pb.go`（`daemon/started_service.pb.go` 会 +2738 行）。
- 判定：**真实缺口，优先级最高**——这是唯一"上游有、我们完全没有对外出口"的东西。

### 3.2 `adapter/host.go`：host 侧 flow 裁决 + 流量日志

- 缺：`JudgeHostFlow`（80 行）+ `FlowLogger`（实现 `tun.FlowTracker`：`AttachFlow` / `CountForward` / `CountReverse` / `FlowEstablished` / `CloseFlow`），被 `protocol/{masque,openconnect,openvpn,tailscale,wireguard}` 五个 endpoint 和 `route/route.go` 引用。
- fork 现状：这五个 endpoint 各自有 `JudgeFlow`，但**没有"把转发流量引到 host 端口再由 tun 接管"的分支**，也没有逐 flow 字节统计的 tracker。
- 影响：host 模式下的流量日志/统计能力，以及 `tun.RoutedPort` 这条旁路。**与 eBPF 无关**，属上游 10 月功能演进。
- 判定：真实缺口，但对 eBPF 入站的主线（手机端）影响不大。

### 3.3 `common/kernelports/`：内核端口池

- 缺：`Pool`（`Acquire` / `ReserveSelector` / `PortSelectorRanges` / `ExpandSelectorRanges` / `Contains` / `ReleaseSelector`）+ 5 个平台文件，被 `protocol/bridge/backend_windows.go`、`transport/device/system.go`、`transport/wireguard/device_system.go` 使用。
- fork 现状：`protocol/bridge/backend_windows.go` 自己用 `acquirePortReservation(..., bridgeReservedPortCount=1024)` 粗粒度占一段；`transport/device/` 目录在 fork 里根本不存在（上游把 openvpn/openconnect 的 device 栈整体迁到了 `transport/device/`）。
- 判定：真实缺口，属 Windows 侧端口管理。**不影响 Android/Linux 主线**。

### 3.4 ringbuf 异步 UDP 恢复调度（eBPF 相关，唯一一项）

| | upstream | fork |
|---|---|---|
| 触发 | `sock_release` ringbuf 事件 → 1024 深 channel | 无（全仓 grep `ringbuf` 命中 0） |
| 调度 | `container/heap` deadline 堆，`cgroupRecoveryMaxIdle=30s`、`SweepBudget=1024` | 同步调用 `backend.RecoverUDPOriginal()` / `RecoverConnectedUDPOriginal()`（`inbound_connection.go:164-167`） |
| 兜底 | 无 ringbuf 的内核走 `runCgroupRecoveryFallback` 有界低频 sweep | 内核 `socket_release_supported` 时直接返回 `ENOENT`（连接型 UDP LRU 恢复被禁用） |
| 诊断 | — | 有 `ReleaseNotificationDrops` 字段，但**没有生产者，恒为 0** |

- 影响：cgroup 数据面下，内核丢了 `sock_release` 通知时 fork 只能靠同步路径；连接型 UDP 在 socket-release 可用时**放弃 LRU 恢复**。
- 前提：fork 的内联 `common/ebpf` 里也没有 ringbuf 通道，只移植 `protocol/ebpf/cgroup_recovery.go` 不够，得连 `CgroupBackend` 侧一起补。
- 判定：真实缺口，**Android 上 cgroup 是默认数据面，值得做**；工作量比前面三项大。

### 3.5 顺带确认：上游那批 `protocol/ebpf/` 独有文件，除 3.4 外都是"拆文件"

`interface_topology.go`（`repairTCInfrastructure` / `monitoredDefaultInterfaceName` 在 fork 的 `interface_monitor.go:597/543`）、`logging.go`（`ebpfStructuredEvent`）、`maintenance.go`（`startTCAssignmentJanitor` → fork 用 `tc_stale_reclaim.go` + `interface_monitor.go` 的 10 分钟 tick 承担；TC assignment map 本身是 `LRUHash`，内核自己淘汰）、`policy_types.go`（`uidRange` 等）。**均非能力缺口。**

---

## 4. fork 独有（上游完全没有）

按能力归类，共 373 条路径：

- **eBPF**：`common/ebpf/` 整个包（117 文件，含 `native/*.bpf.c`、`internal/bpfgen/*.o`、`kernel_probe.go` 31.7 KB、`testing/checksum_offload_verify.sh` 46.6 KB）；`protocol/ebpf/` 30 个独有文件（`tc_dataplane.go` 65.7 KB、`pre_match_linux.go` 28.7 KB、`bypass_selector.go`、`tc_routing.go`、`tc_sysctl.go`、`tc_stale_reclaim.go`、`capture_owner.go`，以及 `fakeip_icmp_matrix_netns_test.go` 30 KB 等大批 netns 测试）
- **配置面**：`option/ebpf.go` 的 `pre_match`、`map_capacity`（UDP NAT 8192 等全部容量可配）、`bypass_selector`（含保留关键字 `"直连"`）
- **对外出口**：`experimental/clashapi/ebpf.go`（`GET /ebpf`、`GET /ebpf/maps`）、`cmd/sing-box/cmd_tools_ebpf.go`（`sing-box tools ebpf status`，内核能力探测）
- **ding-direct**：`protocol/http/ding.go` + `scripts/check-ding-sync.sh`
- **provider 体系**：`adapter/provider/*`、`provider/{local,parser,remote}/*`（clash/link/sing_box/sip008）
- **group 增强**：`loadbalance.go`（26.1 KB）、`urltest_health.go`、`urltest_schedule.go`、`provider_members.go`
- **协议/传输**：`protocol/cns` + `transport/cns`、`transport/v2rayxhttp`、snell QUIC、`protocol/pass`
- **可观测**：`experimental/observability/*` + Grafana dashboard
- **其它**：`common/{expiringmap,hash,proxyproto,badh2,authuser}`、`deps/fswatch`、`scripts/build-android-arm64.sh`

---

## 5. CI / 工程纪律

| 项 | fork | upstream |
|---|---|---|
| `android-ebpf.yml` | 1,638 B，go 1.26.**6** | 1,660 B，go 1.26.**8** |
| `ebpf-verifier.yml` | 4,611 B，**含 `make -C common/ebpf check`（现场编 BPF 对象）+ 两段 `sudo` 真内核测试（`SING_BOX_EBPF_REQUIRE_TCX=1` 把 TCX 降级变硬失败）** | 3,372 B，只有 `go test -tags with_ebpf` + 版本交叉校验 |
| `lint.yml` | 4,084 B，额外两个 gate：`.golangci.yml run.go` 与 go.mod 对齐、Replace ledger 行数 == `grep -c '^replace ' go.mod` | 1,895 B |
| 独有 workflow | `stale.yml`、`upstream-sync.yml` | — |

→ **fork 的 CI 纪律强于上游**，这一点不用抄。

### 5.1 但 4 个 workflow 现在是失效的（可立即修）

`tc-rewrite-clean` 是唯一分支，而下面这些还写着已归档的 `testing-ebpf-tc-rewrite`：

| 文件 | 行 | 后果 |
|---|---|---|
| `lint.yml` | 9, 20 | push 到 `tc-rewrite-clean` **不触发 lint** |
| `test.yml` | 9, 20 | **不触发 test** |
| `build.yml` | 37 | **不触发 build** |
| `upstream-sync.yml` | `on.push.branches` + `git fetch upstream testing-ebpf-tc-rewrite` | push 不触发；drift job 拿错分支名（上游实际是 `ebpf-inbound`）；merge-base 失败只 `::warning::` + `exit 0` → **每天 cron 静默失败** |

---

## 6. 建议的动手顺序

| 优先级 | 动作 | 依据 |
|---|---|---|
| P0 | 修 4 个 workflow 的分支名（`testing-ebpf-tc-rewrite` → `tc-rewrite-clean`，drift fetch → `ebpf-inbound`，merge-base 失败改 `exit 1`） | 改动小，立刻恢复 lint/test/build 与漂移监控 |
| P1 | 移植 gRPC 诊断 API（`GetEBPFDiagnostics` + proto + `cmd api ebpf`） | 唯一"上游有、我们无对外出口"；需先装 protoc |
| P2 | 移植 ringbuf 异步 UDP 恢复（`cgroup_recovery.go` + `CgroupBackend` 侧通道） | Android cgroup 数据面真实收益，但要连内联 `common/ebpf` 一起改 |
| P3 | `adapter/host.go` + `common/kernelports/` | 属上游 10 月演进，与 eBPF 主线无关；建议等下次整体同步上游时一起带 |
| — | 升 `sagernet/sing` 到 10-23 基线 | fork 落后约 3.5 周；与 P1/P2 一起做能减少重复工作量 |

---

## 7. 复现命令

```bash
git clone --filter=blob:none --no-checkout https://github.com/<repo> && cd <repo>
git -c http.version=HTTP/1.1 checkout -f      # Windows schannel 握手失败时必加

# 文件级
git -C repo   ls-tree -r HEAD --name-only > fork.txt
git -C parent ls-tree -r HEAD --name-only > parent.txt

# 共有文件逐字节
git -C repo hash-object --no-filters "<absolute path>"

# 真实跨度
git -C parent diff --shortstat af6e64c3b69e6132ebaee0e1a3d24e93903f6709 3d776177
```

> 注意：在仓库目录内跑 `git hash-object -- <相对路径>` 会 fatal "could not open"，必须传绝对路径，否则空哈希会被误判成"内容相同"。

---

## 8. 执行记录（2026-11-03 动工）

### 8.1 P0 已完成：4 个 workflow 的分支名

- `lint.yml:9,20`、`test.yml:9,20`、`build.yml:37`：`testing-ebpf-tc-rewrite` → `tc-rewrite-clean`，push / PR 重新触发 lint、test、build。
- `upstream-sync.yml`：`on.push.branches` 改为 `tc-rewrite-clean`；drift job fetch 改为 `ebpf-inbound`；**merge-base 失败从"警告后 exit 0"改成"报错并 exit 1"**，理由是上游一旦再次重写历史，`ahead/behind` 数字就没有意义，静默通过等于让监控说谎。文件里留了一条注释提醒分支名会过期。
- 校验：4 个文件用 `gopkg.in/yaml.v3` 解析全部通过。

### 8.2 P1 已完成：`GetEBPFDiagnostics` 跨进程诊断 API

| 新增/修改 | 作用 |
|---|---|
| `daemon/started_service.proto`（+200） | 新增 `rpc GetEBPFDiagnostics` 与 14 个 EBPF message（schema 版本 **18**，字段号与上游一致） |
| `daemon/started_service.pb.go` / `_grpc.pb.go` | 由 `go run ./cmd/internal/protogen` 重新生成 |
| `adapter/ebpf.go`（新） | `EBPFDiagnosticsSchemaVersion = 18` + `EBPFDiagnosticsProvider` 接口，**无 build tag** |
| `adapter/ebpf_diagnostics.go`（新） | 完整 DTO 层，字段与上游 `adapter/ebpf.go` 对齐 |
| `daemon/started_service_ebpf.go`（新） | `GetEBPFDiagnostics` 实现 + deep 模式的内核运行时合并（按 program/map ID 去重，取最差状态） |
| `daemon/instance.go`（+3） | 暴露 `inboundManager` 供诊断遍历入站 |
| `protocol/ebpf/diagnostics_api.go`（新） | 把包内 `EBPFDiagnostics` 映射到 adapter DTO；`EBPFKernelRuntimeDiagnostics` 走 5 秒缓存，避免每次 deep 调用都枚举整表 |
| `common/ebpf/runtime_resources*.go`（新）、`occupancy.go`（+75）、`tc_fakeip_icmp.go`（+22） | 内核对象快照与**按归属 ID 过滤的** map 占用枚举 |
| `cmd/sing-box/cmd_api_ebpf.go`（新） | `sing-box api ebpf [--deep]`，`protojson` 输出（`EmitUnpopulated`，便于脚本取零值字段） |

设计取舍（与上游不同之处，均为有意）：

1. **DTO 放在 `adapter`、用 `any` 之外的具体类型**：上游把 DTO 也放 `adapter`，我们沿用同一层，但接口方法名改为 `EBPFRuntimeDiagnostics()` / `EBPFKernelRuntimeDiagnostics()`，避免与包内已有的 `Inbound.Diagnostics()` 混淆。
2. **一份 bypass 策略写两个 scope**：fork 只有一套 `bypass_rule_set`（顶层），上游是 `local.` / `shared.` 两套。映射时 `LocalBypassRuleSet` 与 `SharedBypassRuleSet` 填同一份数据——只填一处会让另一处看起来"未知"，而事实是它确实生效于全部数据面（shared 恒喂空策略，见 `inbound_policy.go` 注释）。
3. **上游独有的计数器保持零值而不是借用**：上游 `EBPFCounters` 里的 `tcSocketLookupFailures`、`tcSKAssignFailures`、`tcLocalFragmentPasses`、`tcReturn*` 等字段 fork 侧没有对应实现（fork 用 `raw_ip_*` 一组命名），映射时保留 0，**不拿相邻指标凑数**。
4. **Clash API 侧不改**：`experimental/clashapi/ebpf.go` 的 `/ebpf`、`/maps` 继续走鸭子类型，不 import `protocol/ebpf`，因此不需要 `with_ebpf` tag。

验证：`go build` / `go vet`（`with_ebpf` 与无 tag 两种）、`go test -c` 全部通过；6 个新单测覆盖 schema 版本、未计算计数器的弱化、双 scope 策略、TC 附件计数、内核运行时缓存、DTO 转换。

### 8.3 P2 部分完成：UDP recovery 表的清理（**内核侧未移植**）

上游用的是**内核 ringbuf 释放通知**：`cgroup/sock_release_notify` 程序把 socket cookie 和释放时间写进 ringbuf，用户态在精确 deadline 上删除 `cgroup_udp_recovery` 条目。

**这条路径本 fork 无法照抄**，原因是硬的：

- `common/ebpf/native/cgroup.bpf.c` 没有 ringbuf map，也没有释放通知程序；
- `common/ebpf/internal/bpfgen/*.o` 是**预编译产物**，`manifest.txt` 用 sha256 锁定，生成它需要 Android NDK r29 Clang 21；本机没有 NDK，**改 `.c` 无法重新生成 `.o`**（manifest 里甚至记录了 tc 对象是在设备上用 Termux clang 重建的）。

所以本轮只做了用户态能独立成立的半边：

- `common/ebpf/cgroup_recovery_sweep.go`（新）：`SweepUDPRecoveryBudgeted(maxAge, now, budget)`，复用包内已有的 `mapScanScratch` 批量遍历，**每趟最多 1024 条**，先收集后删除（遍历期间不删，避免依赖 map 游标语义）；`CreatedAtNS == 0` 的条目一律不动——未知年龄就删会切断活流。
- `protocol/ebpf/cgroup_recovery_sweep.go`（新）：10 秒一次的后台清扫，**只在 `udp_cleanup == lru_fallback` 时跑**（内核能报释放事件时由内核负责，用户态去扫只会和内核抢同一张表）；`Inbound.Close()` 先停清扫再关 backend。
- `common/ebpf/cgroup_runtime.go`（+4）：导出 `UDPCleanupModeLRUFallback`，让上层不必比较裸字符串。

**遗留的真实差距（需要下一次能重编 BPF 对象时完成）**：

1. 内核侧 `release_socket()` 给 recovery 值打时间戳（`created_at_ns`）。当前 fork 只对 TCP 打戳，UDP 恒 0 —— 所以清扫器对**现网存量条目一律跳过**，只有内核侧补戳后才真正起作用。这是本项效果的硬前提。
2. ringbuf 通道 + 精确 deadline 删除（替代 10 秒粗粒度清扫）。
3. `EBPFDiagnosticsReleaseNotificationDrops` 在 fork 侧仍无生产者，恒为 0。

### 8.4 未动：P3

`adapter/host.go`（`JudgeHostFlow`/`FlowLogger`）与 `common/kernelports/` 属上游 10 月的 base 演进，与 eBPF 主线无关；它们牵扯 `adapter.NetworkManager` 接口和 `protocol/{masque,openconnect,openvpn,tailscale,wireguard}` 的调用点，建议留到下次整体同步 `sagernet/sing` / `sing-tun` 基线时一起带，避免两次改同一批文件。

### 8.5 本轮改动清单

```
.github/workflows/{build,lint,test,upstream-sync}.yml   P0
daemon/{started_service.proto,pb.go,_grpc.pb.go}        P1
daemon/{instance.go,started_service_ebpf.go}            P1
adapter/{ebpf,ebpf_diagnostics}.go                      P1
cmd/sing-box/cmd_api_ebpf.go                            P1
common/ebpf/{occupancy.go,tc_fakeip_icmp.go,cgroup_runtime.go}  P1+P2
common/ebpf/{runtime_resources,runtime_resources_backends,cgroup_recovery_sweep}.go  P1+P2
protocol/ebpf/{inbound.go,inbound_lifecycle.go,diagnostics_api.go,diagnostics_api_test.go,cgroup_recovery_sweep.go,cgroup_recovery_sweep_test.go}  P1+P2
```

编译矩阵（Windows 主机交叉编译）：`linux/arm64` + `with_ebpf` ✅、`linux/arm64` 无 tag ✅、全 tag 集（`with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale`）android/arm64 87.3 MB ✅。**Linux 单测无法在本机运行**（无 WSL / Docker），只能编译通过。

---

## 9. 补记：RPC 测试与两个被漏掉的东西（2026-11-03 追加）

补 `daemon/started_service_ebpf_test.go` 时，对着上游同名测试逐条比对，发现上一轮 P1 漏了两件事——都不是测试问题，是**产品缺陷**：

### 9.1 `APIVersion` 没跟着升（真 bug）

上游在 `f1a62dff` 里把 `daemon/started_service.go` 的 `const APIVersion = 4` 改成了 `6`，我们移植 RPC 时只搬了 proto 和实现，**没搬这一行**。

后果是实的：客户端拿 `GetAPIVersion()` 的返回值决定"这个 server 支不支持 `GetEBPFDiagnostics`"，版本号还停在 4 就等于告诉客户端"不支持"，于是所有做版本协商的客户端都会跳过这个新接口——功能上线了但没人会调。`cmd/sing-box/main.go` 打印的 `core api version` 也仍然是 4。

已改为 `6`，并在常量上方写清每个版本号对应的变更（5 = 加 `GetEBPFDiagnostics`，6 = 诊断 schema 到 18 带内核运行时快照），避免下次再漏。

### 9.2 `common/ebpf/runtime_resources*.go` 缺 build tag（真 bug，只影响非 Linux）

上一轮新建的 `runtime_resources.go` / `runtime_resources_backends.go` 忘了加 `//go:build with_ebpf && (linux || android)`。因为这个包在 Windows 上也会被编译（`common/ebpf` 有平台无关的文件），结果是：

```
common\ebpf\runtime_resources.go:43:16: undefined: MapOccupancyReport
common\ebpf\runtime_resources_backends.go:18:10: undefined: tcRuntime
...
```

**上一轮的验证没抓到它**，因为当时只做了 `GOOS=linux` 交叉编译。这次在本机能跑 `go test ./common/ebpf/` 时直接炸出来。已补上 tag，现在 Windows 下 `go build ./common/ebpf/` 与 `go test` 都通过。

> 教训写在这里：`GOOS=linux` 交叉编译通过 ≠ 这个仓库在 Windows 上能编。以后动 `common/ebpf` 必须两边都过一遍。

### 9.3 新增的 9 个测试

`daemon/started_service_ebpf_test.go`（本机 **真实运行通过**，不是只编译）：

| 测试 | 守住什么 |
|---|---|
| `ReportsSchemaVersionWithoutInbound` | 没有 eBPF 入站时也要回 schema 版本，dashboard 才能区分"没配置"与"server 太旧" |
| `RequiresStartedService` | 未启动 / 无 instance 时拒绝，不能拿零值糊弄 |
| `SkipsNonEBPFInbounds` | 非 eBPF 入站被跳过，而不是当成空诊断上报 |
| `ShallowSkipsKernelWalk` | 轻量请求**不得**枚举内核对象（这是 `--deep` 存在的理由） |
| `CarriesRuntimeState` | 时间戳按毫秒上 wire、attachment 的 slot、bypass 后端状态、计数器、policy epoch、UDP NAT 逐字段对齐 |
| `DeepIncludesKernelRuntime` | deep 才带程序/映射快照 |
| `MergeEBPFKernelRuntimeDeduplicatesSharedResources` | 两个入站共享同一批内核对象时**按 ID 去重**而不是相加；最差状态取胜；且不得污染入站自己的快照 |
| `GRPCRegistrationAndAuthentication` | 新 RPC 必须同样过鉴权（无 token → `Unauthenticated`） |
| `APIVersionAdvertisesEBPFDiagnostics` | 版本号 `< 6` 直接失败，防止以后再漏 |

### 9.4 与上游测试的差异（有意）

- 上游 stub 用 `Start(adapter.StartStage, *adapter.Scope)`，我们的 `adapter.Lifecycle` 只有 `Start(stage StartStage)`，stub 跟着我们的接口写。
- 上游测试里断言了 `TCRoutingSlot`、`LocalUDPState`、`LocalUDPReleaseProgram` 等字段——我们的 proto 里有这些字段号（schema 18 完整搬过来了），但 `protocol/ebpf` 侧**没有对应实现**，恒为 0/空。测试里没有断言它们，因为断言一个恒零字段等于测试自己骗自己。等内核侧补上（见 8.3 遗留）再补断言。

### 9.5 本机测试覆盖现状

---

## 10. 第二轮 eBPF 专项复核（2026-11-03 追加）

这一轮把父仓的 eBPF 内核侧也拿到了——它没有内联在仓库里，而是作为独立模块 `github.com/CHIZI-0618/sing-ebpf`（`v0.1.0-alpha.13.0.20261101121606-d904cb7932c5`）从 module cache 里解开。之前的审计只看 Go 侧，看不到 `.bpf.c`，所以漏掉了几条**只有在内核代码里才看得见**的结论。

### 10.1 先说三个我自己的错误

**（1）P2 的清扫在 fork 上是死代码。**

我上一轮写的 `SweepUDPRecoveryBudgeted` 靠 `CreatedAtNS` 判断条目是否过期。但 fork 的内核侧**UDP 条目从来不打这个戳**：

```c
// fork: common/ebpf/native/cgroup.bpf.c:235,252
value->created_at_ns = protocol == TCP_VALUE ? ktime_get_ns() : 0U;   // UDP 恒 0
// :889 release_socket 里
if (original != 0) map_update(&cgroup_udp_recovery, listener, original, 0U);  // 原样拷贝，仍 0
```

父仓多了一行（`release_socket_cookie` 里）：

```c
recovery.created_at_ns = released_at_ns != 0U ? released_at_ns : flow_time_ns();
```

所以我的清扫每条都命中 `value.CreatedAtNS == 0 → skip`，`Deleted` **永远是 0**。测试只验证了"参数校验"和"生命周期"，没验证"真的能删"，所以全绿。

这不是"部分完成"，是**没完成**。要它生效必须改 `.bpf.c` 并重编 `.o`，而本机没有 NDK clang（见 10.3）。**结论：这个清扫目前应当视为未实现**，文档里 8.3 那句"部分完成"写得过于乐观，按此更正。

**（2）我此前说"fork 用内联 common/ebpf、父用外部模块"是对的，但由此推出"fork 的 eBPF 更完整"是错的。**

模块里的 `native/` 有 5 个 `.c`，其中 `icmp_echo_reply.bpf.c`（29 KB）fork 完全没有——fork 用自己写的 `fakeip_icmp.bpf.c`（27.4 KB）做同一件事。配置项两边都叫 `fakeip_icmp`，内核产物不同名，所以按"文件是否同名"比会误判。

**（3）`force_intercept_policy.h` 父仓独有、fork 缺失，但功能不缺。**

fork 没有这个头文件，因为它是父仓新引入的 `_force4/_force6` LPM map 机制；fork 的等价物是 `ForceInterceptIPv4/ForceInterceptIPv6` 两个前缀字段（`inbound_lifecycle.go:64-65` 传给 cgroup 控制块）。同一个语义，两种承载。这又是一条"同物异名"。

### 10.2 这一轮确认的**真实**缺陷（4 条，都不是文件缺失）

> **状态：E1–E4 已全部修复，见第 11 节。** 下表保留当时的判断与证据，便于回看"改了什么、为什么改"。

| # | 缺陷 | 证据 | 后果 |
|---|---|---|---|
| **E1** | 同一 UDP socket 重连到新目标时，旧 redirect/token 条目不清理 | 父仓有 `cgroup_udp_token_reverse`（listener→cookie 反查）在 `store_connected_udp_token` 里发现 cookie 变了就删旧 token+peer；fork 直接 `map_update(&cgroup_udp_token, &cookie, &listener, 0U)` 覆盖（`cgroup.bpf.c:616/719/789`），**没有反查表** | 旧 `listener_key` 指向的 `cgroup_udp_redirect` 变成孤儿，直到该 socket 关闭才被 `release_socket` 清掉；频繁重连的客户端会累积 |
| **E2** | recovery 表只增不减（LRU 兜底） | fork 的 `cgroup_udp_recovery` 是 `BPF_MAP_TYPE_LRU_HASH`（8192），内核侧只在 `release_socket` 写、**从不在内核侧读**（`cgroup.bpf.c` 仅 L889 一处写）；用户态只在收到迟到包时 `lookupAndDelete` | 不会有正确的条目被主动清理；压满后 LRU 赶掉**仍可能需要**的条目 → 迟到包找不到原目标，静默丢会话 |
| **E3** | map 压力只上报、不处理 | fork 有 `MapPressureHealthy/Warning/Degraded` 阈值（0.85/0.95）和 `diagnostics` 上报，但没有父仓 `maintenance.go` 的 `mapPressureHysteresis` + `maintenanceSchedule`（压力驱动提前触发维护/清理） | 仪表盘会显示 degraded，但系统不会因此做任何事；诊断能看到问题、修不了 |
| **E4** | per-interface local route 缺失：socket 绑定接口场景流量绕过 listener | fork `addLocalRoute` 只装 loopback 一条（redirect_route.go:141 `LinkIndex: loopbackIndex`），`setupLocalRoutes` 只在启动时调（inbound_lifecycle.go:116），接口地址变化后的 `reconcileTCDataPlane` 只重挂 TC attachment **不碰 local route**；父的 `ReconcileInterfaceRoutes`（redirect_route.go:131）给每个 up 且有该族地址的接口都装 prefix local route（source 用接口自己的地址），接口/地址变化时重跑 | systemd-resolved 的 DNS socket（SO_BINDTODEVICE/IP_UNICAST_IF 绑定）路由查找会跳过 next hop 是别的设备的路由——包括 loopback 上的 redirect prefix 路由——被 cgroup 重定向的连接顺着默认路由出接口而不是到达 listener，表现为 DNS 解析黑洞。**纯用户态（Go）可修**，是 4 条缺陷里唯一本机能做的 |

#### E4 的技术细节（照父模块 redirect_route.go:109-130 注释）

> A socket bound to an interface (SO_BINDTODEVICE, IP_UNICAST_IF or IPV6_UNICAST_IF, as systemd-resolved binds the sockets for its DNS servers) routes with that interface as the required output device, and the kernel skips every route whose next hop is another device, the prefix's loopback route included. A connection a cgroup program redirected into the prefix would follow the default route out of the interface instead of reaching the listener. The interface route keeps the lookup local, and its source address, one of the interface's own, brings the listener's replies back on the interface the socket is bound to, so the socket accepts them.

要点：①per-interface 路由的 source 必须用接口自己的地址（listener 回包从同接口回来，绑定 socket 才会接受）；②IPv4 还要在 loopback 上保留 prefix 路由（比接口路由更优先，未绑定 socket 保持 127.0.0.1 源）；③**内核会连同源地址一起删路由**，所以接口/地址变化时必须重跑 reconcile——fork 现在 reconcileTCDataPlane 完全不做这件事。

**fork 的 pre_match/NFQUEUE 不是这个场景的替代**：preMatchController 是"没匹配到的包送用户态决定"的机制（pre_match_linux.go:44），处理的是匹配面，不是路由面。

### 10.3 内核侧改不了（本机约束）

`common/ebpf/Makefile` 要求 **Android NDK r29 的 clang 21**；`internal/bpfgen/*.o` 是预编译产物，`manifest.txt` 用 sha256 锁定，并明确写着 tc 那些对象是在设备上用该编译器重新生成的。本机 `Get-Command clang` 为空、没有 NDK。**E1 和 E2 都必须在 `.bpf.c` 里改并重编 `.o`，所以在本机无法完成**，只能记录成待办。

E3 是纯用户态（Go），可以在这里做——但需要先明确"压力降下来该做什么"（提前 reclaim？拒绝新会话？缩表？），属于策略决策，不该由我替他拍。

**E4 也是纯用户态（Go），本机就能做**：照父的 `ReconcileInterfaceRoutes` 移植 per-interface local route 管理并挂到接口监视事件上。这是 4 条缺陷里唯一可以立刻动手的。

### 10.4 这一轮仍确认"不是缺口"的项

逐一按**行为**核过 fork 有无等价实现，下列均已有（形态不同）：

`action_policy.go`→`inbound_policy.go`；`cgroup_packet_writer`→`sharedPacketWriter`（方向不同：父做 cgroup 侧写、fork 做 shared 侧写）；`tc_runtime/tc_listener/tc_connection`→`tc_dataplane.go`(65 KB)+`tc_netlink.go`；`shared_runtime.go`→直接调 `kernelRuntime`；`logging.go`→`inbound_log.go`；`policy_types.go`→`common/ebpf/policy.go`；`interface_topology.go` 的四个函数在 fork 的 `interface_monitor.go` 里同名存在；`maintenance.go` 见 E3（唯一真差异）；`icmp_echo_reply`→`fakeip_icmp`；`force_intercept_policy.h`→`ForceInterceptIPv4/6` 字段；`tc_isolation.h`/`tc_namespace.go`/`tc_isolated_delivery.go`（netns 隔离投递，520 行）→ **仍缺**，但只在多 netns 场景需要（与 8 月那份 parity 文档结论一致）。

另外，父模块 `api.go` 的 31 个导出符号逐一对照：**19 个同名直接命中**；10 个异名（`SharedPacketRewriteBackend`≡`SharedNetworkBackend`、`PrepareSharedPacketRewrite`≡`PrepareSharedNetwork`、`CompileActionPolicy`≡`CompileBypassCIDRPolicy`、`NewSelfBypassWithCapacity`≡self_bypass.go 的 capacity 版、`InspectRuntimeState`≡cgroup_backend.go:212、`SelectRedirectPrefix`≡cgroup_backend.go:142、3 个 `wrap*` 是模块层包装 fork 不需要）；**真缺的只有 `NewLocalRouteSet`/`ReconcileInterfaceRoutes`（即 E4）**。

### 10.5 fork 独有的 eBPF 配置能力（父仓没有）

`pre_match`（NFQUEUE 前置匹配）、`bypass_selector`（含 `直连` 通配）、`map_capacity`（8 项可调）、`shared.default_interface`、`capture_owner/capture_runtime`。这些父仓 `option/ebpf.go` 里一个都没有——fork 的 option 层确实是父仓的超集。

## 11. 第三轮执行：E1–E4 全部修完（2026-11-04）

10.3 里我写过"E1/E2 本机做不到，因为缺 NDK clang"、"E3 属于策略决策不该我拍"。这两条都被推翻了：NDK r29 下载到位，`bpf2go` 在 Windows 上打通，四条缺陷全部落地。

### 11.1 E1：UDP 重连时的孤儿 redirect

内核侧加了一张反查表，把"cookie → listener"的单向映射补成双向。

| 位置 | 改动 |
|---|---|
| `native/abi.h` | 新增 `sb_ebpf_udp_token_reverse_value{socket_cookie, reserved}`（16 B，`reserved` 为将来的 generation 留位）+ 静态断言 |
| `native/cgroup.bpf.c` | 新增 `cgroup_udp_token_reverse`（`BPF_MAP_TYPE_HASH`，listener → reverse value） |
| `native/cgroup.bpf.c` | 新增 `store_connected_udp_token(cookie, listener)`：查反查表，发现上一个 cookie 不同就删掉它的 token 和 peer，再写 token、写反查，反查写失败回滚 |
| `native/cgroup.bpf.c` | 三处 connected_udp 的 `map_update(&cgroup_udp_token, ...)` 直写全部改调上面这个函数 |
| `native/cgroup.bpf.c` | `reset_connected_udp` 补 `map_delete(&cgroup_udp_token_reverse, ...)` |
| `cgroup_maps.go` | override 加 `sb_cg_token_rev`；`validateCgroupUDPCleanupMaps` 把它一并纳入类型校验 |
| `cgroup_abi.go` | 新增 Go 侧镜像结构 `udpTokenReverseValue` |

`store_connected_udp_token` 必须**单行声明**——它的参数列表会被 `INLINE` 宏展开吃掉，写成多行 clang 直接报 `expected parameter declarator`。

### 11.2 E2：recovery 表只增不减

两处改动共同让它变成"能过期"：

1. **内核侧打戳**：`release_socket` 拆成 `release_socket_cookie(cookie, released_at_ns)`，拷贝 original 进 `cgroup_udp_recovery` 时写 `recovery.created_at_ns = released_at_ns != 0U ? released_at_ns : flow_time_ns()`；`release_socket(ctx)` 变成它的薄包装。
2. **用户态扫掉过期的**：`SweepUDPRecoveryBudgeted` 现在真的能删东西了。

**时钟必须对得上**：内核写的是 `ktime_get_ns()`（`CLOCK_MONOTONIC`），而清扫原来拿 `time.Now()`（`CLOCK_REALTIME`）去比——两个量纲比大小，删不删全看运气。新增 `commonEBPF.MonotonicNow()`（`unix.ClockGettime(CLOCK_MONOTONIC)`），清扫统一用它。

**门禁也改对了**：原来只扫 `lru_fallback` 模式，漏掉了 `socket_release`。而 recovery 表在**两种**模式下都是内核释放钩子写的，socket_release 模式不扫，表照样被 LRU 挤爆。现在两种都扫。

### 11.3 E3：map 压力从"看得见"变成"会动手"

父仓的 `maintenance.go` 依赖一个 fork 没有的原语（TC assignment 扫描），所以没有照抄，而是把它的**滞回 + 调度**套在 fork 真有的两个可收缩对象上：cgroup UDP recovery 表、shared network 流表。

新增 `protocol/ebpf/cgroup_maintenance.go`：

- 每分钟一次慢 tick，重读两张表的占用；
- 受压（≥85% 进、≤50% 出，沿用 `MapPressureTracker` 的滞回）就 15 秒扫一次，宽松就 2 分钟一次；
- 每次最多扫 1024 条（`cgroupMaintenanceSweepBudget`），失败冷却 5 秒；
- **第一次启动必扫**，不必等第一个间隔。

redirect/token 两张表被**故意排除**在压力观察之外——清扫永远缩不小它们，纳进来只会让循环白扫。

`UDPRecoveryUsage()` 数不出 entries 时**上报满额**而不是 0：谎报"还有空间"会让表悄悄填满，而这正是这条路径要防的事。

### 11.4 E4：per-interface local route

新增 `protocol/ebpf/redirect_interface_routes.go`（照父模块 `redirect_route.go` 的 `LocalRouteSet` 移植）：

- 每个 up 且有该族地址的接口，都装一条 redirect 前缀的 local route，**source 用接口自己的地址**；
- IPv4 额外保留 loopback 上那条（更优先，未绑定 socket 保持 127.0.0.1 源）；
- 路由用 `RTM_NEWROUTE` 手工构造（`netlink` 包会把 `Src` 设成 source-specific 前缀，只有 `RTA_PREFSRC` 才是要的）；
- 用 `RTA_PRIORITY = 0x53000000 + linkIndex` 排在 loopback 路由之后；
- 挂进 `interface_monitor.go` 的 tick——**内核会连同源地址一起删路由，接口/地址一变就必须重跑**；
- 失败只 warn，不阻塞 TC reconcile。

`setupLocalRoutes` 里原本重复的前缀计算收敛成 `redirectPrefixes()`，两处共用。

### 11.5 内核对象重编（NDK 打通）

10.3 说"本机无 NDK"已不成立。做法：

1. `cilium/ebpf` 的 `cmd/bpf2go` 全部文件带 `//go:build !windows`，Windows 上跑不了；把它整棵 module 复制出来、去掉那几个 `!windows` 标记后编译成 `bpf2go.exe`。
2. 用 NDK r29 的 clang 21 重生成 cgroup / cgroup_coarse / cgroup_storage 六个对象（两种字节序）。
3. `llvm-objcopy --remove-section=.BTF --remove-section=.BTF.ext` 剥掉调试段（bpf2go 强制 `-g`，不剥体积会翻三倍）。
4. `manifest.txt` 的 sha256 与 clang 版本行同步更新；手工复刻 `make check` 的 native 比对 → **15 条目 / 15 文件全部一致**。

对象体积：`cgroup_bpfel.o` 112,968 → 104,448 B，`cgroup_bpfeb.o` 113,072 → 104,944 B。`cgroup_bpfel.go` 多了 `CgroupMapCgroupUdpTokenReverse` 常量。

### 11.6 新增测试

| 文件 | 守住什么 |
|---|---|
| `protocol/ebpf/redirect_interface_routes_test.go` | nil 接收者不 panic、close 后 no-op、地址族分类、空前缀不发路由 |
| `protocol/ebpf/cgroup_maintenance_test.go` | 无 backend 不启动、stop 幂等且 5 秒内返回、间隔大小关系、无 backend 时判为宽松 |
| `protocol/ebpf/cgroup_recovery_sweep_test.go`（追加 2 个） | `MonotonicNow` 确实读的是单调钟（与墙钟差 > 1 分钟）、没打戳的条目不被误删 |

### 11.7 验证

| 项目 | 结果 |
|---|---|
| `GOOS=linux GOARCH=arm64 go build -tags with_ebpf`（4 个包） | exit 0 |
| 同上 `go vet` | exit 0 |
| 160 个包 bulk build（排除 `experimental/boxdd`、`experimental/libbox`） | exit 0 |
| 全 tag 集 android/arm64 完整二进制 | exit 0，92,360,606 B |
| Windows 原生无 tag：`go build ./common/ebpf/ ./daemon/ ./adapter/` | exit 0 |
| Windows 原生 `go test ./common/ebpf/` | ok |
| `make check` 的 native 部分（手工复刻） | 15/15 一致 |
| `golangci-lint fmt -E gci -E gofumpt`（只对改动文件） | 无无关漂移 |

`protocol/ebpf` 的测试二进制只能交叉编译（`go test -c` 通过），在 Windows 上跑不了——eBPF 的集成测试要么 Linux 真机、要么 CI 里的 `ebpf-verifier.yml`。

### 11.8 仍然没做的

- **父仓的 ringbuf 释放通知**（`sock_release_notify` + watch/stats/events 四张表 + 用户态 deadline 调度）。有了 `created_at_ns` 之后，10 秒级周期清扫已经能覆盖"socket 已关的孤儿"，ringbuf 只买到那 10 秒的延迟。收益与复杂度（多四张表、多一个读线程、一条降级路径）不成比例，决定不做。
- **netns 隔离投递**（`tc_isolation.h` / `tc_namespace.go` / `tc_isolated_delivery.go`，约 520 行）：只在多 netns 场景需要，与 8 月那份 parity 文档结论一致。
- **`adapter/host.go`、`common/kernelports/`、`tailssh/switch_user`**：不属于 eBPF 范围，第 2 节列过，仍未移植。

## 12. 真机验证与 eBPF CPU 归因（2026-11-05）

### 12.1 设备

Redmi 2407FRK8KEC（`rothko`），Android 16 / SDK 36，`arm64-v8a`，内核 `6.1.138-android14-11-g6ab8c9a86a33-ab14396278`，Magisk root，**没有 bpftool**（所以本文所有内核侧观测都是自己发 `bpf()` 系统调用读的）。内核带 `CONFIG_CGROUP_BPF`、`CONFIG_NET_CLS_BPF`、`CONFIG_DEBUG_INFO_BTF`。

### 12.2 Android 15+ 的 netd 占位程序

Android 15（API 35）起 netd 用**不带 flag** 的 `BPF_PROG_ATTACH` 占住 cgroup v2 root 上每一个 socket-address hook（connect4/6、sendmsg4/6、recvmsg4/6）。内核把这些 hook 锁进单程序模式，之后任何多程序 attach（含 `BPF_LINK_CREATE`）都返回 EPERM。这是本 fork 之前在这台设备上一启动就失败的原因：

```
attach eBPF inbound: sb_ebpf_conn4: CGroupInet4Connect owned by connect4_inet4_:
refusing to replace existing cgroup program owner
```

移植的解法（`common/ebpf/cgroup_netd.go`）：**不把 hook 转成多程序**，而是用 hook 自己的 flags 原子换掉 owner，detach 时换回来。

- 判定按**行为**不按名字：必须是单程序 hook、单程序模式、且翻译后指令化简为 `r0 = 1; exit`（`instructionsAlwaysAllow`，上限 8 条）。
- 内核隐瞒指令时才按身份认，且只认 netd 为该 hook pin 的那个（`/sys/fs/bpf/netd_shared/prog_netd_*`）。
- **netd 的 socket-release 程序做真实流量统计，其 hook 永不接管**（`netdHookPinPrefixes` 里故意没有 `CGroupInetSockRelease`）；该 hook 被占时 socket-release 加速降级为 LRU 模式。
- 崩溃自愈：上一个后端被 `kill -9` 留在 hook 上的 stale 程序**不能裸 detach**（空 hook 会让下次 attach 转成多程序模式，令重启的 netd 直接 abort），要先 `restoreNetdOwnerForStaleProgram` 换回 netd 的 pass-through。

真机实测（`/sys/fs/cgroup` 上 7 个 hook 的 mode/count/owner）：

| 场景 | connect4/6、sendmsg4/6、recvmsg4/6 | socket-release |
|---|---|---|
| 基线（无 sing-box） | `exclusive` count=1，owner `connect4_inet4_` 等（id 25–30） | `cgroupsockrelea`(22) |
| 运行中 | `exclusive` count=1，owner `sb_ebpf_conn4` 等 | id 22 不动 |
| 优雅停止 | netd 原 id 25–30 全部回来 | 不动 |
| `kill -9` | 6 个 `sb_ebpf_*` 留在 hook（stale） | 不动 |
| `kill -9` 后重启（无自愈） | 变 `multi` —— netd 重启会 abort | 不动 |
| `kill -9` 后重启（有自愈） | 保持 `exclusive` | 不动 |

接管、归还、崩溃自愈三条路径都验过；netd 的流量统计 hook 全程未被触碰。

### 12.3 三轮集成测试

`SING_BOX_EBPF_INTEGRATION=1 ./ebpf.test -test.count=1`（`-tags with_ebpf,ebpf_integration`）：

| 轮次 | 结果 |
|---|---|
| 第 1 轮（首跑） | 398 PASS / 3 FAIL |
| 修完 3 个失败后 | PASS（EXIT=0） |
| 第 2 轮 | PASS |
| 第 3 轮 | PASS |

三个失败都是**测试自身**跟代码脱节，不是功能坏：

1. `TestEBPFRuntimeDiagnosticsReportsOnePolicyInBothScopes`：断言要求 `backendState` 里有 `shared`，但构造的 `sharedRewrite{}` 没设 `sharedBackend` 字段（`diagnostics.go` 判的是 `sharedBackendInstance() != nil`）。修：构造时给 `&commonEBPF.SharedNetworkBackend{}`。
2. `TestUDPNATDiagnosticsReuseCacheMetrics`：`c7329905` 把 `defaultUDPNATSessions` 从 1024 改成 8192（`protocol/ebpf/config.go`），测试还写死 1025 条并断言 1 次驱逐，实际容量 8192 不驱逐。修：容量取 `defaultUDPNATSessions`。
3. `TestRecoverySweepLeavesUnstampedEntriesAlone`：暴露一个**真 bug**——`MonotonicNow()` 返回 `time.Time`，而内核戳的是 `CLOCK_MONOTONIC` 的纳秒数；`time.Unix(monotonicSec, nsec)` 把"开机 1317 秒"当成 1970 年，算出来的 cutoff 与表里的戳差三个数量级，清扫恒删 0 条。修：改成 `MonotonicNanoseconds() (uint64, error)` 直接返回裸纳秒，`SweepUDPRecoveryBudgeted(maxAge, nowNanoseconds uint64, budget uint32)` 全程用 uint64 比较（并防下溢）。

### 12.4 CPU 归因：eBPF 到底吃了多少

方法：`/proc/sys/kernel/bpf_stats_enabled=1` 打开内核统计（**默认 0，不开 `RunTimeNs` 恒 0**），然后按程序 ID 快照 `RunTimeNs`/`RunCnt` 两次算增量（`cmd/internal/statsprobe`）；流量由 `cmd/internal/trafficgen` 产生；`device/costcompare.sh` 一次跑完 baseline（停 sing-box）与 loaded 两轮。

**UDP 50k pps，8 秒窗口**：

| 程序 | 调用 | CPU (ms) | 单次 | 占比 |
|---|---|---|---|---|
| 厂商 `tracepoint_sched_*` ×3 | 388,074 | 1080.0 | 1.0–1.3 μs | **65.6%** |
| netd `cgroupskb_egress` / `skfilter_egress` / `cgroupskb_ingress` / `skfilter_ingress` | 217,716 | 492.3 | 0.39–0.88 μs | **30.0%** |
| **`sb_ebpf_urcv4`（我们）** | 203,392 | **47.9** | **235 ns** | **2.9%** |
| `sb_ebpf_conn4` / `conn6` | 12 | 0.14 | 11–15 μs（冷缓存） | 0.0% |

合计 eBPF 1647 ms / 8 s。

**TCP connect（8 worker，10 ms 拨号超时，6 秒 36,402 次连接）**：

| 程序 | 调用 | CPU (ms) | 单次 | 占比 |
|---|---|---|---|---|
| **`sb_ebpf_conn4`（我们）** | 66,991 | **116.0** | **1.73 μs** | **9.2%** |
| `sb_ebpf_conn6` | 16 | 0.15 | 9.3 μs | 0.0% |
| 其余 sb_ebpf_* | 13 | 0.03 | — | 0.0% |

合计 eBPF 1260.6 ms / 8 s；其中厂商与 netd 仍是主体。同一时段 softirq：`NET_RX` 从基线 +253 涨到 +121,276（重定向把流量带回 loopback，属 cgroup 数据面的固有代价），`RCU` +36,764。

**结论**（这也是对"sing-box 走 eBPF 让内核 CPU 异常"的回答）：

1. 本 fork 的单次成本 **235 ns（recvmsg 快路径）/ 1.73 μs（connect 全策略链）**，全部程序的 CPU 占比在 3%–9%。
2. 跑同一批包的是 netd 的流量统计程序，调用次数与我们几乎相同（217,716 vs 203,392），**每包 1.47 μs，是我们的 6 倍**。
3. 空闲时厂商 `tracepoint_sched` 占 eBPF 总时间的 **92%**，与我们无关。
4. `recv_v4` 已经是 2 次 map lookup 的最短路径（`control()` + 一次 `cgroup_udp_redirect` 查表 + 回写 user_ip/port）；`handle_v4` 的 connect 链是 8–10 次 lookup，在 11,000 conn/s 下占单核 1.9%。
5. 想再省只能"少跑"：`:53` 的 DNS 包在 `respect_policy` 下会全量重定向并让 listener 每包多跑一次 `recvmsg` hook——这是配置语义（DNS 劫持）而非程序开销，要省应该改配置而不是改程序。

### 12.5 复现方法

```sh
# 1. 用 NDK 的 clang 编 BPF 对象（Windows 上可行，NDK r29 = clang 21）
clang -target bpf -mcpu=v1 -O2 -g0 -ffreestanding \
  -mllvm -disable-block-placement -mllvm -disable-branch-fold \
  -nostdinc -Inative -isystem "$NDK/toolchains/llvm/prebuilt/windows-x86_64/lib/clang/21/include" \
  -isystem "$NDK/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include" \
  -isystem "$NDK/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include/aarch64-linux-android" \
  -c -o out.o native/cgroup.bpf.c

# 2. 打开内核统计（默认关，不开测不到时间）
echo 1 > /proc/sys/kernel/bpf_stats_enabled

# 3. 归因 + 压流量
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o statsprobe ./cmd/internal/statsprobe/
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o trafficgen ./cmd/internal/trafficgen/
su -c 'sh /data/local/tmp/costcompare.sh 8 udp'      # 或 tcpconn
```

`statsprobe` 用 `BPF_PROG_GET_NEXT_ID` → `BPF_PROG_GET_FD_BY_ID` → `BPF_OBJ_GET_INFO_BY_FD` 遍历所有已加载程序读 `RunTimeNs`/`RunCnt`，不依赖 bpftool（设备上没有）。注意 `struct bpf_prog_info` 里 `RunTimeNs` 在偏移 192、`RunCnt` 在 200，`Name` 在 64。
### 12.6 gRPC 诊断 RPC 的真机端到端验证

第 8.2 节移植的 `GetEBPFDiagnostics` 此前只在 Windows 上跑过单测，从没在真机上通过 gRPC 调过。这一节补上。

`sing-box api` 走的是配置里的 `api` service（`service/api` 把 `daemon.NewServer` 挂到 h2c 上），所以设备上这样起：

```json
{
  "services": [ { "type": "api", "tag": "api", "listen": "127.0.0.1",
                  "listen_port": 18080, "secret": "devsecret" } ],
  "inbounds": [ { "type": "ebpf", "tag": "ebpf-in", "network": ["tcp", "udp"],
                  "local": { "enabled": true, "data_plane": "cgroup" } } ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "final": "direct" }
}
```

```sh
/data/local/tmp/sb-test run -c test-api.json &
/data/local/tmp/sb-test api --url http://127.0.0.1:18080 --secret devsecret ebpf
/data/local/tmp/sb-test api --url http://127.0.0.1:18080 --secret devsecret ebpf --deep
```

结果（真实输出节选）：

- 浅查询就带齐了 `observedAt` / `state: "normal"` / `localEnabled` / `localDataPlane: "cgroup"` / `attachments[]` / `udpReplySockets` / `counters`。
- `--deep` 额外给到 `udpNAT`、`localBypassRuleSet`（`consistent: true`、`policyVersion: 1`）和 `kernelRuntime`（程序列表 + 每个 map 的 `maxEntries`/`entries`/`pressure`，例如 `sb_self_sockets` 65536 容量用了 5 条、`pressure: "healthy"`）。
- 响应尾部 `"schemaVersion": 18`，与 `adapter.EBPFDiagnosticsSchemaVersion` 一致。
- 启动日志：`eBPF inbound started: paths=[local=cgroup] mounts=[/sys/fs/cgroup(local,cgroup)] waiting_for_interface=[none] fakeip_icmp=[off]`。
- 运行期间抓到了真实设备流量被接管：`inbound connection from 127.0.0.1:40962` → `inbound connection to 157.255.131.101:23861`。

两个注意点：

- `local.enabled` 接管的是**整机 cgroup**，所以这个配置一跑起来就真的在代理系统流量，测完必须 `pkill -f sb-test`。
- `attachments[].interfaceName` 在 cgroup 模式下报的是挂载路径（`/sys/fs/cgroup`），`interfaceIndex` 是 0。字段名是历史包袱，上游同款，改字段名会破坏 proto 兼容性，先记着。
## 13. CI 门禁修复（2026-11-06）

Lint 自 2026-09-12 起就没绿过，Test 从未绿过。两道门禁分别卡在不同位置，按顺序拆开修：

| 门禁 | 之前卡在哪 | 修了什么 |
| --- | --- | --- |
| Replace ledger must match go.mod | go.mod 有 3 条 replace（含 swatch => ./deps/fswatch），ledger 只有 2 行 | 补 fswatch 行（9c74130） |
| go vet against baseline | 基线记 experimental/libbox/debug.go:10:11，实际 :11:11（上游 0bdface 加 16 行下推） | 更新 scripts/vet-baseline/{linux,windows}.txt（e0d3d14d） |
| golangci-lint | 前两道过了才第一次真正跑到它，暴露出 19 项既有问题 | 12 项 unused 删除、6 项 modernize、1 项 import 顺序（本次） |
| Schema is up to date | docs/schema.json 落后于 eBPF 选项新增 | 重新生成（本次） |
| Test (windows) | 依赖升级后 	ransport/wireguard 的 fake 缺 WaitActiveContext、oute 的 L3 NAT 测试还在用旧签名；另有 TestURLTestOutboundsConcurrentCapsConcurrency 与 clashapi 的进程名断言从未通过 | 逐个修（本次） |

三个值得记下的点：

- **unused 的删除都先做过全仓 grep 确认零引用**。其中 (*slowOpenConn).setCloseHandler 只被 with_ebpf 的 self-bypass 路径调用，而 lint 的 build-tags 不含 with_ebpf，所以它不是死代码——已移到 common/dialer/tfo_ebpf.go，用同一 build tag 保护，而不是删掉。
- **TestURLTestOutboundsConcurrentCapsConcurrency 原来是假通过反面的假失败**：它断言 288 个成员全部产出延迟，但 288 个并发真 dial 打同一个 loopback listener 时会被拒掉几十个（Windows 上三次里失败两次）。改为断言「每个成员都被发出一次 + 峰值不超过 256」，这才是这个测试名字要保证的东西。用 git stash 验证过它在改动前就失败，不是本次引入。
- **clashapi 的进程名偏好反了**：代码优先 ProcessPaths[0]，而测试（以及 Android 现实——所有 app 的 exe 都是 pp_process64）要的是 PackageNames[0]。PackageNames 只在 Android 上被填充，所以调换顺序不影响其他平台。

复现命令（本机 Windows，10 个 matrix 目标逐个跑）：

``bash
GOOS=<os> GOARCH=<arch> golangci-lint run --timeout=30m   # 现在 10/10 都是 0 issues
go test -count=1 -tags "with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0" \
  -ldflags "-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0" ./...                 # 43 包 ok，0 失败
go run -ldflags "-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0" \
  -tags "with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0" ./cmd/sing-box schema -o docs/schema.json
``

## 14. TC 数据面的资源表维护（2026-11-06）

第 11 节的 E1–E4 修完之后，作者指出这台设备跑的是 `local.data_plane: tc`，不是 cgroup。按那个前提重查，发现两件事，都在这一节修掉。

### 14.1 第 11 节的 E3 在纯 TC 上完全空转

`protocol/ebpf/cgroup_maintenance.go` 的压力驱动维护循环入口是

```go
func (i *Inbound) startCgroupMaintenance(ctx context.Context) {
	if i.cgroupBackendInstance() == nil {
		return
	}
```

纯 TC 没有 cgroup backend，所以这个循环**从来没有启动过**，我上一轮报告的「按 map 压力提前清扫」在 TC 上等于没有。这是本次复核最实质的发现：缺陷不在代码写错，而在覆盖面被一行门禁挡住，而报告没有跟着那行门禁收窄。

### 14.2 TC 的 assignment 表此前没有任何过期机制

`tc_assignment`（`sb_tc_assign`，LRU_HASH，默认 65536 条）只在启动时回收一次（`reclaimStaleTCDeliveryLinks`、`reclaimStaleTCPolicyRouting`）。LRU 表的问题是双向的：压满之前谁都不走，压满之后内核按 LRU 挑一个走，挑中的可能正是还在用的那条。对 UDP 尤其糟——一条迟到的包找不到 assignment 就当新流处理，会话断掉。

上游的做法是 `TCBackend.SweepAssignments(maxIdle, fallbackBudget)`，判定条件是

```go
if value.NetworkGeneration != b.control.NetworkGeneration ||
   (value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore) { /* 删 */ }
```

两个字段此前都不存在：`sb_tc_assign_value` 只有 24 字节，内核侧连 `ktime_get_ns` 都没调用过。

### 14.3 这次改了什么

内核侧（`common/ebpf/native/tc.bpf.c`）：

| 项 | 改动 |
| --- | --- |
| `sb_tc_control` | `__u16 reserved` → `__u16 network_generation`（大小仍 72，偏移不变） |
| `sb_tc_assign_value` | 24 → 32 字节：加 `last_seen_ns`（偏移 8）与 `network_generation`（偏移 28），并把编译器原本隐式的两字节尾填充写成显式 `reserved[2]` |
| 记账 | 三个 assign 函数与 `record_local_socket_cookie` 写 assignment 时打戳；新增 `SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE` 统计槽位（`tc_stats` 5 → 6） |
| 刷新粒度 | `assignment_is_stale` 以 `SB_TC_ASSIGNMENT_REFRESH_NS`（1 秒）为单位判过期，**每秒最多一次 map 写**，不让每包都写 |

用户态：

| 文件 | 内容 |
| --- | --- |
| `common/ebpf/tc_assignment_sweep.go`（新） | `SweepAssignments(maxIdle, budget)`：generation 不符先删，`LastSeenNS == 0` 一律不动（无从判断年龄），过期才删；删除在遍历之外做，容忍 `ENOENT`。`AssignmentUsage()` 供压力信号读占用。 |
| `common/ebpf/tc.go` | `TCAssignment` 镜像 32 字节布局；`SetNetworkGeneration` / `NetworkGeneration`；`tcStatCount` 6 |
| `protocol/ebpf/map_maintenance.go`（替换 `cgroup_maintenance.go`） | 循环从「cgroup 专用」改成「有任一数据面就启动」；每次 tick 同时清扫 UDP recovery 与 TC assignment；`observeMapPressure` 把 `tc_assignment` 占用也喂进滞回 |
| `protocol/ebpf/tc_assignment_maintenance.go`（新） | 记录上一轮扫描的结果并按诊断字段形状上报 |
| `protocol/ebpf/tc_dataplane.go` | `startTCDataPlane` 打 generation 1；`reconcile` 检测到接口集合变化时递增 generation，**在 `slices.Clone` 之前比较旧值**（否则永远相等） |

超时窗口的选择值得单独说明：TC assignment 用 30 秒（压力）/ 5 分钟（宽松），比 UDP recovery 的 30 秒上限长得多。理由是两者语义不同——recovery 条目只活到对端下一个包，assignment 是流的 socket 映射，一条静默的 TCP 连接可以合法地好几分钟不动。按 recovery 的窗口清 assignment 会把活流重新 assign，代价是小，但纯属白折腾。

### 14.4 admission 计数器：换成 TC 侧等价物

上一轮列的「6 个 admission 失败计数器」经核查是 **cgroup 专属**：它们对应 `cgroup_tcp_redirect` / `cgroup_udp_token` / `cgroup_udp_token_reverse` / `cgroup_udp_peer` / `cgroup_udp_recovery` 的写入失败，而 `common/ebpf/native/cgroup.bpf.c` 里**根本没有 stats map**——照抄要新加一整张 PERCPU_ARRAY 再插进六处写入点，对这些设备零收益。

改成做 TC 侧真正缺的那个：assignment 写失败。原来 assign 路径 `map_update(...) != 0` 直接 `return TC_ACT_SHOT`，**丢包且没有任何地方记录**。现在计入 `SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE`，经既有的 `tcAssignmentUpdateFailures` 字段上报——这个字段从移植进来那天就有，一直是常量 0。

### 14.5 一个只在真机上才暴露的 bug

第一次上机，清扫立刻报

```
scan TC assignment state: map batch lookup: unmarshaling []ebpf.TCAssignment doesn't consume all data
```

原因是 cilium/ebpf 的批量读按**各字段宽度之和**计算元素大小：`8+8+4+6+1+1+2 = 30`，而内核 map 的 value 是编译器对齐后的 32 字节。多出来的两字节尾填充 Go 侧看不见，于是「剩余数据没被消费」。修法是把填充在两个结构体里都写显式——C 加 `__u8 reserved[2]`，Go 加 `Reserved [2]byte`，两边都断言 32 与偏移 30。

这个错误在 Linux 交叉编译、`go vet`、`go test -c` 里都看不见，只有真的跑起来读一次 map 才会出现。

### 14.6 验证

| 项 | 结果 |
| --- | --- |
| `go vet -tags with_ebpf ./common/ebpf/ ./protocol/ebpf/` | exit=0 |
| `golangci-lint run ./common/ebpf/... ./protocol/ebpf/...` | 0 issues |
| `go build`（linux/amd64、linux/arm64、linux/arm、android/arm64） | 全部 exit=0 |
| Windows 无 tag build + `go test ./...`（全 tag 集） | 43 包 ok，0 失败 |
| `make -C common/ebpf check`（native 源与 manifest 的 sha256） | 15/15 一致 |
| 真机 `data_plane: tc` 启动 | `attachments=[wlan0(local,l2,clsact)]`、`tcp_listener_lookup=sockmap`、流量正常接管 |
| 真机 `api ebpf --deep` | `schemaVersion: 19`、`tcAssignmentSweepEntries: 15`、`Capacity: 65536`、`Runs: 1`、`Partial: 0`、`Failure: ""`、`UsageKnown: true` |

`EBPFDiagnosticsSchemaVersion` 从 18 提到 19：这次没加字段，但让一批原本恒零的字段有了值，按该常量自己的注释（"Bump it whenever a field changes meaning, not merely when one is added"）属于该提的情形。

### 14.7 仍然没做

- **CPU 归因要按 TC 路径重测**：第 12.4 节的 235ns（recvmsg）/1.73μs（connect）是 cgroup hook 的数，TC 的钱花在 ingress 程序上，两组数不能混用。`cmd/internal/statsprobe` 与 `cmd/internal/trafficgen` 仍在，重测不需要新工具。
- **ringbuf 释放通知**、**netns 隔离投递**：同 11.8，仍然决定不做。
- **上游的 `tc_assignment_claim` 表与 `SweepAssignments` 的三计数器（Missing/Superseded/InFlight）**：我们只有 assignment 一张表，清扫结果按 `Scanned/Deleted/Expired/Superseded/Unstamped` 记录，字段名与上游对不上，不硬凑。
