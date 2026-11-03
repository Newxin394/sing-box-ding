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

发现一个好消息：`daemon`、`adapter`、`option`、`common/ebpf`、`common/tls` 这些包**能在 Windows 上真实跑测试**（不需要 WSL/Docker）。只有 `protocol/ebpf`（`linux || android` tag）与 `test/` 下的 e2e（要 Docker）跑不了。所以以后不是"只能编译通过"，多数纯逻辑改动可以真跑。
