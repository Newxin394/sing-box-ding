# eBPF 上游功能对比适配表

对比对象：`CHIZI-0618/sing-ebpf` **v0.1.0-alpha.13**（10-18）↔ 本 fork `tc-rewrite-clean`（v33 基线）

对比方法：不看文件名，按 **symbol（type / func / method）** 提取后在全仓回查；未命中的再按实现语义人工判定。上游 64 个非测试文件、838 个符号，本地命中 519。

---

## 0. 结论先说

**13 个"缺失"的 runtime 文件里，9 个功能我们其实已有，只是没拆文件。真正缺的是 4 项能力 + 3 个小件。**

最硬的一条证据是行数对得上：

| | 行数 |
|---|---|
| 上游 `tc_dataplane.go` + `tc_reconcile.go` + `tc_topology.go` + `tc_health.go` + `tc_delivery.go` | 1,112 + 651 + 98 + 124 + 99 = **2,084** |
| 我们的 `protocol/ebpf/tc_dataplane.go`（这些全在里面） | **2,004** |

差 80 行（2%）。上游是**把同一套东西拆成了 5 个文件**，不是多了 5 个功能。

---

## 1. 先更正上一版报告

我在《eBPF上游同步评估报告.md》里有两处结论是错的，这次的证据推翻了它们：

| 上一版说法 | 实际情况 |
|---|---|
| 「我们缺 `tc_reconcile` / `tc_topology` / `tc_health`，所以漂移不自愈」 | **全都有**。`tcDataPlane.reconcile`（`tc_dataplane.go:292`）、`desiredAttachmentState`（:483）、`attachmentStateChanged`（`interface_monitor.go:755`）、`repairInfrastructure`（:843）都在，并且在 10 分钟 tick 里真实调用（`interface_monitor.go:584/701/719`）。两阶段（只读检测 → 有漂移才变更）是**已经实现的**，不是缺失。 |
| 「缺 `kernel_probe_plan` / `runtime_state` 是 P1 硬前置」 | 我们有 `kernelProbePlan` 结构（`kernel_probe.go:71`）、`ProbeKernel`（:182）、`KernelProbeReport`，功能等价。不是前置缺口。 |

所以"启动初期无网"那个症状，归因到"缺对账层"是错的——那次的真因已经查明是**订阅节点失效 + DNS 全走代理出口**。

---

## 2. runtime 层对照（上游 13 文件 / 4,943 行）

| 上游文件 | 行数 | 我们的对应 | 判定 |
|---|---:|---|---|
| `api.go` | 321 | `inbound_lifecycle.go`(781) + `tcDataPlane` 方法 | ⚪ 组织层，无功能缺口 |
| `core_access.go` | 20 | — | ⚪ 纯句柄转换 |
| `tc_dataplane.go` | 1,112 | `tc_dataplane.go`(2,004，含下面 4 块) | ✅ 等价（内联） |
| `tc_reconcile.go` | 651 | `reconcile()` + `closeStaleTCAttachmentsLocked()` | ✅ **已有** |
| `tc_topology.go` | 98 | `desiredAttachmentState()` + `attachmentStateChanged()` | ✅ **已有** |
| `tc_health.go` | 124 | `interface_monitor.go` tick + `repairInfrastructure()` | ✅ **已有** |
| `tc_delivery.go` | 99 | `createTCDeliveryLink()`（内联在 tc_dataplane:1802） | ✅ **已有**（未拆分） |
| `tc_netlink.go` | 322 | `tc_netlink.go`(370) | ✅ 等价 |
| `tc_routing.go` | 677 | `tc_routing.go`(651) | ✅ 等价 |
| `shared_rewrite_dataplane.go` | 842 | `shared_rewrite_dataplane.go`(625) | ⚠️ 缺 10 个方法，见 §4.3 |
| `sysctl_lease.go` | 157 | `tc_sysctl.go`(293) | ⚠️ **降级**：记录+还原，无跨进程租约 |
| `tc_namespace.go` | 131 | 无 | ❌ **真缺** |
| `tc_isolated_delivery.go` | 389 | 无 | ❌ **真缺** |

**`TCRuntime` 接口的 13 个方法逐项对照**（上游 `api.go`）：

| 上游方法 | 我们的实现 | |
|---|---|---|
| `Backend()` | `tcBackend()` | ✅ |
| `NetworkInfo()` | `diagnostics.go` 中的网络信息 | ✅ |
| `TCDiagnostics()` | `Diagnostics()` / `DiagnosticsJSON()` | ✅ |
| `Reconcile()` | `reconcile()` :292 | ✅ |
| `HealthCheck()` | `attachmentStateChanged()` + `tick` | ✅ |
| `RepairInfrastructure()` | `repairInfrastructure()` :843 | ✅ |
| `AttachmentStateChanged()` | `attachmentStateChanged()` :755 | ✅ |
| `AttachmentDescriptions()` | `attachmentDescriptions()` :1103 | ✅ |
| `AttachmentDiagnostics()` | `attachmentDiagnostics()` :1072 | ✅ |
| `UpdateHostAddresses()` | `updateHostAddresses()` :830 | ✅ |
| `Disable()` | `disable()` | ✅ |
| `IsClosed()` / `Close()` | 同名 | ✅ |

**13/13 全有。** 差别只是我们没抽 `interface TCRuntime`，方法挂在 `tcDataPlane` 上。

---

## 3. core 层对照（关键 14 项）

| 上游文件 | 行数 | 我们的对应 | 判定 |
|---|---:|---|---|
| `tc.go` | 1,181 | `tc.go`(977) | ⚠️ 差 204 行，缺 return route / assignment sweep 等 |
| `icmp_echo_reply_backend.go` + `tc_icmp_echo_reply.go` | — | `fakeip_icmp_backend.go`(279) + `tc_fakeip_icmp.go`(92) | ✅ **改名而已**：`ICMPEchoReplyEnabled`→`FakeIPICMPEnabled`、`ICMPEchoLocalReplyProgram`→`LocalReplyProgram`、`ICMPEchoSharedReplyProgram`→`SharedReplyProgram`，9 个方法 1:1 对上 |
| `map_occupancy.go` | 216 | `occupancy.go`(216) | ✅ **改名，行数逐字节级接近** |
| `redirect_route.go` | — | `redirect_address.go`(77) + `protocol/ebpf/redirect_route.go`(276) | ✅ **改名 + 拆两处** |
| `kernel_probe_plan.go` + `kernel_probe_object.go` | 495 | `kernel_probe.go`(850) + `kernel_probe_render.go`(180) | ✅ 等价（我们合一个文件） |
| `decision.go` + `access.go` | 220 | `policy_runtime.go` / `policy_compiler.go` / `policy_vector.go` | 🔵 抽象不同：上游 `ActionPolicy{Local,Shared}`+`Decision`，我们 `CompiledPolicy`+`PolicyConfig`；CIDR/MAC/UID 决策能力都在 |
| `cgroup_attachment.go` | — | `cgroup_attachment.go`(230) | ✅ 同名 |
| `instance_slot.go` | 263 | 无 | ❌ **真缺** |
| `tc_return.go` | 248 | 无 | ❌ **真缺** |
| `cgroup_netd.go` | 425 | 无 | ❌ **真缺** |
| `bpf_permission.go` | 179 | 无 | ❌ **真缺**（诊断增强） |
| `cgroup_network_state.go` | 38 | 无 | ❌ 真缺（小，`ResetNetworkState`） |
| `tcx_order.go` | 225 | 部分（`tcxSupport` 探测 + `tcxLinkInfo`） | ⚠️ 有支持但无优先级锚点 |
| `runtime_state.go` + `runtime_resources.go` | 202 | `diagnostics.go` 部分覆盖 | ⚠️ 部分 |

---

## 4. 真正缺的东西（附证据）

证据均为**全仓**搜索、排除 `_test.go` 后的命中数。

### 4.1 netns 隔离投递（`tc_namespace.go` + `tc_isolated_delivery.go`，520 行）— 真缺

```
unix.Setns|unix.Newns|netns.Set   →  6 命中，全在 common/listener 与 common/netns（sing-box 通用设施）
                                    protocol/ebpf + common/ebpf 生产代码：0
```

我们现在是**在当前 netns 里直接 `netlink.LinkAdd(veth)`**（`tc_dataplane.go:1802`）。上游是在隔离 netns 里建 veth 对，带 `tcReturnFilterHandle = 0x5349` 的回程 filter。

影响：单容器/单 netns 场景无差别；只有"同一套 eBPF 服务多个 netns"才会暴露。Android 上通常是单一 netns，**收益低**。

### 4.2 实例槽位（`instance_slot.go`，263 行）— 真缺

```
AcquireInstanceLease|AcquireInstanceSlot  →  0
```

上游用 abstract socket 名做**跨进程互斥 + 租约**（`@sing-ebpf/<slot>`）。我们用 0 个。多实例/残留进程同时跑时会互相抢 cgroup 程序。

### 4.3 回程路由（`tc_return.go`，248 行）— 真缺

```
AcquireReturnRoute|TCReturnHandle  →  0
```

我们靠 `redirect_route.go` + `route_localnet` + 策略路由，没有引用计数式的 return route 生命周期。单实例够用，并发切换时可能残留。

### 4.4 netd 侵占检测（`cgroup_netd.go`，425 行）— 真缺

```
displaceableCgroupOwner|restoreNetdOwner  →  0
```

上游会枚举 netd 占用的 cgroup program、读它翻译后的指令判断是否"全放行"、必要时接管并在退出时还原。我们在 `cgroup_attachment.go:56` 只有一句注释"可能和 netd 共享 host cgroup"。

**这条在 Android 上价值最高**——netd 抢 attach 是真实存在的失败模式。

### 4.5 三个小件

| 项 | 行数 | 证据 | 价值 |
|---|---:|---|---|
| `bpf_permission.go`（EPERM 可读化） | 179 | `bpfPermissionError` 0 命中 | 中：报错从 "operation not permitted" 变成"缺 CAP_BPF / memlock 不足" |
| `cgroup_network_state.go`（`ResetNetworkState`） | 38 | 0 命中 | 低 |
| `SweepUDPRecovery` / `DeleteUDPRecovery` | ~60 | 我们有 map（`udpRecoveryMapFD`）但无 sweep | 低：我们 UDP NAT 自己管会话 |

### 4.6 共享数据面缺 10 个方法（`shared_rewrite_dataplane.go`）

上游有、我们没有：

```
Index  IsClosed  closeRetiredLocked  retainRetiredAttachment
replacementGenerationLocked  healthCheck  ready  purgeUserspaceFlow  warnFlowPurge  share
```

其中 `retainRetiredAttachment` + `closeRetiredLocked` + `replacementGenerationLocked` 是**退役 attach 延迟关闭**（切换时不打断在途连接），`healthCheck`/`ready` 是共享面健康检查。这块在 4G/多网络共存时才有意义。

---

## 5. 适配分档

### 🟢 A 档：确认「差不多」，不动

| 项 | 理由 |
|---|---|
| 对账 / 拓扑 / 健康三件套 | 已有且已接线，行数 2004 vs 2084 |
| `TCRuntime` 13 方法 | 方法全有 |
| ICMP echo reply | 纯改名，9 方法 1:1 |
| map occupancy | 纯改名，216 行对 216 行 |
| kernel probe | 功能等价 |
| `decision.go` / `access.go` | 抽象风格不同，能力齐 |
| `api.go` / `core_access.go` | 纯组织层，零功能 |

**这 7 类占上游改动量的约 60%，全部不用碰。**

### 🟡 B 档：小改，性价比高

| 项 | 工作量 | 收益 |
|---|---|---|
| `bpf_permission.go` 移植 | 179 行，无外部依赖 | 权限类报错立刻可读。Android 上排障最常撞的坑 |
| 共享面 `healthCheck` + `ready` | ~60 行 | 共享重写挂了能被发现 |
| `sysctl_lease` 升级为租约 | ~150 行（依赖 instance slot） | 多实例下 sysctl 不互相踩 |

### 🔴 C 档：要动就得整包，单独做收益低

| 项 | 工作量 | 什么时候才值得 |
|---|---|---|
| netns 隔离投递 | 520 行 + 接口改造 | 需要一套 eBPF 服务多个 netns 时 |
| instance slot | 263 行 | 需要多实例共存 / 防残留进程时 |
| tc_return | 248 行 | 高并发切换场景实测有残留路由时 |
| cgroup netd 侵占 | 425 行 | **Android 上遇到 netd 抢 attach 时**（当前没遇到，但这是最可能真发生的一项） |

---

## 6. 和你的症状的对应关系

| 之前遇到的现象 | 这次的归属 |
|---|---|
| 启动初期几分钟无网 | **不是** eBPF 缺对账层。已查明是节点失效 + DNS 全走代理 |
| 节点挂了要等 7-8 分钟才切 | **不是** eBPF，是 URLTest 历史不失效（官方 `5372a19` 修的是这个） |
| UDP 时通时断 | 是 UDP NAT 会话表 1024 上限（已在我们 v33 修掉），**不是**上游能力缺失 |
| 挂载漂移后不自愈 | 我们已有 `attachmentStateChanged` + `repairInfrastructure`，理论上能自愈；若实际不自愈，是这俩的实现有 bug，不是缺功能 |

---

## 7. 建议

**先不移植任何东西。** 上一版报告建议的「B1 拓扑 diff → B2 两阶段健康」在功能上已经存在，再移植一遍等于把同一套逻辑写第二份，只会引入双份状态。

真正该做的两件事：

1. **验一次自愈是否真的工作**：手动 `tc qdisc del dev wlan0 egress` 打掉挂载，看 10 分钟内 `interface_monitor` 是否把 attach 恢复。如果恢复 → 对账层没问题，A 档结论成立；如果没恢复 → 是 `attachmentStateChanged`/`repairInfrastructure` 的实现 bug，比移植上游更值得修。
2. **按需挑 B 档**：`bpf_permission` 是纯增量、零风险，随时可以拿。

C 档四项等真实症状出现再动，现在动都是为假想需求付成本。
