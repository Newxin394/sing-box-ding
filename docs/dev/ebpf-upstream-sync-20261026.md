# sing-box-ding eBPF 上游同步评估报告

- 评估时间：2026-10-26
- 评估对象：本仓库 `Newxin394/sing-box-ding`（分支 `tc-rewrite-clean`，HEAD `7911a70`）
- 上游基线：`CHIZI-0618/sing-ebpf` tag `v0.1.0-alpha.13`（2026-10-18）、`CHIZI-0618/sing-box` 分支 `ebpf-inbound` head `764219f`（2026-10-18）
- 当前线上内核：`1.15.0-alpha.12-v33-dnsfallback`（已含 UDP NAT 会话表扩容 + DNS fallback 修复）

---

## 一、结论摘要

1. **eBPF 不在 SagerNet/sing-box 上游**（a8/a13 两版 ebpf 路径数均为 0）。它的上游是 CHIZI-0618 的两个仓库：胶水层 `sing-box@ebpf-inbound`、核心库 `sing-ebpf`。
2. **胶水层已经追平**：`ebpf-inbound` 的 head 就是本仓库 10-21 移植的基准 `764219f`，之后无新提交。
3. **核心库是真实差距，但不是"新提交"，而是"我们把库内嵌改名后停在重构前"**：库已拆成 `internal/core`（51 文件）+ `runtime`（13 文件），我们把两者压平进 `common/ebpf` + `protocol/ebpf`，并改了文件名（`map_occupancy.go`→`occupancy.go`、`redirect_route.go`→`redirect_address.go`、`tc_icmp_echo_reply.go`→`tc_fakeip_icmp.go`）。
4. **两条路线定位不同**：
   - **方案 A（换模块依赖）** 是架构级重写：把 26,582 行自维护代码换成薄宿主 + 库。获得全部上游能力，但接口覆盖率只有 40/72，且 TC 生命周期要整体迁移到 `runtime.NewTCRuntime`。
   - **方案 B（只移植对账/看门狗）** 是增量补齐：约 1,990 行上游代码 + 适配，落在现有 `tc_dataplane` 结构上，不动架构。
5. **建议：先 B 后 A**。B 能直接改善"启动初期无网、漂移不自愈"这类现象；A 应等库脱离 alpha 线再做（库自己 9-25 后 main 就没动，alpha.13 是 release 分支产物，接口仍在动）。

---

## 二、上游三仓现状

| 仓库 | 分支/标签 | 最新提交 | 日期 | 与本仓库关系 |
|---|---|---|---|---|
| `SagerNet/sing-box` | `testing` → tag alpha.13 | `824dbcf` | 10-24 | 基础内核；fork 基线实为 **alpha.8**（9-27 merge），`build_v30.sh` 标的 alpha.12 是虚标 |
| `CHIZI-0618/sing-box` | `ebpf-inbound` | `764219f` | 10-18 | eBPF 胶水层；10-21 已移植，**无新提交** |
| `CHIZI-0618/sing-ebpf` | tag `v0.1.0-alpha.13` | `9505052` | 10-18 | eBPF 核心库；**我们内嵌的是重构前的快照** |
| `CHIZI-0618/sing-ebpf` | `main` | `791d119` | 09-25 | 主线，比 tag 更旧（tag 从 release 分支出） |

`sing-ebpf` 版本线：alpha.10（9-20）→ alpha.11（9-28）→ alpha.12（10-14）→ alpha.13（10-18）。**`runtime.NewTCRuntime` 这套宿主 API 从 alpha.10 就存在且形状稳定**，这是方案 A 可行的前提。

---

## 三、差异全景

### 3.1 结构映射

| 上游（sing-ebpf alpha.13） | 本仓库 | 说明 |
|---|---|---|
| `internal/core/`（51 个非测试 .go） | `common/ebpf/`（40 个） | 压平 + 改名；同名 33，缺 18 |
| `runtime/`（13 个非测试 .go） | `protocol/ebpf/` 的 `tc_*.go`（37 个合计） | 同名仅 4：`tc_dataplane`/`tc_netlink`/`tc_routing`/`shared_rewrite_dataplane` |
| `runtime/api.go`（321 行） | 无 | 宿主入口 `NewTCRuntime`/`NewSharedPacketRewriteRuntime` |
| `internal/bpfgen/` + `native/`（BPF 字节码与 C 源） | `common/ebpf/internal/bpfgen/` + `native/` | 结构一致，9 个同名文件 |

### 3.2 代码规模

| 项 | 数值 |
|---|---|
| 本仓库 eBPF 相关（非测试） | **86 文件 / 26,582 行**（`protocol/ebpf` 37/14,279；`common/ebpf` 49/12,303） |
| 上游 `internal/core` | 51 文件 |
| 上游 `runtime` | 13 文件 / **4,943 行**（含 api 321、reconcile 651、isolated_delivery 389） |
| 上游缺失模块合计 | **1,990 行** |

### 3.3 缺失清单（runtime 层）

| 文件 | 行数 | 职责 | 依赖 |
|---|---|---|---|
| `tc_reconcile.go` | 651 | 完整对账/修复（挂载、路由、maps） | core API、cilium/ebpf、netlink |
| `tc_isolated_delivery.go` | 389 | 隔离投递通道（netns 内 veth 对） | core API、netlink |
| `api.go` | 321 | 宿主 API（`TCRuntime`/`SharedPacketRewriteRuntime`） | core |
| `sysctl_lease.go` | 157 | sysctl 引用计数租约（多实例不打架、退出后还原） | core（`internal/core`） |
| `tc_namespace.go` | 131 | 命名空间句柄 `NewTCNamespace()` | **`vishvananda/netns`（新依赖）** |
| `tc_health.go` | 124 | 只读健康检查（看门狗第一级） | netlink |
| `tc_delivery.go` | 99 | 投递编排 | core API、netlink |
| `tc_topology.go` | 98 | 挂载拓扑 diff | core API、netlink |
| `core_access.go` | 20 | 库内部 → 宿主的最小暴露面 | core |

### 3.4 缺失清单（core 层，18 个）

```
access.go  bpf_permission.go  cgroup_netd.go  cgroup_network_state.go
decision.go  diagnostics.go  icmp_echo_reply_backend.go  instance_slot.go
kernel_probe_object.go  kernel_probe_plan.go  map_occupancy.go
program_name.go  redirect_route.go  runtime_resources.go  runtime_state.go
tc_icmp_echo_reply.go  tc_return.go  tcx_order.go
```

其中 `instance_slot.go`（单实例槽位）、`access.go`/`bpf_permission.go`（访问门控）、`kernel_probe_plan.go`（探测计划分层）是方案 A 的硬前置。

### 3.5 我们并非"完全没有看门狗"

必须纠正一个容易误判的点。本仓库 `protocol/ebpf/interface_monitor.go` 里已有：

- `tcHealthCheckInterval = 10 * time.Minute` —— 无条件低频重查（注释明确写"用于捕捉没有任何事件会触发的漂移"）
- 重试退避 `tcRetryInitialDelay = 2s` → `tcRetryMaximumDelay = 1min`，按组件（shared rewrite / general / bypass ruleset）分别计时
- `tc_stale_reclaim.go`（165 行）：回收残留的策略路由与投递链

**我们缺的是"两阶段"和"拓扑模型"**：

| 能力 | 上游 | 我们 |
|---|---|---|
| 健康检查分离为只读阶段 | `healthCheck()` 只读，漂移才进 `reconcile()` | 单阶段：tick 直接重跑 update（会执行变更） |
| 挂载拓扑 diff | `desiredAttachmentState()` + `tcAttachmentTopologyChanged()` | 无独立拓扑模型，靠重跑 attach |
| 命名空间对象化 | `NewTCNamespace()` + `netns` 句柄 | 无，始终在默认 ns |
| 投递通道抽象 | `tc_delivery` / `tc_isolated_delivery` | `tc_sysctl.go` 里直接拼 veth 名 |
| sysctl 多实例安全 | 引用计数租约，退出还原原值 | `tcSysctlState` 记录后还原，无租约/无多实例协调 |
| 宿主 API 分层 | `runtime/api.go` 的 `TCRuntime` 接口 13 个方法 | 宿主与数据面直接耦合 |

这解释了为什么"症状轻微而非完全失效"：我们有一层退化版的看门狗。

---

## 四、方案 A：切换为 `sing-ebpf` 模块依赖

### 4.1 目标形态

```
protocol/ebpf/inbound.go          薄宿主：配置解析、事件订阅、router 回调
        │
        ├── runtime.NewTCRuntime(TCRuntimeConfig{...})  → TCRuntime
        └── runtime.NewSharedPacketRewriteRuntime(...)  → SharedPacketRewriteRuntime

依赖：github.com/CHIZI-0618/sing-ebpf v0.1.0-alpha.13
删除：common/ebpf（49 文件 / 12,303 行，改为模块引用）
```

宿主需要提供的钩子只有 4 个（`SharedPacketRewriteHooks`）：

```go
PrepareBackend     func() (*core.SharedPacketRewriteBackend, error)
PurgeUserspaceFlow func()
Ready              func([]string)
WarnFlowPurge      func(interfaceName string, err error)
```

`TCRuntimeConfig` 需要：`Namespace *TCNamespace`（`NewTCNamespace()` 现成）、`Backend *core.TCBackend`、`IPv6Enabled`、`LocalInterface`、`SharedInterfaces`、`HostAddresses`、`SharedSourceMACPolicy`、`Priority`。

### 4.2 接口覆盖度实测

我们代码里对 `commonEBPF.*` 的引用：**49 个文件、172 处、72 个去重符号**（全部为导出符号，这点有利）。

| 类别 | 数量 | 说明 |
|---|---|---|
| 库已直接导出 | **40** | 如 `PrepareTC`、`PrepareCgroup`、`ProbeKernel`、`KernelProbe*`、`ClassifyTCLinkFraming`、`MapOccupancy`、`MaxConfigurableMapCapacity`、`ProcessTracker`、`AttachProcessTracker` |
| 改名/移位可映射 | 约 20 | 见下表 |
| 新 API 无同名对应 | 约 12 | `DNSMode`×4、`MapPressureInt64`/`MapPressureLevel`、`CgroupConfig`、`PortRange`、`UIDRange`、`PolicyConfig`、`ProcessTrackerConfig`、`CgroupUDPCleanupSocketRelease` |

改名映射（已核对 api.go）：

| 我们用的 | 库 alpha.13 对应 |
|---|---|
| `PrepareSharedNetwork` / `SharedNetworkConfig` / `SharedNetworkBackend` | `PrepareSharedPacketRewrite` / `SharedPacketRewriteConfig` / `SharedPacketRewriteBackend` |
| `DefaultSharedNetworkMapCapacities` | `DefaultSharedPacketRewriteMapCapacity` + 各 map 单项容量类型 |
| `CompilePolicy` / `CompileBypassCIDRPolicy` | `CompileActionPolicy` |
| `LocalPolicy` / `BypassCIDRPolicy` | `ActionPolicy` / `ActionScope` |
| `TCBackend` / `TCConfig` | `runtime.TCRuntime` / `runtime.TCRuntimeConfig` |
| `FlowMapCapacities` / `DefaultFlowMapCapacities` | `UDPFlowMapCapacity`、`TCPRedirectMapCapacity`、`UDPRedirectMapCapacity`、`UDPPeerMapCapacity`、`UDPRecoveryMapCapacity`、`SocketBypassMapCapacity` |
| `SelfBypass`（类型） | 只导出构造函数 `NewSelfBypass` / `NewSelfBypassWithCapacity` |
| `KernelProbeDataPlaneTC` | `KernelProbeDataPlane` + `KernelProbeMode*` |
| `TCStat*`（5 个） | `TCStats` / `TCDiagnostics` |

> 注意：`SelfBypass` 类型不再导出，意味着任何持有该结构体字段、或直接构造的代码都必须改成走构造函数。

### 4.3 改动规模

| 工作项 | 涉及面 |
|---|---|
| 引入模块依赖 + 删除 `common/ebpf` | go.mod、`common/ebpf/` 全部 49 文件、`internal/bpfgen`、`native`（构建脚本要改，BPF 字节码由库提供） |
| `protocol/ebpf` 重写为薄宿主 | 37 文件 / 14,279 行里，预计保留 `inbound`、`config`、`shared_rewrite` 胶水、`fakeip`、`android_uid`、策略日志等约 1/3，其余（`tc_*`、`udp_nat`、`udp_state`、`interface_monitor`）由库接管 |
| 12 个"无对应"符号重新设计 | DNS 拦截模式改为 `SocketMetadataPolicy*`；map 压力指标改为 `MapCategory`/`MapOccupancy`；`PortRange`/`UIDRange` 改为决策对象 |
| 新增依赖 | `github.com/vishvananda/netns`（纯 Go，无 cgo） |
| 回归验证 | 需覆盖：TC 挂载/卸载、漂移恢复、UDP NAT 会话、shared rewrite、FakeIP、cgroup 拦截、netns 场景 |

参考量级对比：我们当前的 `tc_dataplane.go` 是 **2,004 行**，上游同一职责的 `runtime/tc_dataplane.go` 只有 **1,112 行**（因为把 delivery/reconcile/health 拆出去了），两者 diff 达 **1,355 行**——即"不是改几处调用，是换一套骨架"。

### 4.4 风险

| 风险 | 等级 | 说明 |
|---|---|---|
| 上游仍是 alpha，接口会动 | 高 | alpha.10→13 已多次调整 runtime 内部（runtime 目录 38→49 文件）；一旦跟进就要重复适配 |
| 深水区功能回归 | 高 | UDP NAT 会话管理、自绕回（self_bypass）、TC 交付路径是线上依赖的关键路径，换实现后必须重做我们之前那些 bug 的验证 |
| 我们的本地修复会丢失 | 中 | UDP NAT 表容量 1024→可配置（`udp_sessions`）是我们自己加的，库里需确认是否等价；否则要向上游提 patch |
| BPF 字节码来源变化 | 中 | 现在 `native/` + `bpfgen/` 在树内可改，换模块后不可改 |
| 依赖第三方仓库 | 中 | 项目从"单仓自足"变成依赖 `CHIZI-0618/sing-ebpf`；该仓库若停更，我们被锁死 |

### 4.5 回滚

方案 A 是整体替换，回滚靠分支：在 `ebpf-module` 分支做，`tc-rewrite-clean` 保持不动；内核产物按版本号并存（`sing-box.bak-v33`）。

---

## 五、方案 B：只移植对账 / 看门狗

### 5.1 目标

在现有结构上补齐"拓扑模型 + 两阶段健康检查 + 完整对账 + sysctl 租约"，不动 26,582 行的整体架构。

### 5.2 移植清单（按依赖关系分层，不是按文件）

**B1｜拓扑 diff（可独立完成，最低风险）**

| 上游文件 | 行数 | 内容与改造点 |
|---|---|---|
| `tc_topology.go` | 98 | 纯函数 `desiredTCAttachmentState()`、`tcAttachmentTopologyChanged()` + 方法 `attachmentStateChanged()` |
| `tc_reconcile.go` 里的 `desiredAttachmentState()` | 11 | 只调用 `desiredTCAttachmentState` + `d.linkByName()` + 读 `d.attachments`，**自足，无 netns/隔离投递依赖** |

我方已有 `tcInterfaceAttachment`、`tcInterfaceRole`（15 个文件在用）、`attachments []*tcInterfaceAttachment`、`linkByName()`，结构可直接承接。`retainLocalAttachmentStates`（移动网络切换时保留旧 local 挂载）一并带过来。

**B2｜两阶段健康检查（可行，但隔离部分要留桩）**

`tc_health.go`（124 行）的 `healthCheck()` 实际调用：

| 调用 | 我方现状 |
|---|---|
| `d.desiredAttachmentState()` | B1 带过来即可 |
| `d.backend.RequiresRebuild()` | **已有**（`common/ebpf/tc.go:457`） |
| `r.healthy()`（策略路由） | 需从现有 `ensure()` / `inspectTCPolicyRoutingFamily()` 适配 |
| `d.tcDeliveryLink.healthy()` | 需从 `tc_sysctl.go` 的 veth 逻辑抽出 |
| `d.inNamespace()` / `d.isolatedReplyMTU()` / `d.healthyIsolated()` | **缺，属隔离投递；B2 阶段留桩返回"不需要隔离"** |

**B3｜完整对账（与隔离投递 + netns 不可拆）**

这是本次评估修正的一个关键结论。`tc_reconcile.go`（651 行）本身不直接引用库符号，但它调用：

```
createIsolatedTCDeliveryLink / isolatedReplyMTU / inNamespace   → tc_isolated_delivery.go（389 行）
retainRetiredDelivery / closeRetired / retainRetiredAttachment
/ linkByName / attachInterface                                  → tc_dataplane.go（我方已有同名实现）
```

也就是说 **`tc_reconcile` → `tc_isolated_delivery` → `tc_namespace` 是一条硬链**，三者必须一起做：

| 文件 | 行数 | 说明 |
|---|---|---|
| `tc_isolated_delivery.go` | 389 | 隔离投递（netns 内 veth 对、MTU 计算、清理） |
| `tc_namespace.go` | 131 | `NewTCNamespace()`；新增依赖 `vishvananda/netns` |
| `tc_delivery.go` | 99 | 投递编排 |
| `sysctl_lease.go` | 157 | 独立可做：把 `tcSysctlState`（记录+还原）升级为引用计数租约 |

**B4｜可选增强**：`core_access.go` + `api.go`（20 + 321 行）—— 只有决定长期走模块化才需要，本质上是方案 A 的前置。

### 5.3 真正的前置条件（修正版）

初评时曾判断"需先补 core 层的 `kernel_probe_plan`、`runtime_state` 等"。核对后**这个判断不成立**：

- `tc_reconcile.go` 不引用任何库包符号，只调用 `d.*` 方法；
- `healthCheck` 唯一用到的 core 能力是 `backend.RequiresRebuild()`，我方 `TCBackend` / `SharedNetworkBackend` **都已实现**；
- core 层缺的 `instance_slot.go`（单实例槽位）、`tc_return.go`、`tcx_order.go`、`decision.go` 属能力增强，不是对账的前置。

真正的硬前置只有一条：**B3 要连隔离投递和 netns 一起搬**。B1、B2 可以先独立落地。

### 5.4 改动规模

| 工作项 | 规模 |
|---|---|
| B1（拓扑 diff） | 约 110 行移植 + 接入现有 attach/监控循环 |
| B2（两阶段健康） | 124 行移植 + 隔离部分留桩 |
| B3（对账 + 隔离投递 + netns） | 651 + 389 + 131 + 99 = 1,270 行，整体推进 |
| B3 附（sysctl 租约） | 157 行，可独立 |
| 合计 | 约 1,990 行（不含测试） |
| 需前置补的 core 层 | **基本不缺**；`RequiresRebuild` 等已具备，仅可选增强（instance_slot / tc_return） |
| 需改写的现有文件 | `interface_monitor.go`（847 行，健康循环拆两阶段）、`tc_dataplane.go`（2,004 行，attach 走拓扑 diff）、`tc_sysctl.go`（293 行，改租约）、`tc_stale_reclaim.go`（165 行，并入对账） |
| 新增依赖 | `github.com/vishvananda/netns`（仅 B3 的 netns 部分需要） |

### 5.5 收益（按优先级）

| 收益 | 来源 | 对应你遇到过的现象 |
|---|---|---|
| 漂移可检测、可修复 | `tc_health` + `tc_reconcile` | "启动初期无网、几分钟后自愈"——现在靠 tick 重跑，将来是只读检测 + 定向修复 |
| 挂载错乱能自纠 | `tc_topology` | 切换 Wi-Fi/移动网络后 TC 挂错网卡、不恢复 |
| 多实例不互相踩 | `sysctl_lease` + `instance_slot` | 面板重启与手动启动并存时 sysctl/veth 冲突 |
| 对账有基线可日志化 | `runtime_state` | 出问题时能说清"哪里漂了"，而不是靠猜 |

### 5.6 风险

| 风险 | 等级 | 说明 |
|---|---|---|
| `tc_reconcile.go` 与我们的策略路由实现语义不同 | 中高 | 我们有 `tc_routing.go`（651 行）自带一套策略路由，上游对账会重排这部分；需先做行为对齐再替换 |
| 两阶段改造引入新的时序 bug | 中 | 健康检查变只读后，变更路径收敛到 reconcile，若事件与 tick 竞争处理不当会出现"检测到但不修" |
| netns 引入后影响现有挂载 | 中 | 我们一直是默认 ns 直挂，改成持有句柄后 `attach` 目标可能变化，需在真机验证 |
| 与上游持续分叉 | 中 | B 是手工移植，上游后续改动仍需手工跟；但比 A 可控（局部） |

### 5.7 回滚

按文件粒度可控：新增文件都是新路径，`interface_monitor.go` / `tc_dataplane.go` 的改动可用 git 单文件回退；内核产物按版本号并存。

---

## 六、两方案对比

| 维度 | A：换模块依赖 | B：增量移植 |
|---|---|---|
| 改动性质 | 架构替换 | 局部补齐 |
| 触及代码 | `common/ebpf` 全部 49 文件 + `protocol/ebpf` 大部分（约 26,582 行中 2/3） | 新增约 1,990 行 + 改 4 个现有文件 |
| 获得能力 | 全部上游能力（含 netns 隔离投递、单实例槽位、访问门控、探测计划） | 拓扑/健康/对账/租约（B3 后含 netns 隔离；单实例槽位仍需单独补） |
| 接口适配 | 72 个符号，40 直接可用，32 需映射或重设计 | 无接口适配，纯代码移植 |
| 后续同步成本 | 低（改版本号 + 小适配） | 中（每次手工移植） |
| 上游稳定性依赖 | 高（alpha 线，接口会动） | 低（一次移植） |
| 回归验证范围 | 全量（TC/UDP/self_bypass/FakeIP/cgroup） | 聚焦数据面挂载与对账 |
| 丢失本地修复风险 | 有（UDP NAT `udp_sessions` 配置项等） | 无 |
| 适合时机 | 库出 1.0 / 稳定 tag 后 | 现在 |

---

## 七、建议路径

**分阶段，先 B 后 A；B 分三级推进，B3 是整包。**

1. **阶段 0｜基线固化**：把当前 v33 内核与配置备份归档；记录现有数据面行为基线（attach 拓扑、sysctl 值、UDP 会话数、启动到可用的耗时），作为后续对照。
2. **阶段 1｜B1（拓扑 diff）**：移植 `tc_topology.go` + `desiredAttachmentState()`，让 attach 走"目标状态 vs 现有挂载"的比对，而不是无脑重跑。风险最低，可先只做观测（打日志比对结果、不改变行为）再切执行。
3. **阶段 2｜B2（两阶段健康）**：移植 `tc_health.go`，把 10 分钟 tick 的"重跑 update"改成"只读检测 → 有漂移才进入变更"；隔离投递相关方法先留桩。这一步直接对应"启动初期无网 / 漂移不自愈"。
4. **阶段 3｜B3（对账整包）**：`tc_reconcile` + `tc_isolated_delivery` + `tc_namespace` + `tc_delivery` 一起搬（硬依赖链，不可拆），并做 `sysctl_lease`。前提是先把 `tc_routing.go` 的策略路由语义与上游对账流程对齐。
5. **阶段 4｜评估 A**：若库发布稳定 tag，且我们确实需要单实例槽位/访问门控这类宿主级能力，再按第 4 章映射表做 PoC（分支上跑通 `NewTCRuntime` + 一个 inbound，不替换线上）。
6. **不要单独做**：把 `tc_isolated_delivery` 从 B3 里拆出来单独移植——它和 reconcile、netns 是硬依赖，拆开只会得到一段无法接线的代码。

---

## 附录：证据与复现

```bash
# 1. eBPF 不在 SagerNet 上游
git ls-tree -r --name-only v1.15.0-alpha.8  | grep -ci ebpf   # 0
git ls-tree -r --name-only v1.15.0-alpha.13 | grep -ci ebpf   # 0

# 2. 胶水层已追平（head == 我们移植基准）
git ls-remote --heads https://github.com/CHIZI-0618/sing-box refs/heads/ebpf-inbound
# 764219fb22e25ac4d7c03701cd6d9a43bfa4614e

# 3. 核心库版本线
git -C sing-ebpf log -1 --format='%ci %h' v0.1.0-alpha.13   # 2026-10-18
git -C sing-ebpf log -1 --format='%ci %h' main              # 2026-09-25

# 4. 符号覆盖
grep -rhoE 'commonEBPF\.[A-Za-z_][A-Za-z0-9_]*' . | sed 's/commonEBPF\.//' | sort -u | wc -l   # 72
# 库 api.go 对外符号 113，交集 40

# 5. 代码规模
protocol/ebpf  37 文件 14,279 行
common/ebpf    49 文件 12,303 行
```

**数据来源文件（本地副本）**

- `upstream-ref/`：SagerNet/sing-box tag a8、a13
- `chizi-ref/`：CHIZI-0618/sing-box 的 `ebpf-inbound`、`stable`、`testing-ref1nd`
- `sepbf-ref/`：CHIZI-0618/sing-ebpf 的 alpha.10 ~ alpha.13 与 main
