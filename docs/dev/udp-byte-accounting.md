# UDP 字节采集：eBPF 侧计数设计与落地

面向场景：WiFi 大流量下载、蜂窝免流下载下的 **UDP 流量计量**（QUIC / DNS / 游戏 / 视频上行等）。

## 1. 为什么现在采不到（已实证）

- **数据路径**：UDP 走 TC 分类器快路径 —— `tc.bpf.c` 的 `local_egress_*_mark` 判定策略后由
  `assign_udp_socket()`（`sk_assign`）把包**在内核里直接挂到目标 socket**。
- **计数挂在哪**：sing-box 的流量统计是 `common/trafficcontrol/tracker.go` 的
  `Upload` / `Download` 两个 atomics，由 net.Conn 的读写包装驱动。
  包不过用户态 read/write，这两个计数器**一次都不会被调用**。
- **eBPF inbound 侧没有字节统计**：
  - `common/ebpf/native/tc.bpf.c` 中 `skb->len` / `bpf_skb_len` **零使用**。
  - `protocol/ebpf/tc_connection.go` 中 `Count|Upload|Download|bytes|stat` **零命中**。
  - `protocol/ebpf/counters.go` 是**可靠性诊断**计数（assignment 查找失败、recovery 尝试/成功/失败），
    其文档明确声明不做 per-client/per-destination、不数字节 —— **不是流量统计**。
  - `protocol/ebpf/inbound.go` 的 `processTracker` 是 `commonEBPF.ProcessTracker`（**进程**追踪），非字节。

结论：**唯一能看到全部 UDP 包的位置就是 TC 分类器本身**。

## 2. 方案：在 TC 分类器内累加 skb 长度

架构上流量先被重定向进 **redirect veth**（`protocol/ebpf/tc_dataplane.go:1864`
`backend.SetDeliveryInterface(uint32(delivery.redirect.Attrs().Index), deliveryMAC)`），
应用流量无论最终物理出口是 WiFi 还是蜂窝，**都要经过 TC hook**。
因此本方案对两个目标场景同时生效。

### 2.1 C 侧：新增计数 map

照 `tc.bpf.c:214-233` 的 `MAP(...)` 宏风格追加（该处是 `bpf_map_def SEC("maps")` 老式风格，非 BTF）：

```c
struct sb_tc_byte_counters {
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 rx_packets;
    __u64 tx_packets;
};
MAP(tc_byte_counters, __u32, struct sb_tc_byte_counters, BPF_MAP_TYPE_PERCPU_ARRAY, 4U);
```

槽位约定：`0 = UDP rx`、`1 = UDP tx`、`2/3 = 预留`（若要一并覆盖 TCP）。

用 `PERCPU_ARRAY` 而非 LRU_HASH：无锁、无竞争、容量固定，符合本项目对基数的克制
（见 `counters.go` 关于避免无界基数的说明）。

### 2.2 C 侧：开关位

`SB_TC_FLAG_*` 当前占用到 `1U << 21`（`1U << 19` 空缺 —— 不要复用，避免与历史语义冲突）。
新增：

```c
#define SB_TC_FLAG_COUNT_BYTES (1U << 22)
```

**不要给 `sb_tc_control` 加字段**：该结构有 `_Static_assert(sizeof(struct sb_tc_control) == 72, ...)`
及多处 offset 断言（`tc.bpf.c:143-148`），改动会同时牵动 Go 侧 `common/ebpf/tc.go` 的 `tcControl` 镜像。
复用 `flags` 零 ABI 风险。

### 2.3 C 侧：计数 helper 与插入点

```c
INLINE void count_bytes(struct __sk_buff *skb, __u32 slot) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || (control->flags & SB_TC_FLAG_COUNT_BYTES) == 0U) return;
    struct sb_tc_byte_counters *entry = bpf_map_lookup_elem(&tc_byte_counters, &slot);
    if (entry == 0) return;
    entry->rx_bytes += (__u64)skb->len;
    entry->rx_packets += 1ULL;
}
```

插入位置：

- **下行 UDP**：`shared_ingress_udp(struct __sk_buff *skb, bool ethernet)`（`tc.bpf.c:845`）
  函数体前段，在 `assign_udp_socket(...)` 之前。槽位 `0`。
  该函数的两个入口 `shared_ingress_ethernet_udp`(:862) / `shared_ingress_raw_ip_udp`(:867)
  是**同一包的二选一入口变体**，不会双计。
- **上行 UDP**：`local_egress_ethernet_mark`(:771) / `local_egress_raw_ip_mark`(:776) 的 UDP 分支。槽位 `1`。

**不要插在 `delivery_ingress_udp`(:894)** —— 它走 `SB_TC_PATH_DELIVERY`，
是投递段的独立入口，与 `shared_ingress_udp` 走 `SB_TC_PATH_SHARED` 属不同段，
**是否对同一包各触发一次尚未在本分支验证**（见 §7）。

## 3. Go 侧

### 3.1 打开开关

`common/ebpf/tc.go` 构造 `controlValue` 处（约 :240，现有 `controlValue.Flags |= 1 << 12` 那一带）：

```go
if config.CountBytes {
    controlValue.Flags |= 1 << 22
}
```

并在 `TCConfig`（`tc.go:70` 一带的结构）加 `CountBytes bool`，
经上层配置透传（与既有 `FakeIPICMPReply` 的透传方式一致）。

### 3.2 读取

照**项目既有范式**（不要发明新机制）—— `common/ebpf/fakeip_icmp_backend.go:252-258`
与 `common/ebpf/shared_network_flow.go:644` 都是这个写法：

```go
var perCPU []tcByteCounters
if err := statsMap.Lookup(&index, &perCPU); err != nil { return err }
for _, value := range perCPU {
    total += value.RxBytes
}
```

注意 `PERCPU_ARRAY` 的 `Lookup` 返回**每个 CPU 一份**，必须全量求和后再上报。

map 的取得方式参照 `fakeip_icmp_backend.go:83` / `shared_network_backend.go:273`
（按 name + `CiliumEBPF.PerCPUArray` 登记并查找）。

### 3.3 暴露

接到 `protocol/ebpf/counters.go` 的 `EBPFCounters`（新增 `UDPRxBytes/UDPTxBytes/UDPRxPackets/UDPTxPackets`），
或走 metrics 通道 —— 二者都在 `Diagnostics` 被调用时才读，符合该文件"读时才取、不每包记录"的既定原则。

## 4. 生成与 CI

`tc.bpf.c` 改动后必须重新生成产物，**本地改了 .o 不生效**：

```bash
cd common/ebpf
go generate ./...        # common/ebpf/generate.go 里的 bpf2go 行
```

需要一并提交的产物：`common/ebpf/internal/bpfgen/tc_bpfel.{go,o}` 与 `tc_bpfeb.{go,o}`。

相关 CI：`.github/workflows/ebpf-verifier.yml`（verifier 校验）、
`.github/workflows/android-ebpf.yml`（Android 产物）、`.github/workflows/build.yml`。

## 5. 必须处理的坑

1. **GSO**：WiFi 大流量下载必然触发 GSO，TC 层 `skb->len` 是合并后的超级包长度。
   字节总量仍然准确（len 为各段之和），但**包数会显著偏少** —— 报指标时必须区分口径，
   不要把包数当成真实报文数。
2. **重复计数**：只能选"每包恰好一次"的 hook。插入点见 §2.3，务必避免同时使用
   `shared_ingress_udp` 与 `delivery_ingress_udp`。
3. **L2 开销**：`skb->len` 含以太头。要对齐运营商计费口径需减去 14 字节（IPv4）/ 18（VLAN）。
4. **PERCPU 求和**：见 §3.2，漏掉求和会得到一个 CPU 的局部值。
5. **CPU 开销**：每包一次 map lookup + per-CPU 加法。开关默认关闭，只在需要计量时打开；
   压测时用 `top -n 1` / `/proc/PID/stat` 对比基线。
6. **免流路径**：免流若是改路由表/策略路由把特定流量**绕开 redirect veth**，
   则该部分不经 TC hook，本方案覆盖不到 —— 上手前需在真机确认免流路径是否仍走 veth。

## 6. 验证方法

1. 采基线：`top -n 1`、`/proc/PID/stat`（本项目此前**未采过基线**，先补）。
2. 开开关，跑 QUIC 大流量下载（WiFi 与蜂窝各一轮）。
3. 对比：eBPF 读数 vs 系统流量统计 vs 运营商账单口径，三者应同量级；差 2 倍即命中 §5.2。
4. 回归：确认开启计数后吞吐与 CPU 没有明显退化。
5. 回滚：任一异常，关掉开关（`flags` 位）即可，无需换二进制。

## 7. 待验证项（本文档标注为推断、尚未在本分支实测）

- `shared_ingress_udp` 与 `delivery_ingress_udp` 对同一 udp 包是否各触发一次
  （决定能否只在一个点计数，或必须显式去重）。
- 蜂窝免流路径是否经过 redirect veth（§5.6）。
- GSO 在本机型上的实际合并粒度。
