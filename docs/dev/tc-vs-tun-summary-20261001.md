# sing-box TC / TUN 测试总结

日期：2026-10-01  
源码目录：`/var/minis/shared/singme-build`  
测试设备：Android arm64 真实设备  
Go：`go1.26.6`  

## 当前结论

TC 资源清理修复已经完成设备级验证，但尚未推送远端。

已经确认：

- TC 停止、切换和重启后，不再持续累积 IPv4/IPv6 策略规则。
- TC 停止、切换和重启后，不再持续累积 delivery veth。
- TC 停用期间没有发现错误挂到 `ccmni`。
- WiFi 使用 TC，蜂窝使用 TUN，混合模式单活切换能够运行。
- 当前 Android 测试核心没有 `FATAL`，能够正常启动和运行。
- 代码还没有 commit、push 或创建 Release。

切网瞬间仍观察到少量 `network is unreachable`。它发生在 TUN 拆除和 TC 恢复的过渡窗口，切换完成后网络恢复。资源状态和核心进程最终状态正常，但这个短暂断流窗口还没有单独优化。

## 已完成的 TC 修复

涉及文件：

- `protocol/ebpf/capture_owner.go`
- `protocol/ebpf/capture_runtime.go`
- `protocol/ebpf/inbound.go`
- `protocol/ebpf/interface_monitor.go`
- `protocol/ebpf/tc_capture_runtime.go`
- `protocol/ebpf/tc_dataplane.go`
- `protocol/ebpf/tc_routing.go`

修复内容：

1. TC owner 停用时不再只关闭 backend 开关，而是拆除运行时 attachment、策略路由和 delivery veth。
2. TC owner 再次激活时重新创建路由、delivery veth 和接口 attachment。
3. 初次 `Deactivate` 即使 owner 尚未标记为 active，也会清理已经 staged 的资源。
4. TC 停用期间，接口监控不再修复或重新挂载 TC attachment。
5. TC 停用期间不会跟随默认接口变化而挂到蜂窝 `ccmni`。
6. 启动时增加精确匹配的遗留 IPv4/IPv6 TC 路由和 delivery veth 回收。
7. 删除了不可靠的全局资源扫描路径，避免误删其他实例或其他 owner 的资源。

## 本地测试

以下定向测试通过：

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOMAXPROCS=1 \
  go test -p=1 -tags with_ebpf \
  ./protocol/ebpf ./route ./common/capture
```

结果：

```text
protocol/ebpf     PASS
route             PASS
common/capture    PASS
```

Android arm64 编译通过：

```text
GOOS=android GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0 \
  go build -p=1 -trimpath -ldflags '... -s -w -buildid=' \
  -tags 'with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale,badlinkname,tfogo_checklinkname0' \
  ./cmd/sing-box
```

最新测试核心：

```text
大小：65208580 bytes
SHA256：042928e4ed4841933f895a3555e067ba0b31e5c11acc9ff88aa8d0ce8f8674e3
```

设备共享目录中的测试文件：

```text
/var/minis/mounts/mins/sing-box-tc-fix3
```

设备上当前测试核心备份：

```text
/data/local/tmp/sing-box.tcfix3.backup
```

## 设备验证

### 启动

测试核心启动成功：

- eBPF inbound 正常启动。
- TUN runtime 由 capture coordinator 延迟激活。
- WiFi 被识别为 `mode=tc`。
- sing-box 正常启动。
- `FATAL=0`。

### 连续重启

连续重启后观察到：

```text
IPv4 TC 规则：1 组
IPv6 TC 规则：1 组
delivery veth：1 对
```

第一次和第二次重启之间数量没有增长。

### WiFi → 蜂窝

蜂窝阶段观察到：

```text
delivery veth：0
TC IPv4 规则：0
tC IPv6 规则：0
```

TC 没有残留接管路径，也没有观察到绑定到 `ccmni` 的 TC 资源。TUN 接管蜂窝流量。

### 蜂窝 → WiFi

回到 WiFi 后观察到：

```text
delivery veth：1 对
TC IPv4 规则：1 组
TC IPv6 规则：1 组
```

资源重新建立，没有多出第二组规则或第二对 veth。

## 完整测试套件失败项

完整命令：

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOMAXPROCS=1 \
  go test -p=1 -tags with_ebpf ./...
```

完整套件不是全绿，但失败项没有指向本次 TC 修改。

### 沙盒权限限制

当前 Alpine PRoot 不提供这些测试所需的系统能力：

- `common/netns`：创建 network namespace 失败，`operation not permitted`。
- `common/process`：访问 netlink socket 失败，`permission denied`。
- `common/tlsspoof`：创建 IPv4/IPv6 raw socket 失败，`operation not permitted`。

这些测试需要真实 Linux capability 或 Android/root 环境，不能用当前 PRoot 结果判断 TC 修复失败。

### sing-tun API 尚未全树迁移

以下模块仍使用旧版 sing-tun API：

- `protocol/openconnect`
- `protocol/openvpn`
- `transport/wireguard`

错误包括：

```text
PacketHeadroom 不存在
Device.ReturnPath 不存在
MemoryTun.ReadPackets 不存在
inputPackets 函数签名不匹配
```

新 TUN inbound 本身已经在 Android 设备上运行通过，但整个源码树还没有完成新版 sing-tun API 迁移。

### Go 1.26 runtime linkname

以下模块使用旧的 runtime 私有符号：

- `experimental/boxdd`
- `experimental/libbox`

错误：

```text
invalid reference to runtime/pprof.parseProcSelfMaps
```

这是 `go:linkname` 与 Go 1.26 的兼容问题。

### 其他已有代码问题

- `cmd/internal/tun_bench`：`badoption.Listable` 类型已变化。
- `experimental/clashapi`：测试硬编码的 Android 进程路径与当前 `/system/bin/app_process64` 不一致。

## 三种模式的性能测试状态

性能开销目前还没有正式量化。

| 模式 | 功能验证 | 性能数据 |
|---|---|---|
| 纯 TC | 已验证 | 未测 CPU、RSS、吞吐、延迟、丢包 |
| 纯 TUN | 新 TUN 蜂窝运行已验证 | 未测独立性能基准 |
| TC + TUN 混合 | WiFi↔蜂窝单活切换已验证 | 未测切换压力和长期开销 |

建议测试拓扑：

```text
电脑：流量发生器、iperf3、数据采集
手机：真实 Android 被测设备
```

建议顺序：

1. 纯 TC：固定 WiFi，测试 TCP/UDP 吞吐、CPU、RSS、延迟。
2. 纯 TUN：固定蜂窝，测试同一组流量指标。
3. 混合模式：持续压流，反复 WiFi↔蜂窝，记录切换断流时间、CPU、RSS、规则、veth 和丢包。

每种模式至少记录：

- sing-box 进程 CPU 百分比。
- RSS 和内存增长。
- TCP 上下行吞吐。
- UDP 吞吐、丢包、抖动。
- TCP 建连延迟。
- 切网到恢复的时间。
- IPv4/IPv6 TC 规则数量。
- TC delivery veth 数量。
- `FATAL`、`SYN_SENT` 和 `network is unreachable` 数量。

## 当前文件和回滚

源码工作树：

```text
/var/minis/shared/singme-build
```

当前测试核心：

```text
/var/minis/mounts/mins/sing-box-tc-fix3
```

设备回滚核心：

```text
/data/local/tmp/sing-box.tcfix3.backup
```

回滚方式：先通过设备侧 root 将备份原子替换回 `/data/adb/sfmr/bin/sing-box`，再执行现有 `relaunch.sh`。

## 下一步

1. 单独定位并缩短 TUN→TC 恢复时的 `network is unreachable` 窗口。
2. 完成 openconnect、openvpn、wireguard 对新版 sing-tun API 的迁移。
3. 用电脑作为流量发生器，完成纯 TC、纯 TUN、混合模式性能对比。
4. 性能和切换窗口验证通过后，再整理无关工作树改动、提交 commit、推送远端并创建 Release。
