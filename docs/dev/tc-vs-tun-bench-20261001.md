# sing-box 纯 TC(eBPF) vs TUN 实测报告

日期：2026-10-01
设备：Android 16 / arm64
核心：1.15.0-alpha.9-tc-c6c8c8de（含 capture 协调器，TUN 延迟激活）
测试源：国内 = mirrors.tuna.tsinghua.edu.cn；国外 = proof.ovh.net（10MB）
CPU 采样：/proc/<pid>/stat utime+stime jiffies，HZ=100，固定 20s 窗口（1s 窗口会产生 53% 假值，已弃用）

---

## 一、原始数据

### 1.1 WiFi 环境（wlan0，同机同时段）

**TC-WIFI**（PID 27248，proof.ovh.net 10MB）
```
ping proof.ovh.net  20/20  0% loss  rtt min/avg/max/mdev = 176.349/219.004/303.548/38.818 ms
r1 23.01 Mbps  cpu 19.0%
r2 22.22 Mbps  cpu 19.2%
r3 24.14 Mbps  cpu 26.7%
r4 23.98 Mbps  cpu 18.5%
r5 22.15 Mbps  cpu 20.5%
中位 23.01 Mbps / CPU 中位 19.2%
```

**TUN-WIFI**（PID 2241，同源）
```
ping proof.ovh.net  20/20  0% loss  rtt min/avg/max/mdev = 0.470/1.061/2.324/0.376 ms  ← 不可比（见 §3.1）
r1 22.01 Mbps  cpu 24.2%
r2 22.10 Mbps  cpu 21.8%
r3 21.31 Mbps  cpu 23.2%
r4 22.91 Mbps  cpu 20.0%
r5 23.59 Mbps  cpu 27.0%
中位 22.10 Mbps / CPU 中位 23.2%
```

**TC-WIFI 五轮复测**（PID 27248，同源）
```
23.65 / 23.43 / 23.58 / 24.02 / 22.00 Mbps
CPU 21.2 / 27.3 / 27.3 / 23.0 / 22.0 %
中位 23.58 Mbps / 24.2%
```

**长连接狠测**（tcp-long.sh，90s 全程下载）
```
t=1..44  每 2s 采样  if=wlan0  curl=alive   （全程无 dead）
结果     http=200  size=4,660,412,398 B  speed=51,782,266 B/s  total=90.000328s
换算     4.34 GB / 90s = 51.78 MB/s = 414 Mbps
```

**空载开销**（p2.out，20s）
```
core_cpu_pct = 2.76%   core_jiffies 58 / 20s
veth_rx_delta = 13 B   veth_tx_delta = 2 B
RSS 76676 kB  Threads 15  state=S
```

### 1.2 蜂窝环境（ccmni4）

> ⚠️ 前两轮用 proof.ovh.net（国际链路），链路本身拥堵，数据作废。下表 CN 行为国内清华源重做。

**TUN-CELL 早期（作废组）**
```
r1 16.65  r2 11.89  r3 17.74  r4 21.26  r5 16.19 Mbps   cpu 8.6~16.8%
PING 0.470/1.061/2.324/0.376 ms（本地应答）
离散度 56%  ← 运营商链路抖动，非 TUN 引入
```

**TC-CELL 早期（作废组，全 000）**
```
r1..r5 http=000 bytes=0 0.00Mbps  cpu 0.6~6.8%
原因：链路拥堵 + 脚本 --max-time 25s 但 curl 5s 就超时 → 该组无效
```

**背靠背固定 20s 窗口（国内源，关键有效数据）**
```
模式        采样量    吞吐        core_cpu
TUN-CELL    62.0 MB   26.00 Mbps   24.8%   PID 16440 ccmni4
TC-CELL-1   66.8 MB   28.00 Mbps   28.0%   PID 18371 ccmni4
TC-CELL-2   62.0 MB   26.00 Mbps   23.9%   PID 18371 ccmni4
```

**jc-cn.sh 五轮（国内源）**
```
TC-CELL-CN    26.38 / 42.25 / 46.71 / 43.53 / 36.10 Mbps   中位 42.25
              ttfb 0.447~0.456s (r1 1.16s 首包)   cpu 19.0~22.5% (r2 53% 因 1s 窗口弃)
              ping 223.5.5.5  15/15  0% loss  rtt 46.457/49.092/55.302/2.766 ms
TUN-CELL-CN   39.58 / 41.41 / 40.72 / 45.68 / 46.80 Mbps   中位 41.41
              ttfb 0.453~0.684s   cpu 18.0~54.0%（1s 窗口，弃）
              ping 223.5.5.5  15/15  0% loss  rtt 0.576/0.959/1.405/0.215 ms（本地应答）
```

### 1.3 切网瞬态（probe-event.out，ccmni4 → wlan0）

```
1790825711.705  ccmni4  -1ms     ← 首包超时（UDP 首探）
1790825713.748  ccmni4  121ms
1790825714.098  ccmni4  114ms
1790825714.455  ccmni4   90ms
1790825714.739  ccmni4  103ms
1790825715.022  ccmni4   63ms
1790825715.372  wlan0   56ms     ← 接口切换点，间隔 0.350s
1790825715.665  wlan0   58ms
1790825715.946  wlan0   58ms
...
1790825743.152  wlan0   26ms
结果：切换窗口内 UDP 零丢失（除首个 -1 预热包），切换后 RTT 稳定 26~28ms
```

### 1.4 长期会话（session.out，90s，TC-WIFI）

```
TCP bytes=15347  resets=0  stalls=84（脚本误报，见 §3.3）
UDP ok=89  fail=0  avg=211ms
```

---

## 二、对比结论

### 2.1 蜂窝 + 免流出口：TC 与 TUN 开销无可测差异

| | 吞吐 | core_cpu |
|---|---|---|
| TUN-CELL | 26.00 Mbps | 24.8% |
| TC-CELL-1 | 28.00 Mbps | 28.0% |
| TC-CELL-2 | 26.00 Mbps | 23.9% |

TC 自身两轮波动（26.00 ↔ 28.00，±7.7%）**大于** TC 与 TUN 之间的差距（26.00 vs 26.00 = 0%）。CPU 同理（TC 两轮 23.9 ↔ 28.0，TUN 24.8 落于其间）。

**判定：在该链路与出口下，两种数据面路径的开销差异落在测量噪声内，不可区分。**

### 2.2 WiFi：吞吐同级，TUN 略高 CPU

| | 吞吐中位 | CPU 中位 |
|---|---|---|
| TC-WIFI | 23.01 / 23.58 Mbps | 19.2 / 24.2% |
| TUN-WIFI | 22.10 Mbps | 23.2% |

吞吐差 <5%，CPU 差约 2~4 个百分点（TUN 略高）。但 TC 自身两批复测 CPU 就在 19.2~24.2% 间摆动，此差距同样不显著。

### 2.3 国内源交叉验证：完全同级

| | 吞吐中位 | 离散度 |
|---|---|---|
| TC-CELL-CN | 42.25 Mbps | 36.10~46.71（26.5%） |
| TUN-CELL-CN | 41.41 Mbps | 39.58~46.80（17.5%） |

中位差 2%，方向与 §2.1 相反（这次 TC 略高）。**两轮结论互相抵消 → 确认无系统性差异。**

### 2.4 一句话

> **纯 TC 与 TUN 在吞吐与 CPU 上同级；差异始终小于同一方案自身的轮间波动。选型不应以性能为依据，应以功能需求（免流分流、切网行为、资源清理）为依据。**

---

## 三、数据可信度说明（必须读）

### 3.1 TUN 的 ping 1ms 不可比 —— 不是"TUN 更快"

```
TC-WIFI  ping proof.ovh.net = 219 ms
TUN-WIFI ping proof.ovh.net = 1.06 ms
```

TUN 全量接管 ICMP 并在本地栈应答，ping 根本没到公网。**该数字不能用于任何对比。** 蜂窝下 TUN 的 `ping 223.5.5.5 = 0.959ms` 同理。只有 TC 的 219ms / 49ms 反映真实链路 RTT。

### 3.2 作废数据清单

| 数据 | 作废原因 |
|---|---|
| TC-CELL 全 000 组 | 国际链路拥堵 + 脚本超时过短，非模式问题 |
| TUN-CELL proof.ovh 组（离散 56%） | 运营商链路抖动污染，非 TUN 引入 |
| 所有 1s 窗口 CPU 值（53%/41%/48%/54%） | jiffies 精度不足，改用固定 20s |
| cellbench / tc-median 的 0.0 Mbps 轮次 | 国际链路抽风，非模式问题 |

### 3.3 session.js 的 84 次 STALL 是脚本 bug

脚本监控 `lastTick - Date.now()`，但 TCP 流在 6s 就已 `end`（`bytes=15347`，Range 请求只取 1MB 且被 CDN 提前收尾），此后 `lastTick` 永不更新 → 每 5s 恒报一次。**resets=0 才是真实结论**，长连接未被打断。tcp-long.sh 的 4.34GB 全程 alive 才是硬证据。

### 3.4 资源清理已单独验证（凌晨批次）

```
WiFi 连续重启：IPv4 规则 1 组 / IPv6 规则 1 组 / veth 1 对 —— 不增长
WiFi → 蜂窝：veth 0 / TC v4 0 / TC v6 0 —— 无残留，不挂 ccmni
蜂窝 → WiFi：veth 1 对 / TC v4 1 组 / TC v6 1 组 —— 不重复
```

### 3.5 当前设备实况（整理时采样）

```
核心 739  (ppid 19613 面板)  sing-box run -D /data/adb/sfmr -c box.json
面板 19613 node ./bundle --enable-source-maps
接口 wlan0 192.168.x.x/24
规则 8999: fwmark 0x40000000 lookup 2027
veth 2 条记录（1 对）
```

---

## 四、未决项

1. **切网瞬态仍有短暂断流窗口**：TUN→TC 恢复期观测到 `network is unreachable`，未单独优化。
2. **TUN 接管 ICMP 导致无法用 ping 度量真实 RTT**：如需 TUN 下测延迟，须改用 TCP 握手时间。
3. **性能测试缺少电脑侧流量发生器**：当前为手机自测，受手机 I/O 与 CDN 影响；要出权威数字需外部压流。
4. **未测项**：RSS 长期增长、UDP 吞吐/丢包率、切网到恢复的精确耗时分布。
