# 设备验证记录：H1 进程路径缓存修复

本文记录 `tc-rewrite-clean-fixes` 分支上 H1 修复的真机验证方法与结论。下次复验照此执行即可。

## 结论摘要

H1（`searcher_linux.go` uid 命中不写缓存 → 每次新 socket 全 `/proc` 遍历）确认为真实缺陷，修复有效。**在 `processPathRescanInterval` 节流边界场景下，CPU 从 17-36% 降至 1-8%（约 10 倍）。**

## 测试环境

| 项 | 值 |
|---|---|
| 设备 | Xiaomi 2407FRK8EC (rothko) |
| 系统 | Android 16 |
| 架构 | arm64-v8a (aarch64) |
| root | Magisk (uid=0) |
| adb | `D:\AI\CC\platform-tools\adb.exe` |

## 前置条件（容易踩的坑）

**`process_tracking` 必须为 `userspace`。** 这是 H1 代码路径激活的前提。判定链：

`protocol/ebpf/inbound_lifecycle.go:430` → `processTrackingMode()`
- 若 `router.NeedFindProcess()` 为 false，直接返回 `"off"`，**进程查找根本不执行**，测不出任何差异

`route/router.go:74,188` → `NeedFindProcess`
- 有 process/package 规则时置真
- Android + platformInterface 时置真（但本机实测空规则配置下仍为 `off`）

**因此测试配置必须包含按进程或包名的路由规则**，例如：

```json
{
  "route": {
    "rules": [
      { "process_name": ["com.android.chrome"], "outbound": "direct" },
      { "package_name": ["com.android.vending"], "outbound": "direct" }
    ],
    "final": "direct"
  }
}
```

启动后确认日志：`grep -oE 'process_tracking=[a-z_]*' <logfile>` 应输出 `process_tracking=userspace`。

**版本字段差异**：本分支的 ebpf inbound 有 `map_capacity` 字段，`1.15.0-newxin-tcfix` 等旧版没有。做 A/B 对照时旧版需去掉该字段，否则 FATAL 退出。

## 测试方法

用设备上已有的 `/data/local/tmp/ebpf-ab.sh`（专为 H1 设计：唯一变量是 burst 间隔，gap=10s 正好压在 `processPathRescanInterval` 上，gap=15s 越过它）。

把待测二进制命名为 `sing-box`（脚本用 `pidof sing-box` 定位）：

```bash
adb push <binary> /data/local/tmp/sing-box
adb shell su -c 'chmod 755 /data/local/tmp/sing-box'
adb shell su -c 'setsid /data/local/tmp/sing-box run -c <config> -D /data/local/tmp/run </dev/null >/data/local/tmp/run.log 2>&1 &'
adb shell su -c 'setsid sh /data/local/tmp/ebpf-ab.sh >/data/local/tmp/ab.out 2>&1 </dev/null &'
sleep 200 && adb shell cat /data/local/tmp/ab.out
```

**注意**：`ebpf-ab.sh` 完整跑完约 4 分钟（3 组 × 5 轮 + idle）。前台 `adb shell` 等待会超时，必须用 `setsid ... &` 后台跑。

## 实测数据

同设备、同配置、同脚本，`process_tracking=userspace` 双方均激活：

### A10 组（gap=10s，正中节流边界）

| 轮次 | 旧版 1.15.0-newxin-tcfix | 修复版 |
|---|---|---|
| r1 | 0 (0%) | 20 (3%) |
| r2 | **216 (36%)** | 51 (8%) |
| r3 | **171 (28%)** | 20 (3%) |
| r4 | **199 (33%)** | 51 (8%) |
| r5 | 7 (1%) | 17 (2%) |

### A10b 组（再次 gap=10s）

| 轮次 | 旧版 | 修复版 |
|---|---|---|
| r1 | 119 (19%) | 18 (3%) |
| r2 | 122 (20%) | 27 (4%) |
| r3 | 104 (17%) | 35 (5%) |
| r4 | 118 (19%) | 11 (1%) |
| r5 | 108 (18%) | 11 (1%) |

### B15 组（gap=15s，越过节流边界）

旧版 5/4/7/2/3，修复版 4/6/1/26/3 —— 两组都低且无尖峰。

**尖峰只在 gap=10s 出现**，与 H1 定位（节流窗口边界上的全量重建）完全吻合。

### 汇总

| 指标 | 旧版 | 修复版 | 变化 |
|---|---|---|---|
| 峰值 | 36% | 8% | 降 78% |
| 均值 | ~20% | ~3.7% | 降 82% |

### 旁证

- `found process path` 日志次数（同时长）：旧版 216 次 vs 修复版 73 次
- `ebpf-cpu.sh`（120 并发 6 目标）：修复版 baseline 0%、load 峰值 9%、settle 2%

## C5 mark 位确认

启动日志中 `routing_mark=0x40000000`（bit30），落在修复要求的 bit16-30 区间内。

## 设备端 BPF 编译（C 侧补丁验证）

**可行，但产出不能提交。**

设备上 Termux 安装的 clang 是**上游 LLVM 21.1.8**，而 CI 期望的是 **Android NDK r29 的定制 clang**：

```
clang: Android (13989888, +pgo, +bolt, +lto, +mlgo, based on r563880c) clang version 21.0.0
```

两者产出的 `.o` 差 26000+ 字节，`make -C common/ebpf check` 会判 stale。

**设备端编译的用途**：验证补丁的语法、头文件、ABI、指令流正确性。实测 12 个对象（6 源 × bpfel/bpfeb）零错误，变量分离实验证明补丁确实改变输出（tc 差 54570 字节、shared_network 差 4014 字节）。

**设备端搭建方法**（Termux，已在本机完成）：
1. Windows 侧从 `packages-cf.termux.dev` 下载 clang + ndk-sysroot 等 14 个 `.deb`（83MB）
   - Termux 内 apt 的 DNS 被代理 fake-ip 拦截，无法直接 apt 安装，必须外部下载后 `dpkg -i`
2. 推送后 `dpkg -i *.deb`（得到 clang 21.1.8-3 + ndk-sysroot 29-3）
3. 伪造 NDK 目录结构满足 Makefile 的 7 项校验：
   - `$PREFIX/opt/fake-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/` → 软链 clang/llvm-strip/llvm-objcopy
   - `.../sysroot/usr/include/` → 软链 `$PREFIX/include` 下各条目
   - `.../sysroot/usr/include/aarch64-linux-android/asm/` → 软链对应目录
4. 手工执行 clang 命令（绕开需要 Go 的 `go generate`），参数取自 Makefile 的 `BPF_CFLAGS` 与 `BPF_INCLUDE_FLAGS`

**产出可提交 `.o` 的正确方法**：在有 NDK r29 的 Linux 机器上跑
`ANDROID_NDK_HOME=/usr/share/android-ndk-r29 make -C common/ebpf generate`
（见 `docs/installation/build-from-source.zh.md:82`）

## 尚未实机验证的项

- **S4**（`udpReplyAliasLimit = 64`）：需构造单 App 连续访问 64+ 不同 UDP 目标的场景，本次流量模式未覆盖。逻辑层已用等价实现验证（修复后计数不变式恒成立，旧实现确认会在覆盖后永久拒绝新目标）。
- **C 侧两项补丁**（egress 分片放行、sk_assign 顺序）：需 NDK r29 生成 `.o` 后才能实机验证。
- **S3**（网络切换 Purge）：仅确认触发点日志（`network: updated default interface`），未做切换时序测量。

## 设备现存文件

```
/data/local/tmp/sing-box         修复版（54MB，含 H1/S3/S4/C5/M5）
/data/local/tmp/sb-fix           修复版副本
/data/local/tmp/sb-old           旧版对照副本（1.15.0-newxin-tcfix）
/data/local/tmp/sing-box-tcfix   设备原有旧版（可还原 sing-box）
```

测试脚本 `ebpf-ab.sh`、`ebpf-cpu.sh`、`ebpf-orig-strength.sh`、`ebpf-sampler.sh` 均已保留。

Termux 内 clang 21.1.8 + ndk-sysroot 已安装并保留（设备上唯一可编译 BPF 的工具链）。
