### 结构

```json
{
  "type": "selector",
  "tag": "select",

  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
  ],
  "exclude": "",
  "include": "",
  "default": "proxy-c",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! quote ""

    选择器目前只能通过 [Clash API](/zh/configuration/experimental/clash-api/) 来控制。

### 字段

#### outbounds

用于选择的出站标签列表。

#### providers

用于选择的[订阅](/zh/configuration/provider)标签列表。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### default

默认的出站标签。默认使用第一个出站。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。

#### udp_outbound

> [!NOTE]
> 该字段由本 fork 添加，上游不存在。

将 UDP（数据包）流量委派给指定出站处理，而不是交给当前选中的成员出站。
目标出站必须支持 UDP。

`udp_outbound` 在使用时解析而非创建时解析，因此目标可以是配置里的任意出站，
包括不在 `outbounds` 列表中的出站。

#### udp_fallback_outbound

> [!NOTE]
> 该字段由本 fork 添加，上游不存在。

主 `udp_outbound` 失败时使用的备用出站。仅在设置了 `udp_outbound` 时生效；
单独配置它会在启动时被拒绝。

若两者都无法处理该连接，错误信息会同时报告两次尝试：

```
delegate udp_fallback_outbound failed: <fallback>; primary udp_outbound <primary> failed: <error>
```