`http` 出站是一个 HTTP CONNECT 代理客户端

### 结构

```json
{
  "type": "http",
  "tag": "http-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "username": "sekai",
  "password": "admin",
  "path": "",
  "headers": {},
  "tls": {},

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### username

Basic 认证用户名。

#### password

Basic 认证密码。

#### path

HTTP 请求路径。

#### headers

HTTP 请求的额外标头。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#出站)。

#### udp_outbound

> [!NOTE]
> 该字段由本 fork 添加，上游不存在。

将 UDP（数据包）流量委派给指定出站处理，而不是通过 HTTP 代理隧道转发。
目标出站必须支持 UDP。

不设置时该出站只声明 TCP；设置后它会同时声明 UDP，路由规则才可能把 UDP 流量匹配到这里。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
