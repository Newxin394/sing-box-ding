`http` outbound is a HTTP CONNECT proxy client.

### Structure

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
  
  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Basic authorization username.

#### password

Basic authorization password.

#### path

Path of HTTP request.

#### headers

Extra headers of HTTP request.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

#### udp_outbound

> [!NOTE]
> This field is added by this fork and does not exist upstream.

Delegate UDP (packet) traffic to this outbound instead of tunneling it through the
HTTP proxy. The target outbound must support UDP.

Without it the outbound only advertises TCP; setting it makes the outbound
advertise UDP as well, which is what lets route rules match UDP traffic here.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
