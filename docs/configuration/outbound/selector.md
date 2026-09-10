### Structure

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

    The selector can only be controlled through the [Clash API](/configuration/experimental#clash-api-fields) currently.

### Fields

#### outbounds

List of outbound tags to select.

#### providers

List of [Provider](/configuration/provider) tags to select.

#### use_all_providers

Use all [Provider](/configuration/provider) to fill `outbounds`.

#### exclude

Exclude regular expression to filter `providers` nodes. The priority of the exclude expression is higher than the include expression.

#### include

Include regular expression to filter `providers` nodes.

#### default

The default outbound tag. The first outbound will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.

#### udp_outbound

> [!NOTE]
> This field is added by this fork and does not exist upstream.

Delegate UDP (packet) traffic to this outbound instead of handling it through the
selected member outbound. The target outbound must support UDP.

`udp_outbound` is resolved when the selector is used, not when it is created, so
the target may be any outbound defined in the configuration, including one that is
not part of `outbounds`.

#### udp_fallback_outbound

> [!NOTE]
> This field is added by this fork and does not exist upstream.

A secondary outbound used when the primary `udp_outbound` fails. It has no effect
unless `udp_outbound` is set; configuring it alone is rejected at startup.

If neither can handle the connection, the error reports both attempts:

```
delegate udp_fallback_outbound failed: <fallback>; primary udp_outbound <primary> failed: <error>
```
