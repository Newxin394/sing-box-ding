package option

import "github.com/sagernet/sing/common/json/badoption"

// CNSOutboundOptions configures a CNS (免流) outbound. CNS carries the real
// target inside an encrypted HTTP CONNECT header while presenting a camouflage
// Host to the carrier, and multiplexes UDP over the same TCP stream (UoT),
// which lets IPv6 / QUIC targets ride the carrier-免流 whitelist too.
type CNSOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Key is the request header name that carries the encrypted target
	// (mihomo: Proxy_key). Defaults to "Meng".
	Key string `json:"key,omitempty"`
	// Password is the XOR stream cipher key (mihomo: Encrypt_password).
	Password string `json:"password,omitempty"`
	// Flag is the extra header line sent to enable UDP-over-TCP
	// (mihomo: Udp_flag). Defaults to "httpUDP".
	Flag string `json:"flag,omitempty"`
	// Headers are camouflage headers, notably Host set to a carrier-免流
	// whitelist domain.
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
	// UDP enables UDP-over-TCP support.
	UDP bool `json:"udp,omitempty"`
}
