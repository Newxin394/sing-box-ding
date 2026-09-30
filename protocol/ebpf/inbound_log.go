//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// logInboundConnection mirrors the TUN inbound's per-connection INFO lines so
// eBPF-captured flows are visible in the log with an inbound/ebpf[tag] prefix.
func (i *Inbound) logInboundConnection(ctx context.Context, metadata adapter.InboundContext) {
	if metadata.Protocol == C.ProtocolDNS {
		i.logger.InfoContext(ctx, "inbound DNS connection from ", metadata.Source)
		return
	}
	i.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	i.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
}

func (i *Inbound) logInboundPacketConnection(ctx context.Context, metadata adapter.InboundContext) {
	if metadata.Protocol == C.ProtocolDNS {
		i.logger.InfoContext(ctx, "inbound DNS packet connection from ", metadata.Source)
		return
	}
	i.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
}
