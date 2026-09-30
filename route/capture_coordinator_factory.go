//go:build with_ebpf && (linux || android)

package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/capture"
	"github.com/sagernet/sing-box/log"
)

type captureOwnerProvider interface {
	CaptureOwner() capture.Owner
}

// NewCaptureCoordinator discovers the configured TUN and eBPF inbounds after
// they have been constructed. It returns nil unless both backends exist; the
// legacy single-backend configuration remains unchanged.
func NewCaptureCoordinator(ctx context.Context, network *NetworkManager, inbounds adapter.InboundManager, logger log.ContextLogger) adapter.LifecycleService {
	var tcOwner, tunOwner capture.Owner
	for _, inbound := range inbounds.Inbounds() {
		provider, ok := inbound.(captureOwnerProvider)
		if !ok {
			continue
		}
		switch inbound.Type() {
		case "ebpf":
			if tcOwner == nil {
				tcOwner = provider.CaptureOwner()
			}
		case "tun":
			if tunOwner == nil {
				tunOwner = provider.CaptureOwner()
			}
		}
	}
	if tcOwner == nil || tunOwner == nil {
		return nil
	}
	return newCaptureCoordinatorService(ctx, logger, network, tcOwner, tunOwner)
}
