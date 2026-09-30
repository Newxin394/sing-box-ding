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

// captureDeferrer lets the coordinator suppress each backend's self-activation
// during the staged inbound lifecycle. Without it, TUN (PostStart) and eBPF
// (Start) both begin capturing before the coordinator runs in Started, creating
// a dual-capture startup window.
type captureDeferrer interface {
	SetCaptureDeferred(deferred bool)
}

// NewCaptureCoordinator discovers the configured TUN and eBPF inbounds after
// they have been constructed. It returns nil unless both backends exist; the
// legacy single-backend configuration remains unchanged.
func NewCaptureCoordinator(ctx context.Context, network *NetworkManager, inbounds adapter.InboundManager, logger log.ContextLogger) adapter.LifecycleService {
	var (
		tcInbound, tunInbound adapter.Inbound
		tcOwner, tunOwner     capture.Owner
	)
	for _, inbound := range inbounds.Inbounds() {
		provider, ok := inbound.(captureOwnerProvider)
		if !ok {
			continue
		}
		switch inbound.Type() {
		case "ebpf":
			if tcOwner == nil {
				tcInbound = inbound
				tcOwner = provider.CaptureOwner()
			}
		case "tun":
			if tunOwner == nil {
				tunInbound = inbound
				tunOwner = provider.CaptureOwner()
			}
		}
	}
	if tcOwner == nil || tunOwner == nil {
		return nil
	}
	// Both capture backends exist. Defer their self-activation so the
	// coordinator owns the single-active decision from StartStateStarted.
	for _, inbound := range []adapter.Inbound{tcInbound, tunInbound} {
		if deferrer, ok := inbound.(captureDeferrer); ok {
			deferrer.SetCaptureDeferred(true)
		} else {
			logger.Warn("capture coordinator: inbound ", inbound.Type(), " does not support deferred activation")
		}
	}
	logger.Info("capture coordinator: TUN + eBPF both present; deferring self-activation")
	return newCaptureCoordinatorService(ctx, logger, network, tcOwner, tunOwner)
}
