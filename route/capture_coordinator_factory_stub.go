//go:build !with_ebpf || (!linux && !android)

package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func NewCaptureCoordinator(_ context.Context, _ *NetworkManager, _ adapter.InboundManager, _ log.ContextLogger) adapter.LifecycleService {
	return nil
}
