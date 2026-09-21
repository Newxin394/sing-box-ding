//go:build !linux && !android

package dialer

import (
	"time"

	"github.com/sagernet/sing/common/control"
)

// tcpUserTimeoutFunc is a no-op on platforms without TCP_USER_TIMEOUT.
func tcpUserTimeoutFunc(d time.Duration) control.Func {
	return nil
}
