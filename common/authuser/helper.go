package authuser

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/auth"
	F "github.com/sagernet/sing/common/format"
)

// ResolveUserName resolves the authenticated user for inbounds whose
// service stores the user as an index in the context (vless, vmess,
// trojan, snell) and stamps metadata.User when the user carries a name.
// Returns the display name (falling back to the index when unnamed) and
// whether a user is present at all.
func ResolveUserName(ctx context.Context, metadata *adapter.InboundContext, names []string) (string, bool) {
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return "", false
	}
	name := ""
	if userIndex >= 0 && userIndex < len(names) {
		name = names[userIndex]
	}
	if name == "" {
		return F.ToString(userIndex), true
	}
	metadata.User = name
	return name, true
}
