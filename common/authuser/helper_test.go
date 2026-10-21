package authuser

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/auth"
)

func TestResolveUserName(t *testing.T) {
	names := []string{"alice", "", "carol"}

	if _, ok := ResolveUserName(t.Context(), &adapter.InboundContext{}, names); ok {
		t.Fatal("expected ok=false without authenticated user")
	}

	m := &adapter.InboundContext{}
	ctx := auth.ContextWithUser(t.Context(), 0)
	if name, ok := ResolveUserName(ctx, m, names); !ok || name != "alice" || m.User != "alice" {
		t.Fatalf("alice: name=%q ok=%v metadata=%q", name, ok, m.User)
	}

	m = &adapter.InboundContext{}
	ctx = auth.ContextWithUser(t.Context(), 1)
	if name, ok := ResolveUserName(ctx, m, names); !ok || name != "1" || m.User != "" {
		t.Fatalf("unnamed: name=%q ok=%v metadata=%q", name, ok, m.User)
	}
}
