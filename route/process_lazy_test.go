package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type lazyTestSearcher struct{}

func (lazyTestSearcher) FindProcessInfo(ctx context.Context, network string, source, destination [4]uint8) (*adapter.ConnectionOwner, error) {
	return nil, nil
}
func (lazyTestSearcher) ResetCache()  {}
func (lazyTestSearcher) Close() error { return nil }

func TestProcessInfoResolverIsLazyAndMemoized(t *testing.T) {
	calls := 0
	metadata := &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{UserId: 10123},
		ProcessInfoResolver: []func() *adapter.ConnectionOwner{func() *adapter.ConnectionOwner {
			calls++
			return &adapter.ConnectionOwner{UserId: 10123, ProcessPaths: []string{"/system/bin/app_process64"}}
		}},
	}
	if calls != 0 {
		t.Fatal("resolver ran before it was asked")
	}
	if first := metadata.ResolveProcessInfo(); calls != 1 || len(first.ProcessPaths) != 1 {
		t.Fatalf("resolver did not produce paths on demand: calls=%d", calls)
	}
	second := metadata.ResolveProcessInfo()
	if calls != 1 {
		t.Fatalf("resolver re-ran on a cached answer: calls=%d", calls)
	}
	if second.UserId != 10123 {
		t.Fatal("memoized answer lost the uid")
	}
}

func TestProcessInfoResolverAbsentDegradesToProcessInfo(t *testing.T) {
	metadata := &adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{UserId: 1000}}
	if got := metadata.ResolveProcessInfo(); got == nil || got.UserId != 1000 {
		t.Fatal("missing resolver must keep the owner-only result")
	}
}
