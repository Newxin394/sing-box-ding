package route_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type sniffBufferAllocator struct {
	base buf.Allocator
	mu   sync.Mutex
	live map[*byte]int
	gets int
}

func (a *sniffBufferAllocator) Get(size int) []byte {
	data := a.base.Get(size)
	if len(data) != 0 {
		a.mu.Lock()
		a.live[&data[0]]++
		a.gets++
		a.mu.Unlock()
	}
	return data
}

func (a *sniffBufferAllocator) Put(data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.base.Put(data); err != nil {
		return err
	}
	key := &data[:cap(data)][0]
	if count := a.live[key]; count > 1 {
		a.live[key]--
	} else {
		delete(a.live, key)
	}
	return nil
}

func (a *sniffBufferAllocator) counts() (gets, outstanding int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, count := range a.live {
		outstanding += count
	}
	return a.gets, outstanding
}

func newFailingSniffRouter(t *testing.T, sniffer string) *route.Router {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	factory := log.NewNOPFactory()
	transports := boxDNS.NewTransportManager(factory.Logger(), nil, nil, "")
	service.MustRegister[adapter.DNSTransportManager](ctx, transports)
	dnsRouter, err := boxDNS.NewRouter(ctx, factory, option.DNSOptions{})
	require.NoError(t, err)
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)
	router := route.NewRouter(ctx, factory, option.RouteOptions{}, option.DNSOptions{}, nil)
	service.MustRegister[adapter.Router](ctx, router)
	rules := []option.Rule{
		{DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
			Action: "sniff", SniffOptions: option.RouteActionSniff{Sniffer: badoption.Listable[string]{sniffer}},
		}}},
		{DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
			Action: "resolve", ResolveOptions: option.RouteActionResolve{Server: "missing-test-dns"},
		}}},
	}
	require.NoError(t, router.Initialize(rules, nil))
	t.Cleanup(func() { require.NoError(t, router.Close()) })
	t.Cleanup(func() { require.NoError(t, dnsRouter.Close()) })
	return router
}

func trackSniffBufferAllocations(t *testing.T) *sniffBufferAllocator {
	t.Helper()
	original := buf.DefaultAllocator
	allocator := &sniffBufferAllocator{base: original, live: make(map[*byte]int)}
	buf.DefaultAllocator = allocator
	t.Cleanup(func() { buf.DefaultAllocator = original })
	return allocator
}

func TestRouteFailureReleasesSniffBuffers(t *testing.T) {
	// The allocator is process-wide; this test must not run in parallel.
	t.Run("TCP", func(t *testing.T) {
		allocator := trackSniffBufferAllocations(t)
		router := newFailingSniffRouter(t, "http")
		for range 8 {
			reader, writer := net.Pipe()
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			require.NoError(t, writer.SetWriteDeadline(time.Now().Add(5*time.Second)))
			done := make(chan error, 1)
			go func() {
				_, err := writer.Write([]byte("GET / HTTP/1.1\r\nHost: target.example\r\n\r\n"))
				done <- err
			}()
			var closeErr error
			closeCount := 0
			router.RouteConnectionEx(context.Background(), reader, adapter.InboundContext{
				Destination: M.ParseSocksaddr("target.example:443"), Domain: "target.example",
			}, func(err error) { closeErr = err; closeCount++ })
			require.NoError(t, <-done)
			require.NoError(t, writer.Close())
			require.Equal(t, 1, closeCount)
			require.ErrorContains(t, closeErr, "missing-test-dns")
			gets, outstanding := allocator.counts()
			require.Positive(t, gets)
			require.Zero(t, outstanding, "routing failure must return every sniff buffer to its allocator")
		}
	})

	t.Run("UDP", func(t *testing.T) {
		allocator := trackSniffBufferAllocations(t)
		router := newFailingSniffRouter(t, "dns")
		message := new(mDNS.Msg)
		message.SetQuestion("target.example.", mDNS.TypeA)
		payload, err := message.Pack()
		require.NoError(t, err)
		sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, sender.Close()) })
		for range 8 {
			receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = receiver.Close() })
			_, err = sender.WriteTo(payload, receiver.LocalAddr())
			require.NoError(t, err)
			var closeErr error
			closeCount := 0
			router.RoutePacketConnectionEx(context.Background(), bufio.NewPacketConn(receiver), adapter.InboundContext{
				Destination: M.ParseSocksaddr("target.example:53"), Domain: "target.example",
			}, func(err error) { closeErr = err; closeCount++ })
			require.Equal(t, 1, closeCount)
			require.ErrorContains(t, closeErr, "missing-test-dns")
			gets, outstanding := allocator.counts()
			require.Positive(t, gets)
			require.Zero(t, outstanding, "routing failure must return every packet buffer to its allocator")
		}
	})
}
