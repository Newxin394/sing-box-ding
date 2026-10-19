package group

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestURLTestOutboundsPerNodeTimeoutContinuesBatch(t *testing.T) {
	blocked := &timeoutURLTestOutbound{tag: "blocked", waitForCancel: true}
	following := &timeoutURLTestOutbound{tag: "following"}
	manager := &recursiveURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		blocked.tag:   blocked,
		following.tag: following,
	}}
	history := urltest.NewHistoryStorage()

	startedAt := time.Now()
	result := URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{blocked, following}, "http://example.com", time.Hour, true)
	elapsed := time.Since(startedAt)

	require.Less(t, elapsed, 7*time.Second)
	require.EqualValues(t, 1, blocked.dialCount.Load())
	require.EqualValues(t, 1, following.dialCount.Load())
	require.NotNil(t, history.LoadURLTestHistory(following.tag))
	require.Contains(t, result, following.tag)
}

func TestURLTestOutboundsUsesConfiguredBatchConcurrency(t *testing.T) {
	const count = urlTestBatchConcurrency
	state := &batchConcurrencyProbeState{started: make(chan struct{}, count)}
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound, count)}
	outbounds := make([]adapter.Outbound, 0, count)
	for i := 0; i < count; i++ {
		outbound := &batchConcurrencyProbeOutbound{state: state, tag: fmt.Sprintf("probe-%d", i)}
		manager.outbounds[outbound.tag] = outbound
		outbounds = append(outbounds, outbound)
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		URLTestOutbounds(ctx, manager, urltest.NewHistoryStorage(), log.NewNOPFactory().Logger(), outbounds, "http://example.com", time.Hour, true)
		close(finished)
	}()

	for i := 0; i < count; i++ {
		select {
		case <-state.started:
		case <-time.After(2 * time.Second):
			cancel()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("batch did not stop after cancellation")
			}
			t.Fatalf("only %d of %d probes started", i, count)
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not stop after cancellation")
	}
	require.EqualValues(t, count, state.maxActive.Load())
}

type batchConcurrencyProbeState struct {
	started   chan struct{}
	active    atomic.Int32
	maxActive atomic.Int32
}

type batchConcurrencyProbeOutbound struct {
	adapter.Outbound
	state *batchConcurrencyProbeState
	tag   string
}

func (o *batchConcurrencyProbeOutbound) Tag() string { return o.tag }

func (o *batchConcurrencyProbeOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *batchConcurrencyProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	active := o.state.active.Add(1)
	for {
		maxActive := o.state.maxActive.Load()
		if active <= maxActive || o.state.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	o.state.started <- struct{}{}
	<-ctx.Done()
	o.state.active.Add(-1)
	return nil, ctx.Err()
}

type timeoutURLTestOutbound struct {
	adapter.Outbound
	tag           string
	waitForCancel bool
	dialCount     atomic.Int32
}

func (o *timeoutURLTestOutbound) Tag() string { return o.tag }

func (o *timeoutURLTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *timeoutURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCount.Add(1)
	if o.waitForCancel {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
	}()
	return client, nil
}
