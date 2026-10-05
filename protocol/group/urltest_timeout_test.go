package group

import (
	"context"
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
