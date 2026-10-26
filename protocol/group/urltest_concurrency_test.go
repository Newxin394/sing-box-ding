package group

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

// concurrencyProbeOutbound 记录同时在跑的探测数峰值，用来验证并发上限。
type concurrencyProbeOutbound struct {
	adapter.Outbound
	tag      string
	delay    time.Duration
	inflight *atomic.Int32
	peak     *atomic.Int32
}

func (o *concurrencyProbeOutbound) Tag() string { return o.tag }
func (o *concurrencyProbeOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *concurrencyProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	current := o.inflight.Add(1)
	defer o.inflight.Add(-1)
	for {
		previous := o.peak.Load()
		if current <= previous || o.peak.CompareAndSwap(previous, current) {
			break
		}
	}
	select {
	case <-time.After(o.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func newConcurrencyProbes(count int) ([]adapter.Outbound, *atomic.Int32) {
	inflight := new(atomic.Int32)
	peak := new(atomic.Int32)
	outbounds := make([]adapter.Outbound, 0, count)
	for index := range count {
		outbounds = append(outbounds, &concurrencyProbeOutbound{
			tag:      fmt.Sprintf("leaf-%d", index),
			delay:    80 * time.Millisecond,
			inflight: inflight,
			peak:     peak,
		})
	}
	return outbounds, peak
}

func newProbeTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

// 定时健康检查维持 32 路，避免每轮扫描把手机打满。
func TestURLTestOutboundsKeepsBatchConcurrency(t *testing.T) {
	server := newProbeTarget(t)
	outbounds, peak := newConcurrencyProbes(64)

	result := URLTestOutbounds(
		context.Background(), nil, urltest.NewHistoryStorage(),
		log.NewNOPFactory().Logger(), outbounds, server.URL, time.Hour, true,
	)

	require.Len(t, result, len(outbounds))
	require.LessOrEqual(t, peak.Load(), int32(urlTestBatchConcurrency),
		"默认路径不该超过 urlTestBatchConcurrency")
}

// 面板手动测速受固定 timeout 约束，必须一次全发出去，否则排在后面的节点永远轮不到。
func TestURLTestOutboundsConcurrentFiresAllAtOnce(t *testing.T) {
	server := newProbeTarget(t)
	const members = 64
	outbounds, peak := newConcurrencyProbes(members)

	result := URLTestOutboundsConcurrent(
		context.Background(), nil, urltest.NewHistoryStorage(),
		log.NewNOPFactory().Logger(), outbounds, server.URL,
	)

	require.Len(t, result, len(outbounds))
	require.Equal(t, int32(members), peak.Load(), "并发路径应当把成员一次性全部发出去")
}

// 并发数不能超过上限，否则 400+ 节点的组会把 fd 和 CPU 打爆。
func TestURLTestOutboundsConcurrentCapsConcurrency(t *testing.T) {
	server := newProbeTarget(t)
	outbounds, peak := newConcurrencyProbes(outboundProbeConcurrencyLimit + 32)

	result := URLTestOutboundsConcurrent(
		context.Background(), nil, urltest.NewHistoryStorage(),
		log.NewNOPFactory().Logger(), outbounds, server.URL,
	)

	require.Len(t, result, len(outbounds))
	require.LessOrEqual(t, peak.Load(), int32(outboundProbeConcurrencyLimit))
}
