package group

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// timeoutProbeOutbound 的探测耗时可控：快到在 timeout 之前返回，慢到一定被砍断。
type timeoutProbeOutbound struct {
	adapter.Outbound
	tag   string
	delay time.Duration
}

func (o *timeoutProbeOutbound) Tag() string { return o.tag }
func (o *timeoutProbeOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *timeoutProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	select {
	case <-time.After(o.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

// 超时被砍断的成员必须清掉旧延时(面板显示为黑)，否则面板一直把上一次的数字
// 当成这次的结果，用户会以为那个节点还能用，实际上连不上。
func TestURLTestOutboundsDropsCutOffMembers(t *testing.T) {
	server := newProbeTarget(t)
	history := urltest.NewHistoryStorage()

	outbounds := make([]adapter.Outbound, 0, 4)
	for index := range 2 {
		outbounds = append(outbounds, &timeoutProbeOutbound{
			tag:   fmt.Sprintf("fast-%d", index),
			delay: 10 * time.Millisecond,
		})
	}
	for index := range 2 {
		outbounds = append(outbounds, &timeoutProbeOutbound{
			tag:   fmt.Sprintf("slow-%d", index),
			delay: 10 * time.Second,
		})
	}
	for _, outbound := range outbounds {
		history.StoreURLTestHistory(outbound.Tag(), &adapter.URLTestHistory{
			Time:  time.Now().Add(-time.Minute),
			Delay: 111,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result := URLTestOutboundsConcurrent(
		ctx, nil, history, log.NewNOPFactory().Logger(), outbounds, server.URL,
	)

	require.Len(t, result, 2, "只有快节点能在 timeout 前测出结果")
	require.NotNil(t, history.LoadURLTestHistory("fast-0"))
	require.NotNil(t, history.LoadURLTestHistory("fast-1"))
	require.Nil(t, history.LoadURLTestHistory("slow-0"), "超时的成员应清空历史")
	require.Nil(t, history.LoadURLTestHistory("slow-1"), "超时的成员应清空历史")
}

// 一个探测都没发出去(例如锁竞争空返回)时不能清历史，否则整组会被误判成黑。
func TestURLTestOutboundsKeepsHistoryWithoutProbes(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("untouched", &adapter.URLTestHistory{
		Time:  time.Now().Add(-time.Minute),
		Delay: 88,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	result := URLTestOutboundsConcurrent(
		ctx, nil, history, log.NewNOPFactory().Logger(), nil, "https://example.com",
	)

	require.Empty(t, result)
	require.NotNil(t, history.LoadURLTestHistory("untouched"))
}
