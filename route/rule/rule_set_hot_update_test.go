package rule_test

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type snapshotHTTPTransport func(*http.Request) (*http.Response, error)

func (t snapshotHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t(request)
}
func (t snapshotHTTPTransport) CloseIdleConnections() {}
func (t snapshotHTTPTransport) Reset()                {}

type snapshotHTTPManager struct{ transport adapter.HTTPTransport }

func (m snapshotHTTPManager) ResolveTransport(context.Context, logger.ContextLogger, option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	return m.transport, nil
}
func (m snapshotHTTPManager) DefaultTransport() adapter.HTTPTransport { return m.transport }
func (m snapshotHTTPManager) ResetNetwork()                           { m.transport.Reset() }

type snapshotTestRouter struct {
	adapter.Router
	set adapter.RuleSet
}

func (r snapshotTestRouter) RuleSet(string) (adapter.RuleSet, bool) { return r.set, true }
func (r snapshotTestRouter) DefaultDomainMatchStrategy() C.DomainMatchStrategy {
	return C.DomainMatchStrategyAsIS
}

func TestRuleSetHotUpdateKeepsOneMatchingGeneration(t *testing.T) {
	const multiple = `{"version":1,"rules":[{"domain":["outer.example"]},{"domain":["other.example"]}]}`
	const single = `{"version":1,"rules":[{"domain":["other.example"]}]}`
	var generation atomic.Uint32
	transport := snapshotHTTPTransport(func(request *http.Request) (*http.Response, error) {
		content := multiple
		if generation.Load()%2 != 0 {
			content = single
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(content)), Request: request}, nil
	})
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.HTTPClientManager](ctx, snapshotHTTPManager{transport})
	set, err := R.NewRemoteRuleSet(ctx, log.NewNOPFactory().Logger(), "live", option.RuleSet{
		Type: C.RuleSetTypeRemote, Format: C.RuleSetFormatSource,
		RemoteOptions: option.RemoteRuleSet{URL: "https://rules.example.test/live.json"},
	})
	require.NoError(t, err)
	defer set.Close()
	start := adapter.NewHTTPStartContext()
	defer start.Close()
	require.NoError(t, set.StartContext(ctx, start))
	service.MustRegister[adapter.Router](ctx, snapshotTestRouter{set: set})
	outer, err := R.NewRule(ctx, log.NewNOPFactory().Logger(), option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Domain: []string{"outer.example"}, RuleSet: []string{"live"}},
			RuleAction:     option.RuleAction{Action: C.RuleActionTypeReject},
		},
	}, false)
	require.NoError(t, err)
	require.NoError(t, outer.Start())
	defer outer.Close()
	for _, version := range []uint32{0, 1} {
		generation.Store(version)
		require.NoError(t, set.Update(ctx))
		require.True(t, outer.Match(&adapter.InboundContext{Domain: "outer.example"}), "each complete generation must match independently")
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	var mismatches atomic.Uint64
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !outer.Match(&adapter.InboundContext{Domain: "outer.example"}) {
					mismatches.Add(1)
				}
				runtime.Gosched()
			}
		})
	}
	for version := range 1000 {
		generation.Store(uint32(version))
		if err = set.Update(ctx); err != nil {
			break
		}
	}
	close(stop)
	readers.Wait()
	require.NoError(t, err)
	require.Zero(t, mismatches.Load(), "one match must not select a strategy from one generation and rules from another")
}

func TestRuleSetCleanupClearsContentMetadataAndCount(t *testing.T) {
	prefix := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	set, err := R.NewLocalRuleSet(context.Background(), log.NewNOPFactory().Logger(), "cleanup", option.RuleSet{
		Type: C.RuleSetTypeInline,
		InlineOptions: option.PlainRuleSet{Rules: []option.HeadlessRule{{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{IPCIDR: []*badoption.Prefixable{&prefix}},
		}}},
	})
	require.NoError(t, err)
	defer set.Close()
	require.Positive(t, set.RuleCount())
	require.True(t, set.Metadata().ContainsIPCIDRRule)
	set.Cleanup()
	require.Zero(t, set.RuleCount())
	require.Equal(t, adapter.RuleSetMetadata{}, set.Metadata())
	require.Empty(t, set.String())
	require.Empty(t, set.ExtractIPSet())
}
