package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type subscriptionCacheStub struct {
	adapter.CacheFile
	saved *adapter.SavedBinary
}

func (c *subscriptionCacheStub) LoadSubscription(string) *adapter.SavedBinary {
	return c.saved
}

type closeTrackingBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *closeTrackingBody) Close() error {
	b.closed.Add(1)
	return nil
}

type staticRoundTripper struct {
	response *http.Response
}

func (t staticRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return t.response, nil
}

func TestProviderRemoteURLHash(t *testing.T) {
	t.Parallel()

	const providerURL = "https://example.com/provider"
	provider, err := NewProviderRemote(
		context.Background(),
		nil,
		log.NewNOPFactory(),
		"test",
		option.ProviderRemoteOptions{URL: providerURL},
	)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte(providerURL)), provider.(*ProviderRemote).urlHash)
}

func TestProviderRemoteRejectsCacheFromDifferentURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	providerURLHash := sha256.Sum256([]byte("https://example.com/new-provider"))
	provider := &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			ctx,
			nil,
			nil,
			nil,
			logFactory,
			logger,
			"test",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:     ctx,
		logger:  logger,
		urlHash: providerURLHash,
		cacheFile: &subscriptionCacheStub{saved: &adapter.SavedBinary{
			Content: []byte("invalid provider content must not be parsed"),
			URLHash: []byte("different URL hash"),
		}},
	}

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.False(t, loaded)
}

func TestProviderRemoteFetchClosesEveryHTTPResponse(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &closeTrackingBody{Reader: bytes.NewReader(nil)}
			provider := &ProviderRemote{
				ctx:        context.Background(),
				logger:     log.NewNOPFactory().NewLogger("test"),
				url:        "https://example.com/provider",
				userAgent:  "test",
				httpClient: &http.Client{Transport: staticRoundTripper{response: &http.Response{StatusCode: status, Status: http.StatusText(status), Body: body, Header: make(http.Header)}}},
			}
			err := provider.fetch(context.Background(), true)
			if status == http.StatusNotModified {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, int32(1), body.closed.Load())
		})
	}
}

type deadlineTrackingRoundTripper struct {
	deadline    time.Time
	hasDeadline bool
}

func (t *deadlineTrackingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.deadline, t.hasDeadline = request.Context().Deadline()
	return nil, context.DeadlineExceeded
}

func TestProviderRemoteFetchHasBoundedDeadline(t *testing.T) {
	transport := &deadlineTrackingRoundTripper{}
	provider := &ProviderRemote{
		ctx:        context.Background(),
		logger:     log.NewNOPFactory().NewLogger("test"),
		url:        "https://example.com/provider",
		userAgent:  "test",
		httpClient: &http.Client{Transport: transport},
	}
	// Measure from just before fetch so the window covers the timeout anchor
	// (WithTimeout inside fetch) with margin for scheduler jitter. A zero-tolerance
	// upper bound races the elapsed time between time.Now() and the deadline
	// being set — CI showed 30.000001802s > 30s failures.
	started := time.Now()
	require.Error(t, provider.fetch(context.Background(), true))
	require.True(t, transport.hasDeadline)
	remaining := transport.deadline.Sub(started)
	require.Greater(t, remaining, providerFetchTimeout-time.Second)
	require.LessOrEqual(t, remaining, providerFetchTimeout+time.Second)
}

func TestReadProviderContentLimitsResponseSize(t *testing.T) {
	const limit = int64(8)
	testCases := []struct {
		name          string
		contentLength int64
		body          string
		wantError     bool
	}{
		{name: "exact declared size", contentLength: limit, body: "12345678"},
		{name: "oversized declared size", contentLength: limit + 1, wantError: true},
		{name: "oversized chunked body", contentLength: -1, body: "123456789", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			content, err := readProviderContentWithLimit(strings.NewReader(testCase.body), testCase.contentLength, limit)
			if testCase.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte(testCase.body), content)
		})
	}
}
