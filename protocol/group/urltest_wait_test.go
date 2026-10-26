package group

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// TestURLTestOutboundsWaitsForProbes guards the behaviour the Clash API relies
// on: GET /group/{name}/delay must not return before the member probes finish,
// otherwise a dashboard gets an empty map and the latency column never fills in.
func TestURLTestOutboundsWaitsForProbes(t *testing.T) {
	const probeDelay = 150 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(probeDelay)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var outbounds []adapter.Outbound
	for index := range 5 {
		outbounds = append(outbounds, &loadBalanceURLTestOutbound{tag: fmt.Sprintf("leaf-%d", index)})
	}

	start := time.Now()
	result := URLTestOutbounds(
		context.Background(),
		nil,
		urltest.NewHistoryStorage(),
		log.NewNOPFactory().Logger(),
		outbounds,
		server.URL,
		time.Hour,
		true,
	)
	elapsed := time.Since(start)

	require.Len(t, result, len(outbounds), "every member must report a delay")
	require.GreaterOrEqual(t, elapsed, probeDelay, "URLTestOutbounds returned before the probes finished")
}
