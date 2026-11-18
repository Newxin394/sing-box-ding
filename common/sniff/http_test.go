package sniff_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"

	"github.com/stretchr/testify/require"
)

func TestSniffHTTP1(t *testing.T) {
	t.Parallel()
	pkt := "GET / HTTP/1.1\r\nHost: www.google.com\r\nAccept: */*\r\n\r\n"
	var metadata adapter.InboundContext
	err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, metadata.SniffHost, "www.google.com")
}

func TestSniffHTTP1WithPort(t *testing.T) {
	t.Parallel()
	pkt := "GET / HTTP/1.1\r\nHost: www.gov.cn:8080\r\nAccept: */*\r\n\r\n"
	var metadata adapter.InboundContext
	err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, metadata.SniffHost, "www.gov.cn")
}

func TestHTTPHostPreservesMappedDomainForIPLiteral(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		host      string
		sniffHost string
	}{
		{"192.0.2.1", "192.0.2.1"},
		{"192.0.2.1:8080", "192.0.2.1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
	} {
		t.Run(testCase.host, func(t *testing.T) {
			t.Parallel()
			metadata := adapter.InboundContext{Domain: "mapped.example"}
			request := "GET / HTTP/1.1\r\nHost: " + testCase.host + "\r\n\r\n"
			err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(request))
			require.NoError(t, err)
			require.Equal(t, "mapped.example", metadata.Domain)
			require.Equal(t, testCase.sniffHost, metadata.SniffHost)
			require.Equal(t, "http", metadata.Protocol)
		})
	}
}

func TestHTTPHostStillUsesSniffedDomain(t *testing.T) {
	t.Parallel()
	metadata := adapter.InboundContext{Domain: "mapped.example"}
	request := "GET / HTTP/1.1\r\nHost: actual.example:8080\r\n\r\n"
	err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(request))
	require.NoError(t, err)
	require.Equal(t, "actual.example", metadata.Domain)
	require.Equal(t, "actual.example", metadata.SniffHost)
}
