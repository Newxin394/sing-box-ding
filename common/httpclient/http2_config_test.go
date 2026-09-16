package httpclient

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestHTTPIdleConnectionTimeout(t *testing.T) {
	transport, err := ConfigureHTTP2Transport(option.HTTP2Options{
		KeepAlivePeriod: badoption.Duration(15 * time.Second),
		IdleTimeout:     badoption.Duration(45 * time.Second),
	})
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, transport.IdleConnTimeout)
	clone := CloneHTTP2Transport(transport)
	require.Equal(t, transport.IdleConnTimeout, clone.IdleConnTimeout)
	h1 := newHTTP1Transport(nil, nil, 45*time.Second)
	require.Equal(t, 45*time.Second, h1.transport.IdleConnTimeout)
}
