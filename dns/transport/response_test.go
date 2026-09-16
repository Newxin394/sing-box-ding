package transport

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadDNSMessageLimitsResponseSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contentLength int64
		bodySize      int
		wantError     bool
	}{
		{name: "maximum declared size", contentLength: maxDNSMessageSize, bodySize: maxDNSMessageSize},
		{name: "oversized declared size", contentLength: maxDNSMessageSize + 1, bodySize: 0, wantError: true},
		{name: "oversized chunked body", contentLength: -1, bodySize: maxDNSMessageSize + 1, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content, err := ReadDNSMessage(bytes.NewReader(make([]byte, test.bodySize)), test.contentLength)
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, content, test.bodySize)
		})
	}
}
