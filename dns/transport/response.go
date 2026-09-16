package transport

import (
	"io"

	E "github.com/sagernet/sing/common/exceptions"
)

// maxDNSMessageSize is the largest DNS wire message that can be represented
// by the standard 16-bit DNS length field. Limit HTTP DNS responses to this
// size as well: a malicious or broken DoH endpoint must not be able to turn a
// single query into an unbounded heap allocation.
const maxDNSMessageSize = 65535

// ReadDNSMessage reads one HTTP DNS response while enforcing the DNS wire-size limit.
func ReadDNSMessage(reader io.Reader, contentLength int64) ([]byte, error) {
	if contentLength > maxDNSMessageSize {
		return nil, E.New("DNS response too large: ", contentLength, " bytes")
	}
	limitedReader := io.LimitReader(reader, maxDNSMessageSize+1)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if len(content) > maxDNSMessageSize {
		return nil, E.New("DNS response too large")
	}
	return content, nil
}
