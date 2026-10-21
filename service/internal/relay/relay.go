package relay

import (
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/buf"
)

// IsHopByHopHeader reports whether the header must not be forwarded by a proxy.
func IsHopByHopHeader(header string) bool {
	switch strings.ToLower(header) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "host":
		return true
	default:
		return false
	}
}

// ParseInt64Header parses a trimmed integer header value, reporting whether it
// was present and valid.
func ParseInt64Header(headers http.Header, headerName string) (int64, bool) {
	headerValue := strings.TrimSpace(headers.Get(headerName))
	if headerValue == "" {
		return 0, false
	}
	parsedValue, parseError := strconv.ParseInt(headerValue, 10, 64)
	if parseError != nil {
		return 0, false
	}
	return parsedValue, true
}

// CopyRequestHeaders copies inbound request headers to the proxy request,
// skipping hop-by-hop headers and Authorization. The returned boolean reports
// whether the request carries an Accept-Encoding header.
func CopyRequestHeaders(proxyRequest *http.Request, source http.Header) {
	for key, values := range source {
		if !IsHopByHopHeader(key) && key != "Authorization" {
			proxyRequest.Header[key] = values
		}
	}
}

// ApplyServiceHeaders overrides proxy request headers with service-level
// configured headers.
func ApplyServiceHeaders(proxyRequest *http.Request, serviceHeaders http.Header) {
	for key, values := range serviceHeaders {
		proxyRequest.Header.Del(key)
		proxyRequest.Header[key] = values
	}
}

// CopyResponseHeaders copies upstream response headers to the client
// response, skipping hop-by-hop headers.
func CopyResponseHeaders(destination http.Header, source http.Header) {
	for key, values := range source {
		if !IsHopByHopHeader(key) {
			destination[key] = values
		}
	}
}

// IsEventStream reports whether the content type is text/event-stream.
func IsEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "text/event-stream"
}

// WriteUntrackedResponse forwards an upstream response body to the client.
// Streaming (text/event-stream) responses are flushed per chunk; other bodies
// are copied directly. It reports whether the response was a stream.
func WriteUntrackedResponse(logger interface {
	Error(args ...any)
}, writer http.ResponseWriter, response *http.Response) {
	if !IsEventStream(response.Header.Get("Content-Type")) {
		_, _ = io.Copy(writer, response.Body)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		logger.Error("streaming not supported")
		return
	}
	buffer := make([]byte, buf.BufferSize)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			_, writeError := writer.Write(buffer[:n])
			if writeError != nil {
				logger.Error("write streaming response: ", writeError)
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}
