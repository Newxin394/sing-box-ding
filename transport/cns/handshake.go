package cns

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

// BuildRequest builds the CNS CONNECT handshake header. target is the real
// destination "host:port" (may be IPv4 / IPv6 / domain). key is the header
// name carrying the encrypted target (default "Meng"), password is the XOR
// key, flag is the UDP-over-TCP marker line (only written when udp is true),
// server is the camouflage Host value, and headers are extra camouflage
// headers (which may override Host).
func BuildRequest(target, key, password, flag, server string, udp bool, headers map[string]string) (string, error) {
	encodedTarget := EncryptHost(target, password)

	var builder strings.Builder
	builder.Grow(160 + len(encodedTarget))
	builder.WriteString("CONNECT / HTTP/1.1\r\n")
	// The CNS server selects the first occurrence of the key header, so keep
	// the target-bearing field before camouflage headers (notably when
	// key == "Host").
	builder.WriteString(key)
	builder.WriteString(": ")
	builder.WriteString(encodedTarget)
	builder.WriteString("\r\n")
	if udp {
		builder.WriteString(flag)
		builder.WriteString("\r\n")
	}

	merged := make(map[string]string, len(headers)+3)
	merged["Host"] = server
	merged["DNT"] = "1"
	merged["Connection"] = "keep-alive"
	for hk, hv := range headers {
		if strings.ContainsAny(hk, "\r\n") || strings.ContainsAny(hv, "\r\n") {
			return "", fmt.Errorf("invalid CNS header %q", hk)
		}
		for existing := range merged {
			if strings.EqualFold(existing, hk) {
				delete(merged, existing)
			}
		}
		merged[hk] = hv
	}

	keys := make([]string, 0, len(merged))
	for hk := range merged {
		keys = append(keys, hk)
	}
	sort.Strings(keys)
	for _, hk := range keys {
		builder.WriteString(hk)
		builder.WriteString(": ")
		builder.WriteString(merged[hk])
		builder.WriteString("\r\n")
	}

	builder.WriteString("\r\n")
	return builder.String(), nil
}

// ClientHandshake writes the CNS request and reads back the CONNECT response.
// On success it returns a buffered conn positioned right after the response
// headers (any server-buffered payload is preserved by the bufio reader).
func ClientHandshake(conn net.Conn, request string) (net.Conn, error) {
	if err := writeFull(conn, []byte(request)); err != nil {
		return nil, fmt.Errorf("write CNS handshake: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("read CNS handshake: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CNS handshake rejected: %s", response.Status)
	}
	if response.Body != nil {
		response.Body.Close()
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// bufferedConn wraps a conn so buffered bytes read during the handshake
// response are still available to subsequent Read calls.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
