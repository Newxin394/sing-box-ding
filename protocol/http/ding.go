package http

// This file contains a vendored copy of github.com/sagernet/sing's
// protocol/http.Client, extended with "ding-direct" support.
//
// Why vendored instead of a go.mod replace directive:
//
//	The CONNECT request-line is built inside sing's Client.DialContext and is
//	not reachable from the outside, so the feature cannot be layered on top of
//	the upstream client. Keeping the copy here means this fork stays a single
//	repository and rebases onto upstream sing-box cleanly.
//
// What "ding-direct" does:
//
//	When the outbound carries a "With-At" header, the header is removed and its
//	value is appended to the CONNECT target after an "@":
//
//	    CONNECT api.example.com:443@gw.alicdn.com HTTP/1.1
//	    Host: 153.3.236.22:443
//
//	Proxies that parse the request-line as an authority accept everything
//	before the "@" as userinfo and dial the real target, while middleboxes that
//	read the trailing component see the decoy host instead. Behaviour is
//	byte-identical to the upstream client when the header is absent.
//
// Keep this file in sync with upstream sing when bumping the dependency; the
// only intentional differences are the `ding` field and the three lines that
// use it.

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

// dingHeader is the header that carries the decoy host appended to the CONNECT
// target. It is consumed by newDingClient and never sent on the wire.
const dingHeader = "With-At"

var _ N.Dialer = (*dingClient)(nil)

type dingClient struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
	username   string
	password   string
	host       string
	ding       string
	path       string
	headers    http.Header
}

func newDingClient(options sHTTP.Options, dingHost string) *dingClient {
	client := &dingClient{
		dialer:     options.Dialer,
		serverAddr: options.Server,
		username:   options.Username,
		password:   options.Password,
		path:       options.Path,
		headers:    options.Headers,
		ding:       dingHost,
	}
	if options.Dialer == nil {
		client.dialer = N.SystemDialer
	}
	if client.headers != nil {
		// Clone before stripping: options.Headers is the caller's map (built
		// once in NewOutbound), and Host/With-At are consumed here rather than
		// sent as headers. Mutating it in place would eat With-At for anyone
		// reusing the same map to build a second client.
		client.headers = client.headers.Clone()
		client.host = client.headers.Get("Host")
		client.headers.Del("Host")
		client.headers.Del(dingHeader)
	}
	return client
}

func (c *dingClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (result net.Conn, err error) {
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
	case N.NetworkUDP:
		return nil, os.ErrInvalid
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		handshakeConn := conn
		stopContext := context.AfterFunc(ctx, func() {
			_ = handshakeConn.Close()
		})
		defer func() {
			if !stopContext() {
				result = nil
				err = ctx.Err()
			}
		}()
	}
	request := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if c.host != "" && c.host != destination.Fqdn {
		if c.path != "" {
			_ = conn.Close()
			return nil, E.New("Host header and path are not allowed at the same time")
		}
		request.Host = c.host
		// c.ding is always non-empty here: newDingClient is only reached when
		// the With-At header carried a value. The guard keeps the vendored
		// diff against upstream minimal and stays correct if that changes.
		target := destination.String()
		if c.ding != "" {
			target += "@" + c.ding
		}
		request.URL = &url.URL{Opaque: target}
	} else {
		request.URL = &url.URL{Host: destination.String()}
	}
	if c.path != "" {
		err = sHTTP.URLSetPath(request.URL, c.path)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	for key, valueList := range c.headers {
		request.Header.Set(key, valueList[0])
		for _, value := range valueList[1:] {
			request.Header.Add(key, value)
		}
	}
	if c.username != "" {
		auth := c.username + ":" + c.password
		request.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	err = request.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		if reader.Buffered() > 0 {
			buffer := buf.NewSize(reader.Buffered())
			_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
			if err != nil {
				conn.Close()
				return nil, err
			}
			conn = bufio.NewCachedConn(conn, buffer)
		}
		return conn, nil
	}
	conn.Close()
	switch response.StatusCode {
	case http.StatusProxyAuthRequired:
		return nil, E.New("authentication required")
	case http.StatusMethodNotAllowed:
		return nil, E.New("method not allowed")
	default:
		return nil, E.New("unexpected status: ", response.Status)
	}
}

func (c *dingClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
