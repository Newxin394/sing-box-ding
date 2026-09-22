package cns

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TC "github.com/sagernet/sing-box/transport/cns"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultCnsKey  = "Meng"
	defaultCnsFlag = "httpUDP"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.CNSOutboundOptions](registry, C.TypeCns, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx      context.Context
	logger   logger.ContextLogger
	dialer   N.Dialer
	serverddr M.Socksaddr
	key      string
	password string
	flag     string
	headers  map[string]string
	udp      bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CNSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	key := options.Key
	if key == "" {
		key = defaultCnsKey
	}
	flag := options.Flag
	if flag == "" {
		flag = defaultCnsFlag
	}
	headers := make(map[string]string)
	for hk, hv := range options.Headers.Build() {
		if len(hv) > 0 {
			headers[hk] = hv[0]
		}
	}
	networks := []string{N.NetworkTCP}
	if options.UDP {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeCns, tag, networks, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		dialer:    outboundDialer,
		serverddr: options.ServerOptions.Build(),
		key:       key,
		password:  options.Password,
		flag:      flag,
		headers:   headers,
		udp:       options.UDP,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := o.handshake(ctx, destination, false)
		if err != nil {
			return nil, err
		}
		return TC.NewCnsConn(conn, o.password), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !o.udp {
		return nil, os.ErrInvalid
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	conn, err := o.handshake(ctx, destination, true)
	if err != nil {
		return nil, err
	}
	return TC.NewUDPPacketConn(conn, o.password), nil
}

func (o *Outbound) handshake(ctx context.Context, destination M.Socksaddr, udp bool) (net.Conn, error) {
	conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.serverddr)
	if err != nil {
		return nil, E.Cause(err, "connect to CNS server ", o.serverddr)
	}
	request, err := TC.BuildRequest(destination.String(), o.key, o.password, o.flag, o.serverddr.AddrString(), udp, o.headers)
	if err != nil {
		conn.Close()
		return nil, err
	}
	shaked, err := TC.ClientHandshake(conn, request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return shaked, nil
}
