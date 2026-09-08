package http

import (
	"context"
	"net"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HTTPOutboundOptions](registry, C.TypeHTTP, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	logger      logger.ContextLogger
	client      dialClient
	udpOutbound string
	udpDetour   adapter.Outbound
}

// dialClient is the TCP dialing surface shared by the upstream sing HTTP
// client and the ding-direct client in ding.go.
type dialClient interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	detour, err := tls.NewDialerFromOptions(ctx, logger, outboundDialer, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Build()
	clientOptions := sHTTP.Options{
		Dialer:   detour,
		Server:   options.ServerOptions.Build(),
		Username: options.Username,
		Password: options.Password,
		Path:     options.Path,
		Headers:  headers,
	}
	var client dialClient
	if dingHost := headers.Get(dingHeader); dingHost != "" {
		// The With-At header is not a real header: it is consumed here and
		// appended to the CONNECT request target as "host:port@<dingHost>".
		client = newDingClient(clientOptions, dingHost)
	} else {
		client = sHTTP.NewClient(clientOptions)
	}
	networks := []string{N.NetworkTCP}
	if options.UDPOutbound != "" {
		networks = append(networks, N.NetworkUDP)
	}
	return &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypeHTTP, tag, networks, options.DialerOptions),
		ctx:         ctx,
		logger:      logger,
		client:      client,
		udpOutbound: options.UDPOutbound,
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart || h.udpOutbound == "" {
		return nil
	}
	manager := service.FromContext[adapter.OutboundManager](h.ctx)
	if manager == nil {
		return E.New("udp_outbound: missing outbound manager")
	}
	detour, loaded := manager.Outbound(h.udpOutbound)
	if !loaded {
		return E.New("udp_outbound: outbound not found: ", h.udpOutbound)
	}
	if !common.Contains(detour.Network(), N.NetworkUDP) {
		return E.New("udp_outbound: outbound does not support UDP: ", h.udpOutbound)
	}
	h.udpDetour = detour
	return nil
}

func (h *Outbound) Dependencies() []string {
	dependencies := h.Adapter.Dependencies()
	if h.udpOutbound != "" {
		dependencies = append(slices.Clone(dependencies), h.udpOutbound)
	}
	return dependencies
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.udpDetour != nil && N.NetworkName(network) == N.NetworkUDP {
		// UDP-connect mode (used by UDP-over-TCP transports and WireGuard)
		// arrives through DialContext, not ListenPacket; delegate it the same way.
		return h.udpDetour.DialContext(ctx, network, destination)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.udpDetour != nil {
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Destination = destination
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination, " via ", h.udpDetour.Tag())
		return h.udpDetour.ListenPacket(ctx, destination)
	}
	// The adapter advertises TCP only, so reaching this path means a route rule
	// sent UDP at an HTTP outbound. Say so explicitly: the bare os.ErrInvalid
	// ("invalid argument") gives no clue which side is misconfigured.
	return nil, E.New("UDP is not supported by outbound: ", h.Tag())
}
