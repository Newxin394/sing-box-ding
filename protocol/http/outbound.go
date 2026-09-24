package http

import (
	"context"
	"net"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	TLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
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
	ctx            context.Context
	logger         logger.ContextLogger
	client         dialClient
	nativeClient   *transportHTTP.Client
	udpOutbound    string
	udpDetour      adapter.Outbound
	interruptGroup *interrupt.Group
}

type dialClient interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}

type dingOnlyDialClient interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Build()
	var nativeClient *transportHTTP.Client
	var legacyClient dialClient
	if headers.Get(dingHeader) == "" {
		nativeClient, err = transportHTTP.NewClientWithTLS(ctx, logger, outboundDialer, options.ServerOptions, common.PtrValueOrDefault(options.TLS), transportHTTP.ClientOptions{
			Username: options.Username, Password: options.Password, Path: options.Path, Headers: headers,
			Version:                transportHTTP.ResolveVersion(options.Version, options.Path, headers.Get("Host")),
			DisableVersionFallback: options.DisableVersionFallback, HTTP2Options: options.HTTP2Options, HTTP3Options: options.HTTP3Options,
		})
		if err != nil {
			return nil, err
		}
	} else {
		detour, dialErr := TLS.NewDialerFromOptions(ctx, logger, outboundDialer, options.Server, common.PtrValueOrDefault(options.TLS))
		if dialErr != nil {
			return nil, dialErr
		}
		clientOptions := sHTTP.Options{Dialer: detour, Server: options.ServerOptions.Build(), Username: options.Username, Password: options.Password, Path: options.Path, Headers: headers}
		legacyClient = newDingClient(clientOptions, headers.Get(dingHeader))
	}
	client := legacyClient
	if nativeClient != nil {
		client = nativeClient
	}
	networks := []string{N.NetworkTCP}
	if nativeClient != nil || options.UDPOutbound != "" {
		networks = append(networks, N.NetworkUDP)
	}
	return &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHTTP, tag, networks, options.DialerOptions), ctx: ctx, logger: logger, client: client, nativeClient: nativeClient, udpOutbound: options.UDPOutbound, interruptGroup: interrupt.NewGroup()}, nil
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

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.nativeClient != nil {
		h.nativeClient.ResetConnections()
	}
}

func (h *Outbound) Close() error {
	if h.nativeClient != nil {
		return h.nativeClient.Close()
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.udpDetour != nil && N.NetworkName(network) == N.NetworkUDP {
		// UDP-connect mode (used by UDP-over-TCP transports and WireGuard)
		// arrives through DialContext, not ListenPacket; delegate it the same way.
		conn, err := h.udpDetour.DialContext(ctx, network, destination)
		if err != nil {
			return nil, err
		}
		return h.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	if N.NetworkName(network) == N.NetworkUDP && h.nativeClient == nil {
		return nil, E.New("UDP is not supported by outbound: ", h.Tag())
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, network, destination)
	case N.NetworkUDP:
		if h.nativeClient == nil {
			return nil, E.New("UDP is not supported by outbound: ", h.Tag())
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.nativeClient.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.udpDetour != nil {
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Destination = destination
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination, " via ", h.udpDetour.Tag())
		conn, err := h.udpDetour.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return h.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	if h.nativeClient == nil {
		return nil, E.New("UDP is not supported by outbound: ", h.Tag())
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.nativeClient.ListenPacket(ctx, destination)
}
