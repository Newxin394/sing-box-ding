package group

import (
	"context"
	"net"
	"regexp"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.Referrer              = (*Selector)(nil)
	_ adapter.PreMatchOutboundGroup = (*Selector)(nil)
)

type SelectorUpdateCallback func(selected string)
type SelectorUpdateGuard func(previous string, selected string) error

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	stateAccess                  sync.RWMutex
	providerAccess               sync.Mutex
	callbackAccess               sync.Mutex
	controller                   any
	callbacks                    list.List[SelectorUpdateCallback]
	guards                       list.List[SelectorUpdateGuard]

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

	udpOutboundTag string
	udpFallbackTag string

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	if options.UDPFallbackOutbound != "" && options.UDPOutbound == "" {
		return nil, E.New("udp_fallback_outbound requires udp_outbound in selector: ", tag)
	}
	if options.UDPOutbound == tag {
		return nil, E.New("udp_outbound must not reference itself in selector: ", tag)
	}
	if options.UDPFallbackOutbound == tag {
		return nil, E.New("udp_fallback_outbound must not reference itself in selector: ", tag)
	}
	dependencies := options.Outbounds
	if options.UDPOutbound != "" {
		dependencies = append(slices.Clone(dependencies), options.UDPOutbound)
	}
	if options.UDPFallbackOutbound != "" {
		dependencies = append(dependencies, options.UDPFallbackOutbound)
	}
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, []string{N.NetworkTCP, N.NetworkUDP}, common.Uniq(dependencies)),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		udpOutboundTag: options.UDPOutbound,
		udpFallbackTag: options.UDPFallbackOutbound,

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start() error {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
		}
	}
	tags := slices.Clone(s.Dependencies())
	if len(tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}
	outboundByTag := make(map[string]adapter.Outbound, len(tags))
	for i, tag := range tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outboundByTag[tag] = detour
	}
	if len(tags) == 0 {
		detour, loaded := s.outbound.Outbound("Compatible")
		if !loaded {
			return E.New("fallback outbound not found: Compatible")
		}
		tags = append(tags, detour.Tag())
		outboundByTag[detour.Tag()] = detour
	}
	selected, err := s.outboundSelect(outboundByTag, tags)
	if err != nil {
		return err
	}
	s.stateAccess.Lock()
	s.tags, s.outbounds = tags, outboundByTag
	s.selected.Store(selected)
	s.stateAccess.Unlock()
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	return nil
}

func (s *Selector) Now() string {
	selected := s.selected.Load()
	if selected == nil {
		s.stateAccess.RLock()
		defer s.stateAccess.RUnlock()
		return s.tags[0]
	}
	return selected.Tag()
}

func (s *Selector) All() []string {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	return slices.Clone(s.tags)
}

func (s *Selector) References() []string {
	return []string{s.Now()}
}

func (s *Selector) Selected() adapter.Outbound {
	return s.selected.Load()
}

func (s *Selector) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	return selectOutbound(s.selected.Load())
}

func (s *Selector) SelectOutbound(tag string) bool {
	return s.SelectOutboundContext(tag) == nil
}

func (s *Selector) SelectOutboundContext(tag string) error {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	s.stateAccess.RLock()
	detour, loaded := s.outbounds[tag]
	previous := s.selected.Load()
	s.stateAccess.RUnlock()
	if !loaded {
		return E.New("outbound not found in selector: ", tag)
	}
	if previous == detour {
		return nil
	}
	previousTag := ""
	if previous != nil {
		previousTag = previous.Tag()
	}
	if err := s.runUpdateGuards(previousTag, tag); err != nil {
		return err
	}
	s.selected.Store(detour)
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	s.notifyUpdated(tag)
	return nil
}

func (s *Selector) ClaimController(owner any) error {
	if owner == nil {
		return E.New("nil selector controller")
	}
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	if s.controller != nil && s.controller != owner {
		return E.New("selector already has a controller: ", s.Tag())
	}
	s.controller = owner
	return nil
}
func (s *Selector) ReleaseController(owner any) {
	if owner == nil {
		return
	}
	s.callbackAccess.Lock()
	if s.controller == owner {
		s.controller = nil
	}
	s.callbackAccess.Unlock()
}
func (s *Selector) RegisterUpdateGuard(guard SelectorUpdateGuard) *list.Element[SelectorUpdateGuard] {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	return s.guards.PushBack(guard)
}
func (s *Selector) UnregisterUpdateGuard(element *list.Element[SelectorUpdateGuard]) {
	if element == nil {
		return
	}
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	s.callbackAccess.Lock()
	s.guards.Remove(element)
	s.callbackAccess.Unlock()
}
func (s *Selector) runUpdateGuards(previous string, selected string) error {
	s.callbackAccess.Lock()
	guards := make([]SelectorUpdateGuard, 0, s.guards.Len())
	for element := s.guards.Front(); element != nil; element = element.Next() {
		guards = append(guards, element.Value)
	}
	s.callbackAccess.Unlock()
	for _, guard := range guards {
		if err := guard(previous, selected); err != nil {
			return err
		}
	}
	return nil
}
func (s *Selector) RegisterUpdateCallback(callback SelectorUpdateCallback) *list.Element[SelectorUpdateCallback] {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	return s.callbacks.PushBack(callback)
}
func (s *Selector) UnregisterUpdateCallback(element *list.Element[SelectorUpdateCallback]) {
	if element == nil {
		return
	}
	s.callbackAccess.Lock()
	s.callbacks.Remove(element)
	s.callbackAccess.Unlock()
}
func (s *Selector) notifyUpdated(tag string) {
	s.callbackAccess.Lock()
	callbacks := make([]SelectorUpdateCallback, 0, s.callbacks.Len())
	for element := s.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	s.callbackAccess.Unlock()
	for _, callback := range callbacks {
		callback(tag)
	}
}
func (s *Selector) InterruptConnections(interruptExternalConnections bool) {
	s.interruptGroup.Interrupt(interruptExternalConnections)
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if s.udpOutboundTag != "" {
		if s.outbound == nil {
			return nil, E.New("missing outbound manager for udp_outbound: ", s.udpOutboundTag)
		}
		delegate, loaded := s.outbound.Outbound(s.udpOutboundTag)
		if !loaded {
			return nil, E.New("udp_outbound not found: ", s.udpOutboundTag)
		}
		conn, err := delegate.ListenPacket(ctx, destination)
		if err == nil {
			return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		if s.udpFallbackTag != "" {
			fallback, fallbackLoaded := s.outbound.Outbound(s.udpFallbackTag)
			if !fallbackLoaded {
				return nil, E.Cause(err, "udp_fallback_outbound not found: ", s.udpFallbackTag, "; primary udp_outbound ", s.udpOutboundTag, " failed")
			}
			conn, fallbackErr := fallback.ListenPacket(ctx, destination)
			if fallbackErr == nil {
				s.logger.Debug("udp_outbound ", s.udpOutboundTag, " failed, using fallback ", s.udpFallbackTag, ": ", err)
				return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
			}
			return nil, E.Cause(fallbackErr, "delegate udp_fallback_outbound failed: ", s.udpFallbackTag, "; primary udp_outbound ", s.udpOutboundTag, " failed: ", err)
		}
		return nil, E.Cause(err, "delegate udp_outbound failed: ", s.udpOutboundTag)
	}
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Selector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func RealTag(outboundManager adapter.OutboundManager, detour adapter.Outbound) string {
	tag := detour.Tag()
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return tag
		}
		now := group.Now()
		if now == "" {
			return tag
		}
		tag = now
		var loaded bool
		detour, loaded = outboundManager.Outbound(tag)
		if !loaded {
			return tag
		}
	}
}

func (s *Selector) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	tags, outbounds, outboundsCache, err := collectProviderOutbounds(
		tag,
		s.Dependencies(),
		s.outbound,
		s.providers,
		s.providerTags,
		s.outboundsCache,
		s.exclude,
		s.include,
	)
	if err != nil {
		s.providerAccess.Unlock()
		return E.Cause(err, s.Tag())
	}
	outboundByTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, detour := range outbounds {
		outboundByTag[detour.Tag()] = detour
	}
	s.stateAccess.Lock()
	detour, err := s.outboundSelect(outboundByTag, tags)
	if err != nil {
		s.stateAccess.Unlock()
		s.providerAccess.Unlock()
		return err
	}
	s.tags, s.outbounds, s.outboundsCache = tags, outboundByTag, outboundsCache
	previous := s.selected.Swap(detour)
	s.stateAccess.Unlock()
	s.providerAccess.Unlock()
	if previous != detour {
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
		if s.history != nil {
			s.history.NotifyUpdated()
		}
	}
	return nil
}

func (s *Selector) outboundSelect(outbounds map[string]adapter.Outbound, tags []string) (adapter.Outbound, error) {
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := outbounds[selected]
				if loaded {
					return detour, nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := outbounds[s.defaultTag]
		if !loaded {
			return nil, E.New("default outbound not found: ", s.defaultTag)
		}
		return detour, nil
	}

	return outbounds[tags[0]], nil
}
