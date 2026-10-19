package group

import (
	"context"
	"io"
	"maps"
	"net"
	"regexp"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	groupAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *groupAdapter.Registry) {
	groupAdapter.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.PreMatchOutboundGroup   = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
	_ adapter.Referrer                = (*URLTest)(nil)
)

type healthCheckLimiter interface {
	Acquire(ctx context.Context) error
	Release()
}

type semaphoreHealthCheckLimiter struct {
	semaphore chan struct{}
}

func ContextWithHealthCheckConcurrency(ctx context.Context, limit int) context.Context {
	if limit <= 0 {
		return ctx
	}
	return service.ContextWith[healthCheckLimiter](ctx, &semaphoreHealthCheckLimiter{
		semaphore: make(chan struct{}, limit),
	})
}

func (l *semaphoreHealthCheckLimiter) Acquire(ctx context.Context) error {
	select {
	case l.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *semaphoreHealthCheckLimiter) Release() {
	<-l.semaphore
}

type URLTest struct {
	groupAdapter.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	fallback                     URLTestFallback
	udpOutboundTag               string
	udpFallbackTag               string
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
	providerAccess               sync.Mutex
	providerUpdateCheck          providerUpdateCheckScheduler

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
}

type URLTestFallback struct {
	enabled  bool
	maxDelay uint16
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      groupAdapter.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	if options.Fallback.Enabled {
		outbound.fallback = URLTestFallback{
			enabled:  true,
			maxDelay: uint16(time.Duration(options.Fallback.MaxDelay).Milliseconds()),
		}
	}
	if options.UDPFallbackOutbound != "" && options.UDPOutbound == "" {
		return nil, E.New("udp_fallback_outbound requires udp_outbound in urltest: ", tag)
	}
	if options.UDPOutbound == tag {
		return nil, E.New("udp_outbound must not reference itself in urltest: ", tag)
	}
	if options.UDPFallbackOutbound == tag {
		return nil, E.New("udp_fallback_outbound must not reference itself in urltest: ", tag)
	}
	if options.UDPOutbound != "" || options.UDPFallbackOutbound != "" {
		dependencies := append(slices.Clone(options.Outbounds), options.UDPOutbound, options.UDPFallbackOutbound)
		outbound.Adapter = groupAdapter.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, common.Uniq(dependencies))
	}
	outbound.udpOutboundTag = options.UDPOutbound
	outbound.udpFallbackTag = options.UDPFallbackOutbound
	return outbound, nil
}

func (s *URLTest) Start() error {
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
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	if len(s.tags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		s.tags = append(s.tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.fallback, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	s.group = group
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) nowTag() string {
	selectedOutboundTCP := s.group.selectedOutboundTCP.Load()
	if selectedOutboundTCP != nil {
		return selectedOutboundTCP.Tag()
	}
	selectedOutboundUDP := s.group.selectedOutboundUDP.Load()
	if selectedOutboundUDP != nil {
		return selectedOutboundUDP.Tag()
	}
	return ""
}

// Selected implements adapter.OutboundGroup, resolving the best member for the
// requested network. Falls back to the group's own Select() (which may run a
// fresh pick) when no member has been latched yet.
func (s *URLTest) Selected(network string) adapter.Outbound {
	var outbound adapter.Outbound
	if network == N.NetworkUDP {
		outbound = s.group.selectedOutboundUDP.Load()
	} else {
		outbound = s.group.selectedOutboundTCP.Load()
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	return outbound
}

// AttachConnection registers a raw connection with the group's interrupt group
// so a urltest re-pick tears down in-flight traffic, including nested chains.
func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true, false)
}

func (s *URLTest) All() []string {
	outbounds := s.group.loadOutbounds()
	tags := make([]string, 0, len(outbounds))
	for _, detour := range outbounds {
		tags = append(tags, detour.Tag())
	}
	return tags
}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	var references []string
	selectedOutboundTCP := group.selectedOutboundTCP.Load()
	selectedOutboundUDP := group.selectedOutboundUDP.Load()
	if selectedOutboundTCP != nil {
		references = append(references, selectedOutboundTCP.Tag())
	}
	if selectedOutboundUDP != nil && selectedOutboundUDP != selectedOutboundTCP {
		references = append(references, selectedOutboundUDP.Tag())
	}
	return references
}

func (s *URLTest) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	s.group.Touch()
	network := metadata.Network
	if network == N.NetworkICMP {
		network = N.NetworkTCP
	}
	var selectedOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		selectedOutbound = s.group.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		selectedOutbound = s.group.selectedOutboundUDP.Load()
	}
	if selectedOutbound == nil {
		selectedOutbound, _ = s.group.Select(network)
	}
	return selectOutbound(selectedOutbound)
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	return s.group.urlTest(ctx, force)
}

func (s *URLTest) urlTestWithPolicy(ctx context.Context, force bool, policy *urlTestProbePolicy) (map[string]uint16, error) {
	return s.group.urlTestWithPolicy(ctx, force, policy)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(s.ctx, true)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		s.networkChanged()
	}()
}

func (s *URLTest) networkChanged() {
	if s.group == nil || s.group.pause.IsDevicePaused() || s.group.pause.IsNetworkPaused() {
		return
	}
	s.group.networkChanged()
}

func (s *URLTest) isGroupActive() bool {
	if !s.group.started.Load() {
		return false
	}
	return time.Since(s.group.lastActive.Load()) <= s.group.idleTimeout
}

func (g *URLTestGroup) reportDialFailure(outbound adapter.Outbound, network string) {
	if outbound == nil || g == nil {
		return
	}
	tag := RealTag(outbound, network)
	if tag == "" || !g.dialFailures.failure(tag, g.interval) {
		return
	}
	forceTags := map[string]struct{}{tag: {}}
	if outbound.Tag() != tag {
		forceTags[outbound.Tag()] = struct{}{}
	}
	policy := &urlTestProbePolicy{
		forceTags:       forceTags,
		onlyForced:      true,
		preserveHistory: true,
		onResult:        g.health.record,
	}
	go func() {
		defer g.dialFailures.release()
		g.checkOutboundsPolicy(g.ctx, policy)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = s.group.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		outbound = s.group.selectedOutboundUDP.Load()
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.dialFailures.success(RealTag(outbound, network))
		adapter.RecordGroupDial(ctx, s.Tag(), outbound)
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	if ctx.Err() == nil {
		s.group.reportDialFailure(outbound, network)
	}
	s.logger.ErrorContext(ctx, err)
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
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
			s.group.dialFailures.success(RealTag(delegate, N.NetworkUDP))
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		if ctx.Err() == nil {
			s.group.reportDialFailure(delegate, N.NetworkUDP)
		}
		if s.udpFallbackTag != "" {
			fallback, fallbackLoaded := s.outbound.Outbound(s.udpFallbackTag)
			if !fallbackLoaded {
				return nil, E.Cause(err, "udp_fallback_outbound not found: ", s.udpFallbackTag, "; primary udp_outbound ", s.udpOutboundTag, " failed")
			}
			conn, fallbackErr := fallback.ListenPacket(ctx, destination)
			if fallbackErr == nil {
				s.logger.DebugContext(ctx, "udp_outbound ", s.udpOutboundTag, " failed, using fallback ", s.udpFallbackTag, ": ", err)
				return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
			}
			return nil, E.Cause(fallbackErr, "delegate udp_fallback_outbound failed: ", s.udpFallbackTag, "; primary udp_outbound ", s.udpOutboundTag, " failed: ", err)
		}
		return nil, E.Cause(err, "delegate udp_outbound failed: ", s.udpOutboundTag)
	}
	s.group.Touch()
	outbound := s.group.selectedOutboundUDP.Load()
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.dialFailures.success(RealTag(outbound, N.NetworkUDP))
		adapter.RecordGroupDial(ctx, s.Tag(), outbound)
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	if ctx.Err() == nil {
		s.group.reportDialFailure(outbound, N.NetworkUDP)
	}
	s.logger.ErrorContext(ctx, err)
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	_, outbounds, outboundsCache, err := collectProviderOutbounds(
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
	s.outboundsCache = outboundsCache
	s.group.replaceOutbounds(outbounds)
	s.providerAccess.Unlock()
	if s.isGroupActive() {
		s.group.access.Lock()
		if s.group.ticker != nil {
			s.group.ticker.Reset(s.group.interval)
		}
		s.group.access.Unlock()
		s.providerUpdateCheck.Schedule(func() {
			_, _ = s.group.urlTestWait(s.ctx, false)
		})
	}
	return nil
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	outboundsAccess              sync.RWMutex
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     sync.Mutex
	selectedOutboundTCP          common.TypedValue[adapter.Outbound]
	selectedOutboundUDP          common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      atomic.Bool
	lastActive                   common.TypedValue[time.Time]
	healthCheckLimiter           healthCheckLimiter
	health                       urlTestHealthState
	dialFailures                 urlTestDialFailures

	fallback URLTestFallback
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, fallback URLTestFallback, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	group := &URLTestGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		fallback:                     fallback,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		healthCheckLimiter:           service.FromContext[healthCheckLimiter](ctx),
	}
	group.storeOutbounds(outbounds)
	return group, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
}

func (g *URLTestGroup) Touch() {
	if !g.started.Load() {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	var minDelay uint16
	var minOutbound adapter.Outbound
	var selectedOutbound adapter.Outbound
	var fallbackIgnoreOutboundDelay uint16
	var fallbackIgnoreOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		selectedOutbound = g.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		selectedOutbound = g.selectedOutboundUDP.Load()
	}
	if selectedOutbound != nil && common.Contains(selectedOutbound.Network(), network) && !g.memberExcessive(selectedOutbound, network) {
		history := g.history.LoadURLTestHistory(RealTag(selectedOutbound, network))
		if history == nil {
			return selectedOutbound, false
		}
		minOutbound = selectedOutbound
		minDelay = history.Delay
	}
	outbounds := g.loadOutbounds()
	for _, detour := range outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		if detour != selectedOutbound && g.memberExcessive(detour, network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if g.fallback.enabled && g.fallback.maxDelay > 0 && history.Delay > g.fallback.maxDelay {
			if fallbackIgnoreOutboundDelay == 0 || history.Delay < fallbackIgnoreOutboundDelay {
				fallbackIgnoreOutboundDelay = history.Delay
				fallbackIgnoreOutbound = detour
			}
			continue
		}
		if g.fallback.enabled {
			minDelay = history.Delay
			minOutbound = detour
			if minDelay == 0 {
				continue
			} else {
				break
			}
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil && fallbackIgnoreOutbound != nil {
		return fallbackIgnoreOutbound, true
	}
	if minOutbound == nil && selectedOutbound != nil && containsOutbound(outbounds, selectedOutbound) && !g.memberExcessive(selectedOutbound, network) {
		return selectedOutbound, false
	}
	if minOutbound == nil {
		for _, detour := range outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	return g.urlTestWithPolicy(ctx, force, nil)
}

func (g *URLTestGroup) urlTestWithPolicy(ctx context.Context, force bool, policy *urlTestProbePolicy) (map[string]uint16, error) {
	if !g.checking.TryLock() {
		return make(map[string]uint16), nil
	}
	defer g.checking.Unlock()
	if policy == nil && !force {
		policy = g.scheduledProbePolicy()
	}
	return g.urlTestLockedPolicy(ctx, force, policy)
}

func (g *URLTestGroup) urlTestWait(ctx context.Context, force bool) (map[string]uint16, error) {
	g.checking.Lock()
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *URLTestGroup) checkOutboundsPolicy(ctx context.Context, policy *urlTestProbePolicy) {
	g.checking.Lock()
	defer g.checking.Unlock()
	_, _ = g.urlTestLockedPolicy(ctx, false, policy)
}

func (g *URLTestGroup) networkChanged() {
	g.health.forgiveFailures()
	g.dialFailures.reset()
	forceTags := g.hotTags()
	if len(forceTags) == 0 || !g.health.allowNetworkProbe(time.Now()) {
		return
	}
	policy := &urlTestProbePolicy{
		forceTags:       forceTags,
		onlyForced:      true,
		networkChanged:  true,
		preserveHistory: true,
		onResult:        g.health.record,
	}
	g.checkOutboundsPolicy(g.ctx, policy)
}

func (g *URLTestGroup) scheduledProbePolicy() *urlTestProbePolicy {
	return &urlTestProbePolicy{
		preserveHistory: true,
		onResult:        g.health.record,
		shouldProbe: func(tag string, history *adapter.URLTestHistory, now time.Time) bool {
			health := g.health.get(tag)
			lastProbe := health.lastProbe
			if history != nil && history.Time.After(lastProbe) {
				lastProbe = history.Time
			}
			if lastProbe.IsZero() {
				return true
			}
			period := g.interval
			if _, hot := g.hotTags()[tag]; !hot {
				period = urlTestColdRefreshIntervals * g.interval
				if health.failures > 0 {
					period = health.backoff(g.interval)
				}
			}
			return now.Sub(lastProbe) >= period-g.interval/2
		},
	}
}

func (g *URLTestGroup) memberExcessive(outbound adapter.Outbound, network string) bool {
	if outbound == nil {
		return false
	}
	tag := RealTag(outbound, network)
	selected := outbound == g.selectedOutboundTCP.Load() || outbound == g.selectedOutboundUDP.Load()
	if selected {
		return g.dialFailures.excessive(tag)
	}
	return g.health.excessive(tag) || g.dialFailures.excessive(tag)
}

func (g *URLTestGroup) hotTags() map[string]struct{} {
	hot := make(map[string]struct{}, urlTestHotCandidates+2)
	for _, selected := range []adapter.Outbound{g.selectedOutboundTCP.Load(), g.selectedOutboundUDP.Load()} {
		if selected != nil {
			hot[selected.Tag()] = struct{}{}
			hot[RealTag(selected, N.NetworkTCP)] = struct{}{}
			hot[RealTag(selected, N.NetworkUDP)] = struct{}{}
		}
	}
	outbounds := g.loadOutbounds()
	type candidate struct {
		tag   string
		delay uint16
	}
	candidates := make([]candidate, 0, len(outbounds))
	for _, outbound := range outbounds {
		if history := g.history.LoadURLTestHistory(RealTag(outbound, N.NetworkTCP)); history != nil {
			candidates = append(candidates, candidate{outbound.Tag(), history.Delay})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].delay < candidates[j].delay })
	for _, candidate := range candidates[:min(len(candidates), urlTestHotCandidates)] {
		hot[candidate.tag] = struct{}{}
		if outbound, loaded := g.outbound.Outbound(candidate.tag); loaded {
			hot[RealTag(outbound, N.NetworkTCP)] = struct{}{}
			hot[RealTag(outbound, N.NetworkUDP)] = struct{}{}
		}
	}
	return hot
}

func (g *URLTestGroup) urlTestLocked(ctx context.Context, force bool) (map[string]uint16, error) {
	var policy *urlTestProbePolicy
	if !force {
		policy = g.scheduledProbePolicy()
	}
	return g.urlTestLockedPolicy(ctx, force, policy)
}

func (g *URLTestGroup) urlTestLockedPolicy(ctx context.Context, force bool, policy *urlTestProbePolicy) (map[string]uint16, error) {
	result := URLTestOutboundsWithPolicy(ctx, g.outbound, g.history, g.logger, g.loadOutbounds(), g.link, g.interval, force, policy)
	select {
	case <-ctx.Done():
	default:
		g.performUpdateCheck()
	}
	return result, nil
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestSessionKey struct {
	tag  string
	link string
}

type urlTestSessionCall struct {
	done   chan struct{}
	result urlTestResult
}

type urlTestSession struct {
	access sync.Mutex
	calls  map[urlTestSessionKey]*urlTestSessionCall
}

type urlTestSessionContextKey struct{}

type recursiveURLTestGroup interface {
	adapter.OutboundGroup
	urlTest(ctx context.Context, force bool) (map[string]uint16, error)
}

type networkChangedURLTestGroup interface {
	networkChanged()
}

type policyURLTestGroup interface {
	urlTestWithPolicy(ctx context.Context, force bool, policy *urlTestProbePolicy) (map[string]uint16, error)
}

func urlTestSessionFromContext(ctx context.Context) (context.Context, *urlTestSession) {
	if session, loaded := ctx.Value(urlTestSessionContextKey{}).(*urlTestSession); loaded {
		return ctx, session
	}
	session := &urlTestSession{calls: make(map[urlTestSessionKey]*urlTestSessionCall)}
	return context.WithValue(ctx, urlTestSessionContextKey{}, session), session
}

func (s *urlTestSession) test(ctx context.Context, key urlTestSessionKey, test func() urlTestResult) (result urlTestResult) {
	s.access.Lock()
	call, loaded := s.calls[key]
	if !loaded {
		call = &urlTestSessionCall{done: make(chan struct{})}
		s.calls[key] = call
	}
	s.access.Unlock()
	if loaded {
		select {
		case <-call.done:
			return call.result
		case <-ctx.Done():
			return urlTestResult{err: ctx.Err()}
		}
	}
	defer func() {
		call.result = result
		close(call.done)
	}()
	return test()
}

type urlTestBatch struct {
	ctx                context.Context
	outbound           adapter.OutboundManager
	history            *urltest.HistoryStorage
	logger             log.Logger
	session            *urlTestSession
	batch              *batch.Batch[any]
	healthCheckLimiter healthCheckLimiter
	checked            map[string]bool
	groups             []adapter.OutboundGroup
	access             sync.Mutex
	result             map[string]uint16
	policy             *urlTestProbePolicy
}

const urlTestBatchConcurrency = 32

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	return URLTestOutboundsWithPolicy(ctx, outboundManager, history, logger, outbounds, link, interval, force, nil)
}

func URLTestOutboundsWithPolicy(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, policy *urlTestProbePolicy) map[string]uint16 {
	ctx, session := urlTestSessionFromContext(ctx)
	limiter := service.FromContext[healthCheckLimiter](ctx)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](urlTestBatchConcurrency))
	testBatch := &urlTestBatch{
		ctx:                ctx,
		outbound:           outboundManager,
		history:            history,
		logger:             logger,
		session:            session,
		batch:              b,
		healthCheckLimiter: limiter,
		checked:            make(map[string]bool),
		result:             make(map[string]uint16),
		policy:             policy,
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		historyTag := RealTag(outboundGroup, N.NetworkTCP)
		if outboundGroup.Type() == C.TypeLoadBalance {
			historyTag = outboundGroup.Tag()
		}
		groupHistory := history.LoadURLTestHistory(historyTag)
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case recursiveURLTestGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				if b.policy != nil && b.policy.onlyForced {
					forced := b.policy.force(tag) || b.policy.force(RealTag(nested, N.NetworkTCP)) || b.policy.force(RealTag(nested, N.NetworkUDP))
					if !forced {
						return nil, nil
					}
					if b.policy.networkChanged {
						if networkGroup, loaded := nested.(networkChangedURLTestGroup); loaded {
							networkGroup.networkChanged()
							return nil, nil
						}
					}
				}
				var nestedResult map[string]uint16
				if policyGroup, loaded := nested.(policyURLTestGroup); loaded && b.policy != nil {
					nestedResult, _ = policyGroup.urlTestWithPolicy(b.ctx, force, b.policy)
				} else {
					nestedResult, _ = nested.urlTest(b.ctx, force)
				}
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			forced := b.policy != nil && b.policy.force(tag)
			if b.policy != nil && b.policy.onlyForced && !forced {
				continue
			}
			if !force && !forced && b.policy != nil && !b.policy.allow(tag, history, time.Now()) {
				continue
			}
			if !force && !forced && b.policy == nil && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				if b.healthCheckLimiter != nil {
					if err := b.healthCheckLimiter.Acquire(b.ctx); err != nil {
						b.logger.Debug("outbound ", tag, " health check canceled while waiting: ", err)
						return nil, nil
					}
					defer b.healthCheckLimiter.Release()
				}
				testResult := b.session.test(b.ctx, urlTestSessionKey{tag: tag, link: link}, func() urlTestResult {
					testCtx, cancel := context.WithTimeout(b.ctx, C.TCPConnectTimeout)
					defer cancel()
					testChan := make(chan urlTestResult, 1)
					go func() {
						delay, testErr := urltest.URLTest(testCtx, link, detour)
						testChan <- urlTestResult{delay, testErr}
					}()
					select {
					case testResult := <-testChan:
						return testResult
					case <-testCtx.Done():
						return urlTestResult{err: testCtx.Err()}
					}
				})
				if b.ctx.Err() != nil {
					return nil, nil
				}
				resultTime := time.Now()
				if testResult.err != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					if b.policy != nil && b.policy.onResult != nil {
						b.policy.onResult(tag, false, resultTime)
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					if b.policy == nil || !b.policy.preserveHistory {
						b.history.DeleteURLTestHistory(tag)
					}
				} else {
					if b.policy != nil && b.policy.onResult != nil {
						b.policy.onResult(tag, true, resultTime)
					}
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  resultTime,
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	var (
		updated  bool
		selected bool
	)
	selectedOutboundTCP := g.selectedOutboundTCP.Load()
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (selectedOutboundTCP == nil || (exists && outbound != selectedOutboundTCP)) {
		if selectedOutboundTCP != nil {
			updated = true
		}
		g.selectedOutboundTCP.Store(outbound)
		selected = true
	}
	selectedOutboundUDP := g.selectedOutboundUDP.Load()
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (selectedOutboundUDP == nil || (exists && outbound != selectedOutboundUDP)) {
		if selectedOutboundUDP != nil {
			updated = true
		}
		g.selectedOutboundUDP.Store(outbound)
		selected = true
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
}

func (g *URLTestGroup) loadOutbounds() []adapter.Outbound {
	g.outboundsAccess.RLock()
	defer g.outboundsAccess.RUnlock()
	return g.outbounds
}

func (g *URLTestGroup) storeOutbounds(outbounds []adapter.Outbound) {
	g.outboundsAccess.Lock()
	g.outbounds = outbounds
	g.outboundsAccess.Unlock()
}

func (g *URLTestGroup) replaceOutbounds(outbounds []adapter.Outbound) {
	g.updateAccess.Lock()
	selectedOutboundTCP := g.selectedOutboundTCP.Load()
	selectedOutboundUDP := g.selectedOutboundUDP.Load()
	g.storeOutbounds(outbounds)
	if !containsOutbound(outbounds, selectedOutboundTCP) {
		g.selectedOutboundTCP.Store(nil)
	}
	if !containsOutbound(outbounds, selectedOutboundUDP) {
		g.selectedOutboundUDP.Store(nil)
	}
	if g.selectedOutboundTCP.Load() == nil {
		if outbound, _ := g.Select(N.NetworkTCP); outbound != nil {
			g.selectedOutboundTCP.Store(outbound)
		}
	}
	if g.selectedOutboundUDP.Load() == nil {
		if outbound, _ := g.Select(N.NetworkUDP); outbound != nil {
			g.selectedOutboundUDP.Store(outbound)
		}
	}
	updated := (selectedOutboundTCP != nil && g.selectedOutboundTCP.Load() != selectedOutboundTCP) ||
		(selectedOutboundUDP != nil && g.selectedOutboundUDP.Load() != selectedOutboundUDP)
	selected := g.selectedOutboundTCP.Load() != selectedOutboundTCP || g.selectedOutboundUDP.Load() != selectedOutboundUDP
	g.updateAccess.Unlock()
	if updated && g.interruptExternalConnections {
		g.interruptGroup.Interrupt(true)
	}
	if selected && g.history != nil {
		g.history.NotifyUpdated()
	}
}

func containsOutbound(outbounds []adapter.Outbound, selected adapter.Outbound) bool {
	if selected == nil {
		return true
	}
	return slices.Contains(outbounds, selected)
}
