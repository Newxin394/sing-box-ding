//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

func (i *Inbound) startBypassSelector() error {
	o := i.bypassSelectorOptions
	if o == nil {
		return nil
	}
	m := service.FromContext[adapter.OutboundManager](i.ctx)
	// Resolve every watched selector. normalizeBypassSelector guarantees Tags
	// is the canonical, de-duplicated list (legacy `tag` already merged in).
	selectors := make([]*group.Selector, 0, len(o.Tags))
	for _, tag := range o.Tags {
		ob, ok := m.Outbound(tag)
		if !ok {
			return E.New("local.bypass_selector selector not found: ", tag)
		}
		s, ok := ob.(*group.Selector)
		if !ok {
			return E.New("local.bypass_selector outbound is not a selector: ", tag)
		}
		selectors = append(selectors, s)
	}
	directWildcard := common.Contains(o.BypassWhen, option.EBPFBypassSelectorDirectWildcard)
	if directWildcard {
		// The wildcard requires EVERY watched selector to actually contain at
		// least one direct member; otherwise the wildcard can never match for
		// that selector and the configuration is likely a mistake.
		for _, s := range selectors {
			hasDirect := false
			for _, tag := range s.All() {
				member, ok := m.Outbound(tag)
				if ok && member.Type() == C.TypeDirect {
					hasDirect = true
					break
				}
			}
			if !hasDirect {
				return E.New("local.bypass_selector.bypass_when direct wildcard \"", option.EBPFBypassSelectorDirectWildcard, "\" requires selector to contain at least one direct outbound: ", s.Tag())
			}
		}
	}
	for _, tag := range o.BypassWhen {
		if tag == option.EBPFBypassSelectorDirectWildcard {
			// The wildcard keyword may double as a real direct outbound tag
			// (e.g. an outbound literally named "直连"). If such an outbound
			// exists it must be a direct one; if it does not exist the keyword
			// is treated purely as the wildcard, which is already validated
			// above, so skip the strict per-tag membership check here.
			if member, ok := m.Outbound(tag); ok && member.Type() != C.TypeDirect {
				return E.New("local.bypass_selector.bypass_when must be a direct outbound: ", tag)
			}
			continue
		}
		// Non-wildcard explicit tags: must be a direct outbound and must be a
		// member of at least one watched selector.
		member, ok := m.Outbound(tag)
		if !ok {
			return E.New("local.bypass_selector.bypass_when outbound not found: ", tag)
		}
		if member.Type() != C.TypeDirect {
			return E.New("local.bypass_selector.bypass_when must be a direct outbound: ", tag)
		}
		inAny := false
		for _, s := range selectors {
			if common.Contains(s.All(), tag) {
				inAny = true
				break
			}
		}
		if !inAny {
			return E.New("local.bypass_selector.bypass_when outbound not found in any watched selector: ", tag)
		}
	}
	i.bypassSelectorDirectWild = directWildcard
	// Claim every selector for this inbound. On any failure, release the ones
	// already claimed so we do not leak controllers.
	claimed := make([]*group.Selector, 0, len(selectors))
	for _, s := range selectors {
		if err := s.ClaimController(i); err != nil {
			for _, c := range claimed {
				c.ReleaseController(i)
			}
			return E.Cause(err, "local.bypass_selector conflict")
		}
		claimed = append(claimed, s)
	}
	ctx, cancel := context.WithCancel(i.ctx)
	i.bypassSelectors = selectors
	i.bypassSelectorEvents = make(chan struct{}, 1)
	i.bypassSelectorCancel = cancel
	i.bypassSelectorDone = make(chan struct{})
	i.bypassSelectorGuards = make([]*list.Element[group.SelectorUpdateGuard], 0, len(selectors))
	i.bypassSelectorCallbacks = make([]*list.Element[group.SelectorUpdateCallback], 0, len(selectors))
	for _, s := range selectors {
		i.bypassSelectorGuards = append(i.bypassSelectorGuards, s.RegisterUpdateGuard(i.guardBypassSelectorUpdate))
		i.bypassSelectorCallbacks = append(i.bypassSelectorCallbacks, s.RegisterUpdateCallback(i.notifyBypassSelectorUpdate))
	}
	go i.runBypassSelector(ctx)
	if err := i.setBypassSelectorState(false, true); err != nil {
		i.stopBypassSelector()
		return E.Cause(err, "initialize safe eBPF bypass_selector state")
	}
	i.notifyBypassSelectorUpdate("")
	return nil
}

// bypassSelectorWantsBypassAny reports whether ANY watched selector currently
// points at a member that should trigger the bypass (OR aggregation). This is
// the multi-selector replacement for the old single-selector check.
func (i *Inbound) bypassSelectorWantsBypassAny() bool {
	if i.bypassSelectorOptions == nil {
		return false
	}
	for _, s := range i.bypassSelectors {
		selected := s.Selected(N.NetworkTCP)
		if selected == nil {
			continue
		}
		if i.bypassSelectorMemberTriggers(selected.Tag()) {
			return true
		}
	}
	return false
}

// bypassSelectorMemberTriggers reports whether a single selected member should
// engage the bypass: either it is explicitly listed in bypass_when, or the
// direct wildcard is active and the member resolves to a direct outbound.
func (i *Inbound) bypassSelectorMemberTriggers(selected string) bool {
	if i.bypassSelectorOptions == nil || selected == "" {
		return false
	}
	if common.Contains(i.bypassSelectorOptions.BypassWhen, selected) {
		return true
	}
	if i.bypassSelectorDirectWild {
		if m := service.FromContext[adapter.OutboundManager](i.ctx); m != nil {
			if member, ok := m.Outbound(selected); ok && member.Type() == C.TypeDirect {
				return true
			}
		}
	}
	return false
}

func (i *Inbound) guardBypassSelectorUpdate(previous, selected string) error {
	if err := i.setBypassSelectorState(false, true); err != nil {
		return E.Cause(err, "disable eBPF bypass before selector update")
	}
	return nil
}

func (i *Inbound) notifyBypassSelectorUpdate(selected string) {
	i.bypassSelectorGeneration.Add(1)
	select {
	case i.bypassSelectorEvents <- struct{}{}:
	default:
	}
}

func (i *Inbound) runBypassSelector(ctx context.Context) {
	defer close(i.bypassSelectorDone)
	settle := time.Duration(i.bypassSelectorOptions.SettleDelay)
	final := time.Duration(i.bypassSelectorOptions.FinalCheckDelay)
	window := time.Duration(i.bypassSelectorOptions.RapidSwitchWindow)
	threshold := int(i.bypassSelectorOptions.RapidSwitchThreshold)
	var st *time.Timer
	var sc <-chan time.Time
	var ft *time.Timer
	var fc <-chan time.Time
	stop := func(t **time.Timer, c *<-chan time.Time) {
		if *t != nil && !(*t).Stop() {
			select {
			case <-(*t).C:
			default:
			}
		}
		*c = nil
	}
	reset := func(t **time.Timer, c *<-chan time.Time, d time.Duration) {
		stop(t, c)
		if *t == nil {
			*t = time.NewTimer(d)
		} else {
			(*t).Reset(d)
		}
		*c = (*t).C
	}
	defer stop(&st, &sc)
	defer stop(&ft, &fc)
	var generation, settleGeneration, last uint64
	var recent []time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-i.bypassSelectorEvents:
			observed := i.bypassSelectorGeneration.Load()
			changes := observed - last
			last = observed
			generation += changes
			now := time.Now()
			cutoff := now.Add(-window)
			first := 0
			for first < len(recent) && recent[first].Before(cutoff) {
				first++
			}
			recent = recent[first:]
			if changes > 0 && observed > 1 {
				for c := uint64(0); c < changes && len(recent) < threshold; c++ {
					recent = append(recent, now)
				}
			}
			rapid := len(recent) >= threshold
			stop(&st, &sc)
			if i.bypassSelectorWantsBypassAny() {
				settleGeneration = generation
				d := settle
				if rapid && final > d {
					d = final
					i.logger.Debug("eBPF bypass_selector rapid switching detected; delaying bypass enablement for ", d)
				}
				reset(&st, &sc, d)
			} else if err := i.setBypassSelectorState(false, true); err != nil {
				i.logger.Error("disable eBPF bypass_selector: ", err)
			}
			reset(&ft, &fc, final)
		case <-sc:
			sc = nil
			if settleGeneration == generation && i.bypassSelectorWantsBypassAny() {
				if err := i.setBypassSelectorState(true, true); err != nil {
					i.logger.Error("enable eBPF bypass_selector: ", err)
				} else {
					reset(&ft, &fc, final)
				}
			}
		case <-fc:
			fc = nil
			expected := i.bypassSelectorWantsBypassAny()
			if expected && sc != nil && settleGeneration == generation {
				reset(&ft, &fc, final)
				continue
			}
			actual, err := i.currentBypassSelectorState()
			if err != nil {
				i.logger.Error("read final eBPF bypass_selector state: ", err)
				if backend := i.tcBackend(); backend != nil {
					_, _ = backend.SetBypassCIDREnabled(false)
				}
				continue
			}
			if expected != actual {
				if err = i.setBypassSelectorState(expected, true); err != nil {
					i.logger.Error("final eBPF bypass_selector check: ", err)
				}
			}
		}
	}
}

func (i *Inbound) currentBypassSelectorState() (bool, error) {
	b := i.tcBackend()
	if b == nil {
		return false, E.New("local TC eBPF backend unavailable")
	}
	return b.BypassCIDREnabled()
}

func (i *Inbound) setBypassSelectorState(enabled, clean bool) error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	b := i.tcBackend()
	if b == nil {
		return E.New("local TC eBPF backend unavailable")
	}
	changed, err := b.SetBypassCIDREnabled(enabled)
	if err != nil {
		return err
	}
	if changed && clean {
		i.udpNat.Purge()
		if err = i.udpReplySockets.reset(); err != nil {
			if enabled {
				_, _ = b.SetBypassCIDREnabled(false)
			}
			i.bypassSelectorState = false
			i.bypassSelectorStateKnown = true
			return E.Cause(err, "reset eBPF UDP state after bypass_selector update")
		}
		if i.bypassSelectorOptions.InterruptExistingConnections {
			for _, s := range i.bypassSelectors {
				s.InterruptConnections(true)
			}
		}
	}
	i.bypassSelectorState = enabled
	i.bypassSelectorStateKnown = true
	return nil
}

func (i *Inbound) stopBypassSelector() {
	// Release controllers first so no further update events are delivered while
	// we tear down.
	for _, s := range i.bypassSelectors {
		s.ReleaseController(i)
	}
	if i.bypassSelectorCancel != nil {
		i.bypassSelectorCancel()
	}
	if i.bypassSelectorDone != nil {
		<-i.bypassSelectorDone
	}
	// Unregister guards/callbacks. Guards and callbacks are registered in
	// lock-step with bypassSelectors, so indices line up.
	for idx, s := range i.bypassSelectors {
		if idx < len(i.bypassSelectorGuards) {
			s.UnregisterUpdateGuard(i.bypassSelectorGuards[idx])
		}
		if idx < len(i.bypassSelectorCallbacks) {
			s.UnregisterUpdateCallback(i.bypassSelectorCallbacks[idx])
		}
	}
	i.bypassSelectors = nil
	i.bypassSelectorGuards = nil
	i.bypassSelectorCallbacks = nil
	i.bypassSelectorEvents = nil
	i.bypassSelectorCancel = nil
	i.bypassSelectorDone = nil
	i.bypassSelectorGeneration.Store(0)
	i.bypassSelectorState = false
	i.bypassSelectorStateKnown = false
}
