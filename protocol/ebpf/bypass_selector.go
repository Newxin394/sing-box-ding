//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

func (i *Inbound) startBypassSelector() error {
	o := i.bypassSelectorOptions
	if o == nil {
		return nil
	}
	m := service.FromContext[adapter.OutboundManager](i.ctx)
	ob, ok := m.Outbound(o.Tag)
	if !ok {
		return E.New("local.bypass_selector selector not found: ", o.Tag)
	}
	s, ok := ob.(*group.Selector)
	if !ok {
		return E.New("local.bypass_selector outbound is not a selector: ", o.Tag)
	}
	for _, tag := range o.BypassWhen {
		if !common.Contains(s.All(), tag) {
			return E.New("local.bypass_selector.bypass_when outbound not found in selector: ", tag)
		}
		member, ok := m.Outbound(tag)
		if !ok {
			return E.New("local.bypass_selector.bypass_when outbound not found: ", tag)
		}
		if member.Type() != C.TypeDirect {
			return E.New("local.bypass_selector.bypass_when must be a direct outbound: ", tag)
		}
	}
	if err := s.ClaimController(i); err != nil {
		return E.Cause(err, "local.bypass_selector conflict")
	}
	ctx, cancel := context.WithCancel(i.ctx)
	i.bypassSelector = s
	i.bypassSelectorEvents = make(chan struct{}, 1)
	i.bypassSelectorCancel = cancel
	i.bypassSelectorDone = make(chan struct{})
	i.bypassSelectorGuard = s.RegisterUpdateGuard(i.guardBypassSelectorUpdate)
	i.bypassSelectorCallback = s.RegisterUpdateCallback(i.notifyBypassSelectorUpdate)
	go i.runBypassSelector(ctx)
	if err := i.setBypassSelectorState(false, true); err != nil {
		i.stopBypassSelector()
		return E.Cause(err, "initialize safe eBPF bypass_selector state")
	}
	i.notifyBypassSelectorUpdate(s.Now())
	return nil
}
func (i *Inbound) bypassSelectorWantsBypass(selected string) bool {
	return i.bypassSelectorOptions != nil && common.Contains(i.bypassSelectorOptions.BypassWhen, selected)
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
			if i.bypassSelectorWantsBypass(i.bypassSelector.Now()) {
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
			if settleGeneration == generation && i.bypassSelectorWantsBypass(i.bypassSelector.Now()) {
				if err := i.setBypassSelectorState(true, true); err != nil {
					i.logger.Error("enable eBPF bypass_selector: ", err)
				} else {
					reset(&ft, &fc, final)
				}
			}
		case <-fc:
			fc = nil
			expected := i.bypassSelectorWantsBypass(i.bypassSelector.Now())
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
		if i.bypassSelectorOptions.InterruptExistingConnections && i.bypassSelector != nil {
			i.bypassSelector.InterruptConnections(true)
		}
	}
	i.bypassSelectorState = enabled
	i.bypassSelectorStateKnown = true
	return nil
}
func (i *Inbound) stopBypassSelector() {
	s := i.bypassSelector
	if s != nil {
		s.ReleaseController(i)
	}
	if i.bypassSelectorCancel != nil {
		i.bypassSelectorCancel()
	}
	if i.bypassSelectorDone != nil {
		<-i.bypassSelectorDone
	}
	if s != nil {
		s.UnregisterUpdateGuard(i.bypassSelectorGuard)
		s.UnregisterUpdateCallback(i.bypassSelectorCallback)
	}
	i.bypassSelector = nil
	i.bypassSelectorGuard = nil
	i.bypassSelectorCallback = nil
	i.bypassSelectorEvents = nil
	i.bypassSelectorCancel = nil
	i.bypassSelectorDone = nil
	i.bypassSelectorGeneration.Store(0)
	i.bypassSelectorState = false
	i.bypassSelectorStateKnown = false
}
