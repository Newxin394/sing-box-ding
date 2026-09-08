package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/x/list"
)

type closeTestProvider struct {
	tag         string
	closeErr    error
	startErr    error
	closed      bool
	startCalled bool
}

func (p *closeTestProvider) Type() string                                           { return "test" }
func (p *closeTestProvider) Tag() string                                            { return p.tag }
func (p *closeTestProvider) Outbounds() []adapter.Outbound                          { return nil }
func (p *closeTestProvider) Outbound(string) (adapter.Outbound, bool)               { return nil, false }
func (p *closeTestProvider) UpdatedAt() time.Time                                   { return time.Time{} }
func (p *closeTestProvider) HealthCheck(context.Context) (map[string]uint16, error) { return nil, nil }
func (p *closeTestProvider) RegisterCallback(adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return nil
}
func (p *closeTestProvider) UnregisterCallback(*list.Element[adapter.ProviderUpdateCallback]) {}
func (p *closeTestProvider) StartContext(context.Context, *adapter.HTTPStartContext) error {
	p.startCalled = true
	return p.startErr
}
func (p *closeTestProvider) Close() error {
	p.closed = true
	return p.closeErr
}

func TestManagerStartReturnsProviderLifecycleFailure(t *testing.T) {
	startFailure := errors.New("provider start failed")
	first := &closeTestProvider{tag: "first"}
	second := &closeTestProvider{tag: "second", startErr: startFailure}
	manager := &Manager{
		ctx:       context.Background(),
		logger:    log.NewNOPFactory().NewLogger("provider-test"),
		providers: []adapter.Provider{first, second},
	}

	err := manager.Start(adapter.StartStateStart)
	if !errors.Is(err, startFailure) {
		t.Fatalf("got %v, want provider startup failure", err)
	}
	if !first.startCalled || !second.startCalled {
		t.Fatal("manager must call StartContext for providers in sequence")
	}
}

func TestManagerCloseReturnsAndAggregatesProviderErrors(t *testing.T) {
	closeFailure := errors.New("provider close failed")
	first := &closeTestProvider{tag: "first", closeErr: closeFailure}
	second := &closeTestProvider{tag: "second"}
	manager := &Manager{
		logger:    log.NewNOPFactory().NewLogger("provider-test"),
		started:   true,
		providers: []adapter.Provider{first, second},
	}

	err := manager.Close()
	if !errors.Is(err, closeFailure) {
		t.Fatalf("got %v, want aggregated provider close failure", err)
	}
	if !first.closed || !second.closed {
		t.Fatal("manager must attempt to close every provider even after a close failure")
	}
	if len(manager.providers) != 0 {
		t.Fatal("manager must release its provider slice during close")
	}
	if _, found := manager.Get(first.tag); found {
		t.Fatal("manager must release its provider tag references during close")
	}
}
