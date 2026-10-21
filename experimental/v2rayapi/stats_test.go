package v2rayapi

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestStatsServiceTrafficCountersSelectConfiguredDimensions(t *testing.T) {
	service := NewStatsService(option.V2RayStatsServiceOptions{
		Enabled:   true,
		Inbounds:  []string{"in-1"},
		Outbounds: []string{"out-1"},
		Users:     []string{"user-1"},
	})

	uplink, downlink := service.trafficCounters("in-1", "out-1", "user-1")
	if len(uplink) != 3 || len(downlink) != 3 {
		t.Fatalf("counter lengths = (%d, %d), want (3, 3)", len(uplink), len(downlink))
	}

	wantNames := []string{
		"inbound>>>in-1>>>traffic>>>uplink",
		"inbound>>>in-1>>>traffic>>>downlink",
		"outbound>>>out-1>>>traffic>>>uplink",
		"outbound>>>out-1>>>traffic>>>downlink",
		"user>>>user-1>>>traffic>>>uplink",
		"user>>>user-1>>>traffic>>>downlink",
	}
	if len(service.counters) != len(wantNames) {
		t.Fatalf("counter count = %d, want %d", len(service.counters), len(wantNames))
	}
	for _, name := range wantNames {
		if service.counters[name] == nil {
			t.Errorf("counter %q was not created", name)
		}
	}

	secondUplink, secondDownlink := service.trafficCounters("in-1", "out-1", "user-1")
	for i := range uplink {
		if uplink[i] != secondUplink[i] || downlink[i] != secondDownlink[i] {
			t.Errorf("counter %d was not reused", i)
		}
	}
}

func TestStatsServiceTrafficCountersIgnoreUnconfiguredDimensions(t *testing.T) {
	service := NewStatsService(option.V2RayStatsServiceOptions{
		Enabled:  true,
		Inbounds: []string{"in-1"},
	})

	uplink, downlink := service.trafficCounters("in-1", "out-unknown", "user-unknown")
	if len(uplink) != 1 || len(downlink) != 1 {
		t.Fatalf("counter lengths = (%d, %d), want (1, 1)", len(uplink), len(downlink))
	}
	if len(service.counters) != 2 {
		t.Fatalf("counter count = %d, want 2", len(service.counters))
	}

	service.counters["inbound>>>in-1>>>traffic>>>uplink"].Store(12)
	service.counters["inbound>>>in-1>>>traffic>>>downlink"].Store(34)
	if got := uplink[0].Load(); got != 12 {
		t.Errorf("uplink counter = %d, want 12", got)
	}
	if got := downlink[0].Load(); got != 34 {
		t.Errorf("downlink counter = %d, want 34", got)
	}
}

func TestStatsServiceTrafficCountersReturnEmptyWhenNoDimensionMatches(t *testing.T) {
	service := NewStatsService(option.V2RayStatsServiceOptions{Enabled: true})

	uplink, downlink := service.trafficCounters("in-1", "out-1", "user-1")
	if len(uplink) != 0 || len(downlink) != 0 {
		t.Fatalf("counter lengths = (%d, %d), want (0, 0)", len(uplink), len(downlink))
	}
	if len(service.counters) != 0 {
		t.Errorf("created %d counters, want none", len(service.counters))
	}
}
