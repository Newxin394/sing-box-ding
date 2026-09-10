//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/option"
)

// TestResolveMapCapacitiesDefaultsWithoutOverrides pins the property that makes
// map_capacity safe to add to an existing configuration: with no override block
// at all, every capacity is exactly the value the data planes used before the
// option existed.
func TestResolveMapCapacitiesDefaultsWithoutOverrides(t *testing.T) {
	wantFlow := commonEBPF.DefaultFlowMapCapacities()
	wantCgroup := commonEBPF.DefaultCgroupMapCapacity()
	for _, overrides := range []*option.EBPFMapCapacityOptions{nil, {}} {
		flow, cgroup, err := resolveMapCapacities(overrides)
		if err != nil {
			t.Fatalf("resolveMapCapacities(%v) error = %v", overrides, err)
		}
		if flow != wantFlow {
			t.Fatalf("resolveMapCapacities(%v) flow = %+v, want %+v", overrides, flow, wantFlow)
		}
		if cgroup != wantCgroup {
			t.Fatalf("resolveMapCapacities(%v) cgroup = %+v, want %+v", overrides, cgroup, wantCgroup)
		}
	}
}

// TestResolveMapCapacitiesOverridesOneFieldAtATime covers the other half of the
// same property: setting one field must not disturb any other, in either the
// flow group or the cgroup group. A caller lowering exactly the table that hurts
// on a small device should not silently change five other capacities.
func TestResolveMapCapacitiesOverridesOneFieldAtATime(t *testing.T) {
	defaults := commonEBPF.DefaultFlowMapCapacities()
	for _, testCase := range []struct {
		name     string
		override *option.EBPFMapCapacityOptions
		check    func(*testing.T, commonEBPF.FlowMapCapacities, commonEBPF.CgroupMapCapacity)
	}{
		{
			name:     "assignment only",
			override: &option.EBPFMapCapacityOptions{Assignment: 4096},
			check: func(t *testing.T, flow commonEBPF.FlowMapCapacities, _ commonEBPF.CgroupMapCapacity) {
				if flow.Assignment != 4096 {
					t.Fatalf("assignment = %d, want 4096", flow.Assignment)
				}
				if flow.SelfBypass != defaults.SelfBypass || flow.ProcessOwner != defaults.ProcessOwner {
					t.Fatalf("other flow capacities changed: %+v", flow)
				}
			},
		},
		{
			name:     "self_bypass only",
			override: &option.EBPFMapCapacityOptions{SelfBypass: 8192},
			check: func(t *testing.T, flow commonEBPF.FlowMapCapacities, _ commonEBPF.CgroupMapCapacity) {
				if flow.SelfBypass != 8192 {
					t.Fatalf("self_bypass = %d, want 8192", flow.SelfBypass)
				}
				if flow.Assignment != defaults.Assignment || flow.ProcessOwner != defaults.ProcessOwner {
					t.Fatalf("other flow capacities changed: %+v", flow)
				}
			},
		},
		{
			name: "one cgroup field only",
			override: &option.EBPFMapCapacityOptions{
				Cgroup: &option.EBPFCgroupMapCapacityOptions{UDPFlow: 2048},
			},
			check: func(t *testing.T, flow commonEBPF.FlowMapCapacities, cgroup commonEBPF.CgroupMapCapacity) {
				if cgroup.UDPFlow != 2048 {
					t.Fatalf("udp_flow = %d, want 2048", cgroup.UDPFlow)
				}
				if flow != defaults {
					t.Fatalf("flow capacities changed by a cgroup-only override: %+v", flow)
				}
				wantCgroup := commonEBPF.DefaultCgroupMapCapacity()
				wantCgroup.UDPFlow = 2048
				if cgroup != wantCgroup {
					t.Fatalf("cgroup = %+v, want %+v", cgroup, wantCgroup)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			flow, cgroup, err := resolveMapCapacities(testCase.override)
			if err != nil {
				t.Fatalf("resolveMapCapacities error = %v", err)
			}
			testCase.check(t, flow, cgroup)
		})
	}
}

// TestResolveMapCapacitiesRejectsOutOfRange checks that an out-of-range value is
// refused while the configuration is being read. Without this the same value
// would only surface as a bare EINVAL from bpf(2) when the map is created, with
// nothing naming the field that caused it.
func TestResolveMapCapacitiesRejectsOutOfRange(t *testing.T) {
	tooLarge := uint32(commonEBPF.MaxConfigurableMapCapacity + 1)
	for _, testCase := range []struct {
		name     string
		override *option.EBPFMapCapacityOptions
	}{
		{"assignment", &option.EBPFMapCapacityOptions{Assignment: tooLarge}},
		{"self_bypass", &option.EBPFMapCapacityOptions{SelfBypass: tooLarge}},
		{"process_owner", &option.EBPFMapCapacityOptions{ProcessOwner: tooLarge}},
		{
			"cgroup.socket_bypass",
			&option.EBPFMapCapacityOptions{Cgroup: &option.EBPFCgroupMapCapacityOptions{SocketBypass: tooLarge}},
		},
	} {
		if _, _, err := resolveMapCapacities(testCase.override); err == nil {
			t.Fatalf("resolveMapCapacities(%s = %d) succeeded, want an error naming the field", testCase.name, tooLarge)
		}
	}
	if _, _, err := resolveMapCapacities(&option.EBPFMapCapacityOptions{
		Assignment: commonEBPF.MaxConfigurableMapCapacity,
	}); err != nil {
		t.Fatalf("resolveMapCapacities at the documented upper bound failed: %v", err)
	}
}

// TestDefaultFlowMapCapacitiesMatchDocumentedSizes keeps the documented memory
// figures honest: docs/configuration/inbound/ebpf.md quotes roughly 4.5 MB for
// assignment and 1.0 MB for each of the other two, which only holds while these
// defaults stay where they are. Changing a default means changing the document.
func TestDefaultFlowMapCapacitiesMatchDocumentedSizes(t *testing.T) {
	capacity := commonEBPF.DefaultFlowMapCapacities()
	if capacity.Assignment != 65536 {
		t.Fatalf("assignment default = %d, want 65536 as documented", capacity.Assignment)
	}
	if capacity.SelfBypass != 65536 {
		t.Fatalf("self_bypass default = %d, want 65536 as documented", capacity.SelfBypass)
	}
	if capacity.ProcessOwner != 65536 {
		t.Fatalf("process_owner default = %d, want 65536 as documented", capacity.ProcessOwner)
	}
}
