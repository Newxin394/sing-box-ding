package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type testEBPFInbound struct {
	tag         string
	diagnostics adapter.EBPFRuntimeDiagnostics
	runtime     adapter.EBPFKernelRuntimeDiagnostics
}

func (i *testEBPFInbound) Start(adapter.StartStage) error { return nil }
func (i *testEBPFInbound) Close() error                   { return nil }
func (i *testEBPFInbound) Type() string                   { return "ebpf" }
func (i *testEBPFInbound) Tag() string                    { return i.tag }

func (i *testEBPFInbound) EBPFRuntimeDiagnostics() adapter.EBPFRuntimeDiagnostics {
	return i.diagnostics
}

func (i *testEBPFInbound) EBPFKernelRuntimeDiagnostics() adapter.EBPFKernelRuntimeDiagnostics {
	return i.runtime
}

// testPlainInbound stands in for every inbound that is not eBPF: it must be
// skipped by the diagnostics walk rather than reported as empty.
type testPlainInbound struct{ tag string }

func (i *testPlainInbound) Start(adapter.StartStage) error { return nil }
func (i *testPlainInbound) Close() error                   { return nil }
func (i *testPlainInbound) Type() string                   { return "direct" }
func (i *testPlainInbound) Tag() string                    { return i.tag }

type testInboundManager struct {
	inbounds []adapter.Inbound
}

func (m *testInboundManager) Start(adapter.StartStage) error { return nil }
func (m *testInboundManager) Close() error                   { return nil }

func (m *testInboundManager) Inbounds() []adapter.Inbound { return m.inbounds }

func (m *testInboundManager) Get(tag string) (adapter.Inbound, bool) {
	for _, inbound := range m.inbounds {
		if inbound.Tag() == tag {
			return inbound, true
		}
	}
	return nil, false
}

func (m *testInboundManager) Remove(string) error { return nil }

func (m *testInboundManager) Create(
	context.Context,
	adapter.Router,
	log.ContextLogger,
	string,
	string,
	any,
) error {
	return nil
}

func startedServiceWithInbounds(inbounds ...adapter.Inbound) *StartedService {
	return &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{inboundManager: &testInboundManager{inbounds: inbounds}},
	}
}

// The provider methods this daemon calls differ from the ones the package-side
// diagnostics expose; a compile-time assertion here keeps the two in step.
var _ adapter.EBPFDiagnosticsProvider = (*testEBPFInbound)(nil)

func TestGetEBPFDiagnosticsReportsSchemaVersionWithoutInbound(t *testing.T) {
	service := startedServiceWithInbounds()
	response, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{Deep: true})
	if err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("schema version = %d, want %d", response.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	// A process with no eBPF inbound still answers, so a dashboard can tell
	// "not configured" from "server too old to know the call".
	if len(response.Inbounds) != 0 {
		t.Fatalf("inbounds = %d, want none", len(response.Inbounds))
	}
}

func TestGetEBPFDiagnosticsRequiresStartedService(t *testing.T) {
	for _, service := range []*StartedService{
		{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTING}},
		{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}},
	} {
		_, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{})
		if err == nil {
			t.Fatalf("status %v with nil instance should be rejected", service.serviceStatus.Status)
		}
	}
}

func TestGetEBPFDiagnosticsSkipsNonEBPFInbounds(t *testing.T) {
	service := startedServiceWithInbounds(
		&testPlainInbound{tag: "direct-in"},
		&testEBPFInbound{tag: "ebpf-in", diagnostics: adapter.EBPFRuntimeDiagnostics{Tag: "ebpf-in"}},
	)
	response, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Inbounds) != 1 || response.Inbounds[0].Tag != "ebpf-in" {
		t.Fatalf("inbounds = %+v, want only the eBPF one", response.Inbounds)
	}
}

func TestGetEBPFDiagnosticsShallowSkipsKernelWalk(t *testing.T) {
	service := startedServiceWithInbounds(
		&testEBPFInbound{
			tag:         "ebpf-in",
			diagnostics: adapter.EBPFRuntimeDiagnostics{Tag: "ebpf-in"},
			runtime: adapter.EBPFKernelRuntimeDiagnostics{
				ObservedAt: time.UnixMilli(7),
				Programs:   []adapter.EBPFProgramDiagnostics{{ID: 42, Name: "sb_ebpf_conn4"}},
			},
		},
	)
	response, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.KernelRuntime != nil {
		t.Fatal("a lightweight request must not enumerate kernel resources")
	}
	if len(response.Inbounds) != 1 || response.Inbounds[0].KernelRuntime != nil {
		t.Fatal("a lightweight request must not include per-inbound deep snapshots")
	}
}

func TestGetEBPFDiagnosticsCarriesRuntimeState(t *testing.T) {
	observedAt := time.UnixMilli(1700000000123)
	lastErrorAt := observedAt.Add(time.Second)
	service := startedServiceWithInbounds(&testEBPFInbound{
		tag: "ebpf-in",
		diagnostics: adapter.EBPFRuntimeDiagnostics{
			SchemaVersion: adapter.EBPFDiagnosticsSchemaVersion,
			ObservedAt:    observedAt,
			Tag:           "ebpf-in",
			State:         "recovering",
			LocalEnabled:  true,
			LastError:     "attachment missing",
			LastErrorAt:   &lastErrorAt,
			Attachments: []adapter.EBPFAttachmentDiagnostics{{
				InterfaceName:  "wlan0",
				InterfaceIndex: 7,
				Role:           "local",
				Mechanism:      "tcx",
				Slot:           2,
			}},
			LocalBypassRuleSet: adapter.EBPFBypassRuleSetDiagnostics{
				Consistent: true,
				BackendState: map[string]adapter.EBPFBypassRuleSetBackendState{
					"TC": {Version: 3, Known: true},
				},
			},
			PolicyEpoch: adapter.EBPFPolicyEpochDiagnostics{
				LocalConfirmed:  11,
				LocalExpected:   12,
				SharedConfirmed: 21,
				SharedExpected:  21,
				Converged:       false,
			},
			Counters: adapter.EBPFCounters{TCLocalFragmentPasses: 9},
			UDPNAT: adapter.EBPFUDPNATDiagnostics{
				ActiveSessions:  3,
				CreatedSessions: 7,
			},
		},
	})
	response, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := response.Inbounds[0]
	if diagnostics.Tag != "ebpf-in" || diagnostics.State != "recovering" {
		t.Fatalf("unexpected identity: %+v", diagnostics)
	}
	// Milliseconds cross the wire: a nanosecond timestamp would silently lose
	// precision the dashboards rely on for ordering.
	if diagnostics.ObservedAt != observedAt.UnixMilli() {
		t.Fatalf("observed at = %d, want %d", diagnostics.ObservedAt, observedAt.UnixMilli())
	}
	if diagnostics.LastErrorAt == nil || *diagnostics.LastErrorAt != lastErrorAt.UnixMilli() {
		t.Fatalf("last error at = %v, want %d", diagnostics.LastErrorAt, lastErrorAt.UnixMilli())
	}
	if len(diagnostics.Attachments) != 1 ||
		diagnostics.Attachments[0].InterfaceIndex != 7 ||
		diagnostics.Attachments[0].Slot != 2 {
		t.Fatalf("attachments = %+v", diagnostics.Attachments)
	}
	backendState := diagnostics.LocalBypassRuleSet.GetBackendState()["TC"]
	if backendState == nil || !backendState.Known || backendState.Version != 3 {
		t.Fatalf("backend state = %+v", backendState)
	}
	if diagnostics.Counters == nil || diagnostics.Counters.TcLocalFragmentPasses != 9 {
		t.Fatalf("counters = %+v", diagnostics.Counters)
	}
	if diagnostics.PolicyEpoch == nil || diagnostics.PolicyEpoch.LocalConfirmed != 11 ||
		diagnostics.PolicyEpoch.Converged {
		t.Fatalf("policy epoch = %+v", diagnostics.PolicyEpoch)
	}
	if diagnostics.UdpNAT == nil || diagnostics.UdpNAT.ActiveSessions != 3 ||
		diagnostics.UdpNAT.CreatedSessions != 7 {
		t.Fatalf("UDP NAT = %+v", diagnostics.UdpNAT)
	}
}

func TestGetEBPFDiagnosticsDeepIncludesKernelRuntime(t *testing.T) {
	service := startedServiceWithInbounds(&testEBPFInbound{
		tag:         "ebpf-in",
		diagnostics: adapter.EBPFRuntimeDiagnostics{Tag: "ebpf-in"},
		runtime: adapter.EBPFKernelRuntimeDiagnostics{
			ObservedAt: time.UnixMilli(7),
			Programs: []adapter.EBPFProgramDiagnostics{{
				ID: 42, Name: "sb_ebpf_conn4", Type: "CGroupSockAddr", MapCount: 2,
			}},
			MapOccupancy: adapter.EBPFMapOccupancyDiagnostics{
				Status: "pass",
				Maps: []adapter.EBPFMapDiagnostics{{
					ID: 7, Name: "sb_tcp_redirect", Type: "LRUHash", MaxEntries: 4096,
					Entries: 3, Pressure: "healthy", Supported: true,
				}},
			},
		},
	})
	response, err := service.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{Deep: true})
	if err != nil {
		t.Fatal(err)
	}
	if response.KernelRuntime == nil || len(response.KernelRuntime.Programs) != 1 ||
		response.KernelRuntime.Programs[0].Id != 42 {
		t.Fatalf("kernel runtime programs = %+v", response.KernelRuntime)
	}
	if response.KernelRuntime.MapOccupancy == nil ||
		len(response.KernelRuntime.MapOccupancy.Maps) != 1 ||
		response.KernelRuntime.MapOccupancy.Maps[0].Entries != 3 {
		t.Fatalf("map occupancy = %+v", response.KernelRuntime.MapOccupancy)
	}
	if len(response.Inbounds) != 1 || response.Inbounds[0].KernelRuntime == nil {
		t.Fatal("deep request should attach the per-inbound kernel snapshot")
	}
}

func TestMergeEBPFKernelRuntimeDeduplicatesSharedResources(t *testing.T) {
	first := &EBPFKernelRuntimeDiagnostics{
		ObservedAt: 1,
		Programs:   []*EBPFProgramDiagnostics{{Id: 1}},
		MapOccupancy: &EBPFMapOccupancyDiagnostics{
			Status: "pass",
			Maps:   []*EBPFMapDiagnostics{{Id: 3}},
		},
	}
	second := &EBPFKernelRuntimeDiagnostics{
		ObservedAt: 2,
		Programs:   []*EBPFProgramDiagnostics{{Id: 1}, {Id: 2}},
		MapOccupancy: &EBPFMapOccupancyDiagnostics{
			Status: "warning",
			Maps:   []*EBPFMapDiagnostics{{Id: 3}, {Id: 4}},
		},
	}
	aggregate := mergeEBPFKernelRuntime(mergeEBPFKernelRuntime(nil, first), second)
	// Two inbounds share the same loader objects; summing would report each
	// program once per inbound.
	if len(aggregate.Programs) != 2 {
		t.Fatalf("programs = %d, want 2 deduplicated entries", len(aggregate.Programs))
	}
	if len(aggregate.MapOccupancy.Maps) != 2 {
		t.Fatalf("maps = %d, want 2 deduplicated entries", len(aggregate.MapOccupancy.Maps))
	}
	// The worst state wins: one warning among passes is still a warning.
	if aggregate.MapOccupancy.Status != "warning" {
		t.Fatalf("status = %q, want warning", aggregate.MapOccupancy.Status)
	}
	if len(first.Programs) != 1 || len(first.MapOccupancy.Maps) != 1 {
		t.Fatal("merging must not mutate the inbound's own snapshot")
	}
}

func TestGetEBPFDiagnosticsGRPCRegistrationAndAuthentication(t *testing.T) {
	service := startedServiceWithInbounds(&testEBPFInbound{
		tag:         "ebpf-in",
		diagnostics: adapter.EBPFRuntimeDiagnostics{Tag: "ebpf-in"},
	})
	server := NewServer(service, "test-secret")
	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	connection, err := grpc.NewClient(
		"passthrough:///sing-box-api-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := NewStartedServiceClient(connection)

	// Adding an RPC must not accidentally widen the authenticated surface.
	_, err = client.GetEBPFDiagnostics(context.Background(), &EBPFDiagnosticsRequest{Deep: true})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated call = %v, want Unauthenticated", err)
	}
	authenticatedContext := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization",
		"Bearer test-secret",
	)
	response, err := client.GetEBPFDiagnostics(authenticatedContext, &EBPFDiagnosticsRequest{Deep: true})
	if err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("RPC schema version = %d, want %d", response.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if len(response.Inbounds) != 1 || response.Inbounds[0].Tag != "ebpf-in" {
		t.Fatalf("unexpected RPC response: %+v", response.Inbounds)
	}
}

// Clients decide whether to call GetEBPFDiagnostics from the version reported
// by GetVersion; advertising 4 would make a conforming client skip the call.
func TestAPIVersionAdvertisesEBPFDiagnostics(t *testing.T) {
	if APIVersion < 6 {
		t.Fatalf("eBPF diagnostics requires API version 6, got %d", APIVersion)
	}
}
