//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/ebpf"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	CiliumEBPF "github.com/cilium/ebpf"
)

// TestEBPFRuntimeDiagnosticsCarriesSchemaVersionAndObservation covers the two
// fields the gRPC client branches on: the schema version it must check before
// trusting any other field, and the timestamp that tells a dashboard whether
// what it is showing is stale.
func TestEBPFRuntimeDiagnosticsCarriesSchemaVersionAndObservation(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	before := time.Now()
	diagnostics := inbound.EBPFRuntimeDiagnostics()
	if diagnostics.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("schema version = %d, want %d", diagnostics.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if diagnostics.ObservedAt.Before(before) {
		t.Fatalf("observed at = %v, want not before %v", diagnostics.ObservedAt, before)
	}
	// A configured data plane with nothing attached yet must surface as the
	// same state the internal report gives, not as an empty string.
	if diagnostics.State != EBPFDiagnosticsStateWaitingForInterface {
		t.Fatalf("state = %q, want %q", diagnostics.State, EBPFDiagnosticsStateWaitingForInterface)
	}
}

// TestEBPFRuntimeDiagnosticsDeemphasisesUncomputedCounters is the contract for
// fields this fork does not compute: they must read as zero rather than
// borrowing a neighbouring number, because a nonzero value there would claim
// the kernel-side accounting exists.
func TestEBPFRuntimeDiagnosticsDeemphasisesUncomputedCounters(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.diagnostics.haveOutcome = true
	inbound.diagnostics.lastOutcome.general = tcSharedRewriteRecoverable
	diagnostics := inbound.EBPFRuntimeDiagnostics()
	if !diagnostics.RecoveryPending {
		t.Fatal("recovery pending = false, want true for a recoverable outcome")
	}
	// TC-side counters are computed by the fork under different names
	// (RawIP*), so the parent-named TC counters must stay zero rather than
	// being filled from the RawIP numbers.
	counters := diagnostics.Counters
	if counters.TCSocketLookupFailures != 0 || counters.TCReturnConflicts != 0 ||
		counters.TCLocalFragmentPasses != 0 || counters.SharedIngressFragmentPasses != 0 {
		t.Fatalf("kernel-side counters reported as non-zero: %+v", counters)
	}
}

// TestEBPFRuntimeDiagnosticsReportsOnePolicyInBothScopes covers the schema
// mismatch the fork has with the parent's message: the parent has a policy per
// data plane, the fork has one shared by all of them. Both scopes must carry
// the same version rather than one being left unknown, since that is what the
// fork actually runs.
func TestEBPFRuntimeDiagnosticsReportsOnePolicyInBothScopes(t *testing.T) {
	inbound := &Inbound{localEnabled: true, sharedEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.bypassRuleSetInconsistent = false
	inbound.bypassRuleSetPolicyVersion = 7
	inbound.bypassRuleSetExpectedVersion = 7
	// Backend state is only published for backends that exist, so both have
	// to be present for the two scopes to be compared.
	inbound.bypassRuleSetTC = bypassRuleSetBackendVersion{version: 7, known: true}
	inbound.bypassRuleSetShared = bypassRuleSetBackendVersion{version: 7, known: true}
	inbound.tcDataPlane = &tcDataPlane{backend: &commonEBPF.TCBackend{}}
	inbound.sharedRewrite = &sharedRewrite{}
	diagnostics := inbound.EBPFRuntimeDiagnostics()
	if diagnostics.LocalBypassRuleSet.PolicyVersion != 7 ||
		diagnostics.SharedBypassRuleSet.PolicyVersion != 7 {
		t.Fatalf("policy versions = %d/%d, want 7/7",
			diagnostics.LocalBypassRuleSet.PolicyVersion, diagnostics.SharedBypassRuleSet.PolicyVersion)
	}
	if !diagnostics.PolicyEpoch.Converged {
		t.Fatal("converged = false, want true when nothing is pending")
	}
	if len(diagnostics.LocalBypassRuleSet.BackendState) != 2 {
		t.Fatalf("backend state = %+v, want the two backends", diagnostics.LocalBypassRuleSet.BackendState)
	}
}

// TestEBPFRuntimeDiagnosticsCountsTCAttachmentsOnly covers the attachment
// count the operator reads first: a cgroup attachment is an attachment but not
// a TC one, and mixing them would make "TCAttachmentCount: 1" appear on a host
// where no TC filter exists at all.
func TestEBPFRuntimeDiagnosticsCountsTCAttachmentsOnly(t *testing.T) {
	inbound := &Inbound{localEnabled: true, sharedEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = &tcDataPlane{
		attachments: []*tcInterfaceAttachment{
			{interfaceName: "eth0", interfaceIndex: 2, role: tcInterfaceRole{local: true}, attachmentType: "tcx"},
			{interfaceName: "wlan0", interfaceIndex: 3, role: tcInterfaceRole{shared: true}, attachmentType: "clsact"},
		},
	}
	diagnostics := inbound.EBPFRuntimeDiagnostics()
	if diagnostics.TCAttachmentCount != 2 {
		t.Fatalf("TC attachment count = %d, want 2", diagnostics.TCAttachmentCount)
	}
	if diagnosticAttachmentCount := len(diagnostics.Attachments); diagnosticAttachmentCount != 2 {
		t.Fatalf("attachments = %d, want 2", diagnosticAttachmentCount)
	}
}

// TestEBPFKernelRuntimeDiagnosticsCachesTheWalk covers the cost boundary: the
// walk is expensive enough (it counts keys per owned map) that a polling client
// must not be able to trigger one per request.
func TestEBPFKernelRuntimeDiagnosticsCachesTheWalk(t *testing.T) {
	inbound := &Inbound{}
	first := inbound.EBPFKernelRuntimeDiagnostics()
	second := inbound.EBPFKernelRuntimeDiagnostics()
	if !first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatalf("observed at changed from %v to %v inside the cache window",
			first.ObservedAt, second.ObservedAt)
	}
	// An empty inbound owns nothing, and that has to be reported as an empty
	// result rather than a failure.
	if first.ProgramsError != "" {
		t.Fatalf("programs error = %q, want none", first.ProgramsError)
	}
	if len(first.Programs) != 0 || len(first.MapOccupancy.Maps) != 0 {
		t.Fatalf("kernel runtime = %+v, want nothing owned", first)
	}
}

// TestAdapterKernelRuntimeReportsProgramsAndMapsToOccupancy keeps the two
// independent sub-reports from being swapped: programs describe themselves and
// maps describe their own table, and the top-level status comes from the maps.
func TestAdapterKernelRuntimeReportsProgramsAndMapsToOccupancy(t *testing.T) {
	observedAt := time.Now()
	diagnostics := adapterKernelRuntime(observedAt, ebpf.RuntimeState{
		Programs: []ebpf.RuntimeProgram{
			{ID: 3, Name: "sb_tc_ingress", MapCount: 1, MapIDs: []CiliumEBPF.MapID{12}},
		},
		ProgramsError: errors.New("programs unavailable"),
		MapOccupancy: ebpf.MapOccupancyReport{
			Status: "warning",
			Maps: []ebpf.MapOccupancy{
				{ID: 12, Name: "sb_tcp_redirect", Type: "LRUHash", MaxEntries: 4096, Entries: 3800, Pressure: "warning", Supported: true},
			},
		},
	})
	if diagnostics.ProgramsError != "programs unavailable" {
		t.Fatalf("programs error = %q, want the propagated error", diagnostics.ProgramsError)
	}
	if len(diagnostics.Programs) != 1 || diagnostics.Programs[0].Name != "sb_tc_ingress" {
		t.Fatalf("programs = %+v, want one sb_tc_ingress", diagnostics.Programs)
	}
	if len(diagnostics.Programs[0].MapIDs) != 1 || diagnostics.Programs[0].MapIDs[0] != 12 {
		t.Fatalf("map ids = %v, want [12]", diagnostics.Programs[0].MapIDs)
	}
	if diagnostics.MapOccupancy.Status != "warning" {
		t.Fatalf("occupancy status = %q, want warning", diagnostics.MapOccupancy.Status)
	}
	if len(diagnostics.MapOccupancy.Maps) != 1 || diagnostics.MapOccupancy.Maps[0].Pressure != "warning" {
		t.Fatalf("maps = %+v, want one map at warning pressure", diagnostics.MapOccupancy.Maps)
	}
}
