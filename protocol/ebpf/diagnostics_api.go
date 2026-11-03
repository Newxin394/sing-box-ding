//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/ebpf"
)

// This file answers the cross-process diagnostics API. Until it existed, the
// only way to see an eBPF inbound's state was the Clash API's /ebpf endpoint
// or the startup log line -- both of which require being on the box and
// reaching the right port. The gRPC service needs a report it can serialize
// from another process, so the state has to travel as plain data with no
// kernel handles and no build-tag-dependent types on the wire side.

// kernelRuntimeCacheTTL bounds how often --deep can walk the kernel.
//
// Enumerating owned maps counts their keys, which is O(entries) per map, and a
// busy instance has tens of thousands of flow entries. A dashboard polling the
// deep report would put that cost on the data path, so the second and later
// calls inside the window answer from the previous walk. Five seconds is
// short enough that an operator watching after a config reload still sees the
// change, and long enough that a dashboards' refresh interval cannot stack
// walks.
const kernelRuntimeCacheTTL = 5 * time.Second

// EBPFRuntimeDiagnostics reports this inbound's interception state in the form
// the daemon's gRPC service serializes.
//
// Fields the fork does not compute are left zero rather than derived from a
// neighbouring field: a zero here means "this build does not report it", and
// the schema version says which fields a client may rely on. Everything this
// build does know -- attachments, recovery state, bypass policy versions, UDP
// accounting and counters -- is filled.
func (i *Inbound) EBPFRuntimeDiagnostics() adapter.EBPFRuntimeDiagnostics {
	diagnostics := i.Diagnostics()
	// ObservedAt is the one thing the internal report has no field for: it is
	// a property of the read, not of the inbound, and stamping it here keeps
	// Diagnostics itself free of a clock call.
	now := time.Now()
	runtimeDiagnostics := adapter.EBPFRuntimeDiagnostics{
		SchemaVersion: adapter.EBPFDiagnosticsSchemaVersion,
		ObservedAt:    now,
		Tag:           diagnostics.Tag,
		State:         diagnostics.State,

		LocalEnabled:          diagnostics.LocalEnabled,
		LocalDataPlane:        diagnostics.LocalDataPlane,
		SharedEnabled:         diagnostics.SharedEnabled,
		SharedDataPlane:       diagnostics.SharedDataPlane,
		FakeIPICMPReply:       diagnostics.FakeIPICMPReply,
		LastError:             diagnostics.LastError,
		LastErrorAt:           diagnostics.LastErrorAt,
		LastRecoveryAt:        diagnostics.LastRecoveryAt,
		RecoveryPending:       diagnostics.RecoveryPending,
		RecoveryUnrecoverable: diagnostics.RecoveryUnrecoverable,
		NextRetryAt:           diagnostics.NextRetryAt,

		UDPSessionCount: diagnostics.UDPSessionCount,
	}
	runtimeDiagnostics.Attachments = make([]adapter.EBPFAttachmentDiagnostics, 0, len(diagnostics.Attachments))
	for _, attachment := range diagnostics.Attachments {
		runtimeDiagnostics.Attachments = append(runtimeDiagnostics.Attachments, adapter.EBPFAttachmentDiagnostics{
			InterfaceName:  attachment.InterfaceName,
			InterfaceIndex: attachment.InterfaceIndex,
			Role:           attachment.Role,
			Framing:        attachment.Framing,
			Mechanism:      attachment.Mechanism,
			ICMPEchoReply:  attachment.FakeIPICMP,
		})
	}
	runtimeDiagnostics.UDPNAT = adapter.EBPFUDPNATDiagnostics{
		ActiveSessions:                 diagnostics.UDPNAT.ActiveSessions,
		CreatedSessions:                diagnostics.UDPNAT.CreatedSessions,
		CapacityEvictions:              diagnostics.UDPNAT.CapacityEvictions,
		QueueDrops:                     diagnostics.UDPNAT.QueueDrops,
		SocketReleaseEvents:            diagnostics.UDPNAT.SocketReleaseEvents,
		SocketReleaseMatched:           diagnostics.UDPNAT.SocketReleaseMatched,
		PendingReleaseCapacityRejected: diagnostics.UDPNAT.PendingReleaseCapacityRejected,
		ReleaseNotificationDrops:       diagnostics.UDPNAT.ReleaseNotificationDrops,
	}
	runtimeDiagnostics.UDPReplySockets = adapter.EBPFUDPReplySocketDiagnostics{
		Count:            diagnostics.UDPReplySockets.Count,
		Peak:             diagnostics.UDPReplySockets.Peak,
		Evicted:          diagnostics.UDPReplySockets.Evicted,
		CapacityRejected: diagnostics.UDPReplySockets.CapacityRejected,
	}
	runtimeDiagnostics.Counters = adapterCounters(diagnostics.Counters)

	// The fork keeps one bypass_rule_set list shared by all three backends,
	// where the parent's schema has a separate scope per data plane. The same
	// policy versions are therefore reported in both scopes: they are one
	// policy, and repeating its state under two names is the honest answer,
	// whereas putting the state in one scope only would imply the other is
	// unknown.
	localPolicy := adapterBypassRuleSetDiagnostics(diagnostics)
	runtimeDiagnostics.LocalBypassRuleSet = localPolicy
	runtimeDiagnostics.SharedBypassRuleSet = localPolicy
	if diagnostics.LocalEnabled || diagnostics.SharedEnabled {
		confirmed := diagnostics.BypassRuleSetPolicyVersion
		expected := diagnostics.BypassRuleSetExpectedPolicyVersion
		runtimeDiagnostics.PolicyEpoch = adapter.EBPFPolicyEpochDiagnostics{
			LocalConfirmed:  confirmed,
			LocalExpected:   expected,
			SharedConfirmed: confirmed,
			SharedExpected:  expected,
			Converged:       !diagnostics.BypassRuleSetPending && diagnostics.BypassRuleSetConsistent,
		}
	}
	runtimeDiagnostics.TCAttachmentCount = 0
	for _, attachment := range diagnostics.Attachments {
		if attachment.Mechanism == "tcx" || attachment.Mechanism == "clsact" {
			runtimeDiagnostics.TCAttachmentCount++
		}
	}
	i.tcDataPlaneAccess.RLock()
	tcDataPlane := i.tcDataPlane
	i.tcDataPlaneAccess.RUnlock()
	if tcDataPlane != nil {
		if backend := tcDataPlane.backend; backend != nil {
			runtimeDiagnostics.TCListenerLookupMode = backend.TCPListenerLookupMode()
			runtimeDiagnostics.TCRequiresRebuild = backend.RequiresRebuild()
		}
		switch {
		case tcDataPlane.delivery != nil:
			runtimeDiagnostics.TCAttachmentMode = "tcx"
		case len(tcDataPlane.attachments) > 0:
			// clsact is only ever used when TCX was unavailable for the
			// interface, which is exactly what a non-tcx attachment means.
			runtimeDiagnostics.TCAttachmentMode = "clsact"
		}
		runtimeDiagnostics.TCDeliveryInterface = tcDataPlane.deliveryName()
		runtimeDiagnostics.TCNetworkNamespace = tcDataPlane.deliveryName()
	}
	return runtimeDiagnostics
}

// EBPFKernelRuntimeDiagnostics enumerates the kernel programs and maps this
// inbound owns.
//
// The handles are snapshotted under each backend's own lock and the kernel walk
// happens outside them: a walk that counted keys while holding a backend lock
// would stall every reconcile behind it. Results are cached for
// kernelRuntimeCacheTTL for the cost reason documented on that constant.
func (i *Inbound) EBPFKernelRuntimeDiagnostics() adapter.EBPFKernelRuntimeDiagnostics {
	now := time.Now()
	i.kernelRuntimeAccess.Lock()
	defer i.kernelRuntimeAccess.Unlock()
	if !i.kernelRuntimeAt.IsZero() && now.Sub(i.kernelRuntimeAt) < kernelRuntimeCacheTTL {
		return i.kernelRuntimeValue
	}
	owners := make([]ebpf.RuntimeOwner, 0, 5)
	if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
		owners = append(owners, cgroupBackend)
	}
	if tcDataPlane := i.tcDataPlaneInstance(); tcDataPlane != nil {
		if backend := tcDataPlane.backend; backend != nil {
			// RuntimeResources on the TC backend also covers its
			// fakeip_icmp object, which the backend owns behind an
			// unexported field.
			owners = append(owners, backend)
		}
	}
	if i.selfBypass != nil {
		owners = append(owners, i.selfBypass)
	}
	if i.processTracker != nil {
		owners = append(owners, i.processTracker)
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			owners = append(owners, backend)
		}
	}
	diagnostics := adapterKernelRuntime(now, ebpf.InspectRuntimeResources(owners...))
	i.kernelRuntimeAt = now
	i.kernelRuntimeValue = diagnostics
	return diagnostics
}

// tcDataPlaneInstance reads i.tcDataPlane under its lock; Diagnostics already
// does this inline, and the kernel-runtime path needs the same read.
func (i *Inbound) tcDataPlaneInstance() *tcDataPlane {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	return i.tcDataPlane
}

func adapterKernelRuntime(observedAt time.Time, state ebpf.RuntimeState) adapter.EBPFKernelRuntimeDiagnostics {
	programs := make([]adapter.EBPFProgramDiagnostics, 0, len(state.Programs))
	for _, program := range state.Programs {
		mapIDs := make([]uint32, len(program.MapIDs))
		for index, mapID := range program.MapIDs {
			mapIDs[index] = uint32(mapID)
		}
		programs = append(programs, adapter.EBPFProgramDiagnostics{
			ID:       uint32(program.ID),
			Name:     program.Name,
			Type:     program.Type.String(),
			MapCount: program.MapCount,
			MapIDs:   mapIDs,
		})
	}
	maps := make([]adapter.EBPFMapDiagnostics, 0, len(state.MapOccupancy.Maps))
	for _, item := range state.MapOccupancy.Maps {
		maps = append(maps, adapter.EBPFMapDiagnostics{
			ID:         uint32(item.ID),
			Name:       item.Name,
			Type:       item.Type,
			MaxEntries: item.MaxEntries,
			KeySize:    item.KeySize,
			ValueSize:  item.ValueSize,
			Flags:      item.Flags,
			Entries:    item.Entries,
			Supported:  item.Supported,
			Error:      item.Error,
			Pressure:   item.Pressure,
		})
	}
	diagnostics := adapter.EBPFKernelRuntimeDiagnostics{
		ObservedAt: observedAt,
		Programs:   programs,
		MapOccupancy: adapter.EBPFMapOccupancyDiagnostics{
			Status: state.MapOccupancy.Status,
			Maps:   maps,
			Error:  state.MapOccupancy.Error,
		},
	}
	if state.ProgramsError != nil {
		diagnostics.ProgramsError = state.ProgramsError.Error()
	}
	return diagnostics
}

func adapterBypassRuleSetDiagnostics(diagnostics EBPFDiagnostics) adapter.EBPFBypassRuleSetDiagnostics {
	backendState := make(map[string]adapter.EBPFBypassRuleSetBackendState, len(diagnostics.BypassRuleSetBackendState))
	for name, state := range diagnostics.BypassRuleSetBackendState {
		backendState[name] = adapter.EBPFBypassRuleSetBackendState{Version: state.Version, Known: state.Known}
	}
	return adapter.EBPFBypassRuleSetDiagnostics{
		Consistent:            diagnostics.BypassRuleSetConsistent,
		Pending:               diagnostics.BypassRuleSetPending,
		PolicyVersion:         diagnostics.BypassRuleSetPolicyVersion,
		ExpectedPolicyVersion: diagnostics.BypassRuleSetExpectedPolicyVersion,
		RetryCount:            diagnostics.BypassRuleSetRetryCount,
		BackendState:          backendState,
	}
}

func adapterCounters(counters EBPFCounters) adapter.EBPFCounters {
	return adapter.EBPFCounters{
		AssignmentLookupFailures:      counters.AssignmentLookupFailures,
		TokenReservationFailures:      counters.TokenReservationFailures,
		RewriteFailures:               counters.RewriteFailures,
		SharedReconcileFailures:       counters.SharedReconcileFailures,
		RecoveryAttempts:              counters.RecoveryAttempts,
		RecoverySuccesses:             counters.RecoverySuccesses,
		RecoveryFailures:              counters.RecoveryFailures,
		FakeIPICMPReplies:             counters.FakeIPICMPReplies,
		FakeIPICMPPassThrough:         counters.FakeIPICMPPassThrough,
		FakeIPICMPRewriteFailureDrops: counters.FakeIPICMPRewriteFailureDrops,
	}
}

// sortedAttachmentNames is kept for callers that want a stable list of what an
// inbound is attached to without the full report.
func sortedAttachmentNames(diagnostics EBPFDiagnostics) []string {
	names := make([]string, 0, len(diagnostics.Attachments))
	for _, attachment := range diagnostics.Attachments {
		names = append(names, attachment.InterfaceName)
	}
	sort.Strings(names)
	return names
}
