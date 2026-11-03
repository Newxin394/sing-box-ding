package adapter

import "time"

// The types below are the cross-process shape of one running eBPF inbound's
// state, as reported by GetEBPFDiagnostics. They carry no build tag and pull
// in nothing from the eBPF packages, so the daemon, the gRPC client and every
// platform build can name them.
//
// The provider side (protocol/ebpf, with_ebpf) produces the same JSON field
// names these marshal to, and daemon/started_service_ebpf.go converts between
// the two. Keeping the transport shape here rather than relying on JSON
// round-tripping means a renamed or dropped field is a compile error on both
// sides instead of a silent zero.

// EBPFKernelRuntimeDiagnostics is the process-wide view of the kernel objects
// this process owns: which programs are loaded and how full their maps are.
// Only enumerated for explicit deep requests, because reading it walks sysfs
// and every map.
type EBPFKernelRuntimeDiagnostics struct {
	ObservedAt    time.Time
	Programs      []EBPFProgramDiagnostics
	ProgramsError string
	MapOccupancy  EBPFMapOccupancyDiagnostics
}

// EBPFProgramDiagnostics identifies one loaded eBPF program.
type EBPFProgramDiagnostics struct {
	ID       uint32
	Name     string
	Type     string
	MapCount int
	MapIDs   []uint32
}

// EBPFMapOccupancyDiagnostics is the occupancy pass over the maps those
// programs use.
type EBPFMapOccupancyDiagnostics struct {
	Status string
	Maps   []EBPFMapDiagnostics
	Error  string
}

// EBPFMapDiagnostics is one map's capacity, current occupancy and pressure.
type EBPFMapDiagnostics struct {
	ID         uint32
	Name       string
	Category   string
	Type       string
	MaxEntries uint32
	KeySize    uint32
	ValueSize  uint32
	Flags      uint32
	Entries    uint32
	Supported  bool
	Error      string
	Pressure   string
}

// EBPFRuntimeDiagnostics is one running eBPF inbound's actual interception
// state, as distinct from the static kernel-capability probe
// `sing-box tools ebpf status` reports: answering "is this configured inbound
// intercepting traffic right now" needs a running instance, not just kernel
// support.
type EBPFRuntimeDiagnostics struct {
	SchemaVersion int
	ObservedAt    time.Time
	Tag           string
	State         string

	LocalEnabled                  bool
	LocalDataPlane                string
	LocalCgroupAttachMode         string
	LocalSelfBypassMode           string
	LocalSelfBypassCleanupMode    string
	LocalUDPCleanupMode           string
	LocalUDPUserspaceCleanupMode  string
	LocalUDPStorageMode           string
	LocalUDPTimeMode              string
	LocalUDPState                 string
	LocalUDPRecoveryMode          string
	LocalUDPMapPressure           string
	LocalUDPNetworkGeneration     uint32
	LocalUDPReleaseObserver       bool
	LocalUDPReleaseFallbackReason string
	LocalUDPReleaseProgram        string
	SharedEnabled                 bool
	SharedDataPlane               string
	FakeIPICMPReply               bool
	TCBackendMode                 string
	TCListenerLookupMode          string
	TCAttachmentMode              string
	TCDeliveryInterface           string
	TCNetworkNamespace            string
	TCDeliveryInterfaceIndex      int
	TCRoutingMark                 uint32
	TCRoutingTable                int
	TCRoutingPriority             int
	TCRoutingSlot                 int
	TCAttachmentCount             int
	TCRetiredAttachmentCount      int
	TCRetiredDeliveryCount        int
	TCRequiresRebuild             bool
	TCHealthStatus                string
	TCLastHealthCheckAt           *time.Time
	TCLastReconcileAt             *time.Time
	TCNetworkGeneration           uint64
	TCReturnSweepEntries          uint64
	TCReturnSweepCapacity         uint64
	TCReturnSweepScanned          uint64
	TCReturnSweepRemoved          uint64
	TCAssignmentSweepUsageKnown   bool
	TCReturnSweepUsageKnown       bool
	TCAssignmentSweepFailureMap   string
	TCAssignmentSweepScanned      uint64
	TCAssignmentSweepRemoved      uint64
	TCAssignmentSweepComplete     bool
	TCAssignmentSweepEntries      uint64
	TCAssignmentSweepCapacity     uint64
	TCAssignmentSweepPressure     bool
	TCAssignmentSweepRuns         uint64
	TCAssignmentSweepPartial      uint64
	TCAssignmentSweepFailure      string
	TCAssignmentSweepLastAt       *time.Time
	TCAssignmentSweepPartialAt    *time.Time
	CgroupRecoveryQueueOverflows  uint64
	CgroupRecoveryQueueOverflowAt *time.Time
	WaitingRoles                  []string
	WaitingInterfaces             []string

	Attachments []EBPFAttachmentDiagnostics

	// LastError and LastErrorAt are the most recent warning recorded across
	// every category this inbound logs through -- whichever happened most
	// recently, even if its own log line was rate-limited into silence.
	LastError   string
	LastErrorAt *time.Time
	// LastRecoveryAt is when a general-TC or shared-packet-rewrite failure
	// most recently cleared on its own.
	LastRecoveryAt *time.Time
	// RecoveryPending is whether the interface monitor currently has an
	// outstanding retry for general TC state or shared packet-rewrite.
	RecoveryPending bool
	// RecoveryUnrecoverable is whether general TC state or shared
	// packet-rewrite last reported itself unrecoverable. Unlike
	// RecoveryPending, no retry is outstanding for this: State reports
	// needs_attention for it unconditionally.
	RecoveryUnrecoverable bool
	// NextRetryAt is when the interface monitor's retry timer is next armed
	// across all of its components -- nil when nothing is outstanding.
	NextRetryAt *time.Time

	LocalBypassRuleSet  EBPFBypassRuleSetDiagnostics
	SharedBypassRuleSet EBPFBypassRuleSetDiagnostics
	PolicyEpoch         EBPFPolicyEpochDiagnostics

	// UDPSessionCount counts distinct UDP clients (by source address:port)
	// summed across every data plane that keeps its own client table.
	UDPSessionCount int
	UDPNAT          EBPFUDPNATDiagnostics
	UDPReplySockets EBPFUDPReplySocketDiagnostics

	Counters EBPFCounters
}

// EBPFPolicyEpochDiagnostics makes the two independently updated policy
// scopes explicit. A single scalar generation would be misleading because a
// local update can succeed while a shared update is still pending.
type EBPFPolicyEpochDiagnostics struct {
	LocalConfirmed  uint64
	LocalExpected   uint64
	SharedConfirmed uint64
	SharedExpected  uint64
	Converged       bool
}

// EBPFAttachmentDiagnostics describes one place this inbound is actually
// intercepting traffic right now: a TC attachment on a network interface, or
// (Mechanism == "cgroup") the cgroup local data plane, which has no
// per-interface attachment of its own.
type EBPFAttachmentDiagnostics struct {
	InterfaceName  string
	InterfaceIndex int
	Role           string
	Framing        string
	Mechanism      string
	ICMPEchoReply  bool
	Slot           int
}

// EBPFBypassRuleSetDiagnostics is one policy scope's bypass_rule_set state.
type EBPFBypassRuleSetDiagnostics struct {
	Consistent            bool
	Pending               bool
	PolicyVersion         uint64
	ExpectedPolicyVersion uint64
	RetryCount            uint64
	BackendState          map[string]EBPFBypassRuleSetBackendState
}

// EBPFBypassRuleSetBackendState is one backend's own confirmed position in a
// path-scoped bypass_rule_set policy version sequence.
type EBPFBypassRuleSetBackendState struct {
	Version uint64
	Known   bool
}

// EBPFUDPNATDiagnostics reports event-driven userspace UDP NAT state.
type EBPFUDPNATDiagnostics struct {
	ActiveSessions                 int
	CreatedSessions                uint64
	CapacityEvictions              uint64
	QueueDrops                     uint64
	SocketReleaseEvents            uint64
	SocketReleaseMatched           uint64
	PendingReleaseCapacityRejected uint64
	ReleaseNotificationDrops       uint64
}

// EBPFUDPReplySocketDiagnostics is the transparent reply-socket pool.
type EBPFUDPReplySocketDiagnostics struct {
	Count            int64
	Peak             int64
	Evicted          int64
	CapacityRejected int64
}

// EBPFCounters is the packet-path counter set. A counter is 0 when the path
// that would increment it is not configured, not necessarily because nothing
// ever failed.
type EBPFCounters struct {
	AssignmentLookupFailures      uint64
	TCSocketLookupFailures        uint64
	TCSKAssignFailures            uint64
	TCAssignmentUpdateFailures    uint64
	TCReturnUpdateFailures        uint64
	TCReturnConflicts             uint64
	TCReturnLookupFailures        uint64
	TCLocalFragmentPasses         uint64
	TCSharedFragmentPasses        uint64
	TokenReservationFailures      uint64
	RewriteFailures               uint64
	SharedIngressFragmentPasses   uint64
	SharedEgressFragmentPasses    uint64
	SharedReconcileFailures       uint64
	RecoveryAttempts              uint64
	RecoverySuccesses             uint64
	RecoveryFailures              uint64
	FakeIPICMPReplies             uint64
	FakeIPICMPPassThrough         uint64
	FakeIPICMPRewriteFailureDrops uint64
}
