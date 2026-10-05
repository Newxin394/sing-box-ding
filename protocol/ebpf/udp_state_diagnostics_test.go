//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

// TestUDPStateDiagnosticsReportsLiveCounters proves the UDP diagnostic block
// reports values the data plane actually maintains, not placeholders: the
// reply socket pool counters move when the pool is used.
func TestUDPStateDiagnosticsReportsLiveCounters(t *testing.T) {
	inbound := &Inbound{}
	initial := inbound.udpStateDiagnostics()
	if initial == nil {
		t.Fatal("udpStateDiagnostics returned nil")
	}
	if initial.ReplySocketCount != 0 {
		t.Fatalf("fresh pool reply socket count = %d, want 0", initial.ReplySocketCount)
	}
	if initial.ReplySocketCapacity != inbound.udpReplySockets.socketCapacity() {
		t.Fatalf("reply socket capacity = %d, want %d", initial.ReplySocketCapacity, inbound.udpReplySockets.socketCapacity())
	}
	if initial.DataPlane != "disabled" {
		t.Fatalf("data plane = %q, want disabled for an inbound with no data plane configured", initial.DataPlane)
	}

	_, release, err := inbound.udpReplySockets.get(
		destinationOnShard(&inbound.udpReplySockets, 0, 0),
		newLoopbackUDPSocket,
	)
	if err != nil {
		t.Fatalf("get reply socket: %v", err)
	}
	release()
	after := inbound.udpStateDiagnostics()
	if after.ReplySocketCount != 1 {
		t.Fatalf("reply socket count = %d after one pooled socket, want 1", after.ReplySocketCount)
	}
	if after.ReplySocketPeak < 1 {
		t.Fatalf("reply socket peak = %d, want at least 1", after.ReplySocketPeak)
	}
	if after.ReplySocketPressure != "healthy" {
		t.Fatalf("reply socket pressure = %q, want healthy at 1/4096", after.ReplySocketPressure)
	}
	_ = inbound.udpReplySockets.close()
}

// TestUDPDataPlaneNamePrefersSharedRewrite pins the naming rule: forwarded
// hotspot UDP is carried by shared packet rewrite when it is configured, so
// it must not be reported as the local path.
func TestUDPDataPlaneNamePrefersSharedRewrite(t *testing.T) {
	inbound := &Inbound{}
	if got := inbound.udpDataPlaneName(); got != "disabled" {
		t.Fatalf("no data plane name = %q, want disabled", got)
	}
	inbound.localEnabled = true
	inbound.localDataPlane = "cgroup"
	if got := inbound.udpDataPlaneName(); got != "cgroup" {
		t.Fatalf("local cgroup name = %q, want cgroup", got)
	}
	inbound.localDataPlane = "tc"
	if got := inbound.udpDataPlaneName(); got != "tc" {
		t.Fatalf("local tc name = %q, want tc", got)
	}
	inbound.sharedEnabled = true
	inbound.sharedDataPlane = sharedDataPlanePacketRewrite
	inbound.setSharedRewrite(&sharedRewrite{})
	t.Cleanup(func() { inbound.setSharedRewrite(nil) })
	if got := inbound.udpDataPlaneName(); got != sharedDataPlanePacketRewrite {
		t.Fatalf("shared rewrite name = %q, want %q", got, sharedDataPlanePacketRewrite)
	}
}
