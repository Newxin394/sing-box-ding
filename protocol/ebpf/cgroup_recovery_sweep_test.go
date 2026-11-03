//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestSweepUDPRecoveryBudgetedRejectsNonPositiveMaxAge(t *testing.T) {
	backend := &commonEBPF.CgroupBackend{}
	if _, err := backend.SweepUDPRecoveryBudgeted(0, time.Now(), 0); err == nil {
		t.Fatal("sweep with a zero max age should fail instead of deleting everything")
	}
	if _, err := backend.SweepUDPRecoveryBudgeted(-time.Second, time.Now(), 0); err == nil {
		t.Fatal("sweep with a negative max age should fail")
	}
}

func TestSweepUDPRecoveryBudgetedRejectsClosedBackend(t *testing.T) {
	var backend *commonEBPF.CgroupBackend
	if _, err := backend.SweepUDPRecoveryBudgeted(time.Minute, time.Now(), 0); err == nil {
		t.Fatal("sweep on a nil backend should fail")
	}
}

// A backend that has not been attached yet must not be swept: there is no map to
// walk, and getting an error here would pollute the warnings on every tick.
func TestInboundRecoverySweepWithoutBackendIsSilent(t *testing.T) {
	inbound := &Inbound{}
	inbound.sweepCgroupRecovery()
	if inbound.recoverySweepHandledAnything() {
		t.Fatal("sweep without a backend should do nothing")
	}
}

func TestInboundRecoverySweeperStopIsIdempotent(t *testing.T) {
	inbound := &Inbound{}
	inbound.stopCgroupRecoverySweeper()
	inbound.stopCgroupRecoverySweeper()
}

func TestInboundRecoverySweeperStartRequiresCgroupBackend(t *testing.T) {
	inbound := &Inbound{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbound.startCgroupRecoverySweeper(ctx)
	inbound.recoverySweepAccess.Lock()
	started := inbound.recoverySweepCancel != nil
	inbound.recoverySweepAccess.Unlock()
	if started {
		t.Fatal("sweeper should not start without a cgroup backend")
	}
}
