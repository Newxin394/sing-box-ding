//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

const (
	// cgroupRecoverySweepInterval is how often the UDP recovery table is
	// walked. The walk is bounded per pass, so a large table is drained over
	// several intervals instead of blocking startup.
	cgroupRecoverySweepInterval = 10 * time.Second
	// cgroupRecoveryMaxAge is the age past which a recovery entry cannot serve
	// a late packet any more. It matches the kernel UDP conntrack timeout: once
	// the flow mapping is gone, a packet can no longer be redirected to the
	// listener and recovery would never be consulted for it again.
	cgroupRecoveryMaxAge = 30 * time.Second
)

// startCgroupRecoverySweeper bounds the UDP recovery table in time.
//
// The table upstream is bounded by a kernel release notification delivered
// through a ring buffer. That needs loader support this fork's prebuilt
// objects do not have, so this sweeper is the userspace stand-in: it deletes
// entries older than cgroupRecoveryMaxAge on a fixed interval. Entries with an
// unknown timestamp are left alone (they predate timestamping, and deleting
// them would cut live flows).
//
// A second call before stopCgroupRecoverySweeper is a no-op.
func (i *Inbound) startCgroupRecoverySweeper(ctx context.Context) {
	if i.cgroupBackendInstance() == nil {
		return
	}
	i.recoverySweepAccess.Lock()
	if i.recoverySweepCancel != nil {
		i.recoverySweepAccess.Unlock()
		return
	}
	sweepCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	i.recoverySweepCancel = cancel
	i.recoverySweepDone = done
	i.recoverySweepAccess.Unlock()
	go i.runCgroupRecoverySweeper(sweepCtx, done)
}

// stopCgroupRecoverySweeper stops the sweep and waits for a pass in progress to
// finish. Safe to call when it was never started, and safe to call twice.
func (i *Inbound) stopCgroupRecoverySweeper() {
	i.recoverySweepAccess.Lock()
	cancel := i.recoverySweepCancel
	done := i.recoverySweepDone
	i.recoverySweepCancel = nil
	i.recoverySweepDone = nil
	i.recoverySweepAccess.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (i *Inbound) runCgroupRecoverySweeper(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(cgroupRecoverySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.sweepCgroupRecovery()
		}
	}
}

// recoverySweepHandledAnything reports whether a sweep pass ever deleted an
// entry. Used by tests to tell "nothing to do" from "not running".
func (i *Inbound) recoverySweepHandledAnything() bool {
	return i.recoverySweepHandled.Load() > 0
}

func (i *Inbound) sweepCgroupRecovery() {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	// Only LRU-fallback cleanup leaves entries behind forever; with a kernel
	// release hook the table is reclaimed by the hook, and sweeping would race
	// the kernel for no reason.
	if backend.UDPCleanupMode() != commonEBPF.UDPCleanupModeLRUFallback {
		return
	}
	stats, err := backend.SweepUDPRecoveryBudgeted(cgroupRecoveryMaxAge, time.Now(), 0)
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logger, "sweep cgroup eBPF UDP recovery state: ", err)
		return
	}
	if stats.Deleted > 0 {
		i.recoverySweepHandled.Add(uint64(stats.Deleted))
		i.logger.Trace(
			"eBPF cgroup UDP recovery sweep: scanned=", stats.Scanned,
			", deleted=", stats.Deleted,
			", max_age=", cgroupRecoveryMaxAge,
		)
	}
}
