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
// The table is written by the kernel release hook and is an LRU map, so without
// a delete path an entry only leaves when unrelated traffic evicts it -- which
// can just as well evict an entry a late packet still needs. Upstream deletes
// at an exact deadline from a ring buffer notification; this fork walks the
// table on a fixed interval and deletes entries older than
// cgroupRecoveryMaxAge. Entries with an unknown timestamp are left alone (they
// predate the release stamp, and deleting them would cut live flows).
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
	i.sweepCgroupRecoveryBudgeted(cgroupRecoveryMaxAge, 0)
}

// sweepCgroupRecoveryBudgeted is the sweep both the fixed-interval loop and the
// pressure-driven maintenance loop share: the only difference between them is
// how often they ask and how many entries one pass may walk.
func (i *Inbound) sweepCgroupRecoveryBudgeted(maxAge time.Duration, budget uint32) (commonEBPF.RecoverySweepStats, error) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return commonEBPF.RecoverySweepStats{}, nil
	}
	// The recovery table is written by the kernel release hook in both cleanup
	// modes: the mode only decides whether the redirect and token maps are Hash
	// (exact reclaim) or LRU (fallback). Nothing else removes a recovery entry
	// except a late packet consuming it, so leaving the sweep off in
	// socket_release mode would let the LRU map fill up and evict entries that
	// are still needed. Only warn when entries actually outlive the age bound
	// past the kernel timeout.
	switch backend.UDPCleanupMode() {
	case commonEBPF.UDPCleanupModeLRUFallback, commonEBPF.UDPCleanupModeSocketRelease:
	default:
		return commonEBPF.RecoverySweepStats{}, nil
	}
	// The kernel stamps entries with CLOCK_MONOTONIC; reading the wall clock
	// here would drift with NTP steps and either keep stale entries or expire
	// live ones after a clock jump.
	nowNS, err := commonEBPF.MonotonicNanoseconds()
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logger, "read monotonic clock for cgroup eBPF UDP recovery sweep: ", err)
		return commonEBPF.RecoverySweepStats{}, err
	}
	stats, err := backend.SweepUDPRecoveryBudgeted(maxAge, nowNS, budget)
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logger, "sweep cgroup eBPF UDP recovery state: ", err)
		return commonEBPF.RecoverySweepStats{}, err
	}
	if stats.Deleted > 0 {
		i.recoverySweepHandled.Add(uint64(stats.Deleted))
		i.logger.Trace(
			"eBPF cgroup UDP recovery sweep: scanned=", stats.Scanned,
			", deleted=", stats.Deleted,
			", max_age=", maxAge,
		)
	}
	return stats, nil
}
