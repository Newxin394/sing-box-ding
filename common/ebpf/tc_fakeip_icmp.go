//go:build with_ebpf && (linux || android)

package ebpf

import (
	CiliumEBPF "github.com/cilium/ebpf"
)

// This file is TCBackend's thin delegation to FakeIPICMPBackend (see
// fakeip_icmp_backend.go for the object itself and why it is a standalone
// backend rather than fields inline on TCBackend). TCBackend's own public
// API here is unchanged from before that extraction, so protocol/ebpf's
// callers needed no changes: FakeIPICMPEnabled, the program accessors, and
// prepareTC's population of b.fakeIPICMP (in tc.go) are the only places
// that know FakeIPICMPBackend exists underneath.

// FakeIPICMPEnabled reports whether this backend loaded the fakeip_icmp
// object. protocol/ebpf's TC data plane uses this to decide whether to
// attach the extra local/shared reply filters at all.
func (b *TCBackend) FakeIPICMPEnabled() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPICMP != nil
}

func (b *TCBackend) FakeIPICMPLocalReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.LocalReplyProgramFD(framing)
}

func (b *TCBackend) FakeIPICMPLocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.LocalReplyProgram(framing)
}

func (b *TCBackend) FakeIPICMPSharedReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.SharedReplyProgramFD(framing)
}

func (b *TCBackend) FakeIPICMPSharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.SharedReplyProgram(framing)
}

// RuntimeResources reports the TC backend's kernel programs and maps, and the
// fakeip_icmp object it loaded if it loaded one.
//
// It copies handles only, under the backend lock, and leaves the kernel walk to
// the caller: enumerating by ID is slow and must not run while a reconcile is
// waiting for this lock. The fakeip_icmp object is folded in here because the
// backend owns it behind an unexported field, which is the only reason this
// method is not simply runtimeResourcesLocked's wrapper in
// runtime_resources_backends.go.
func (b *TCBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	resources := b.runtimeResourcesLocked()
	fakeIPICMP := b.fakeIPICMP.runtimeResourcesLocked()
	resources.Programs = append(resources.Programs, fakeIPICMP.Programs...)
	resources.Maps = append(resources.Maps, fakeIPICMP.Maps...)
	return resources
}

func (b *TCBackend) fakeIPICMPBackend() *FakeIPICMPBackend {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPICMP
}

// FakeIPICMPReplyCount, FakeIPICMPPassThroughCount, and
// FakeIPICMPRewriteFailureCount delegate to the underlying FakeIPICMPBackend's
// own counters (see that type's doc comments); each reports errBackendClosed
// if fakeip_icmp was never enabled on this backend.
func (b *TCBackend) FakeIPICMPReplyCount() (uint64, error) {
	return b.fakeIPICMPBackend().ReplyCount()
}

func (b *TCBackend) FakeIPICMPPassThroughCount() (uint64, error) {
	return b.fakeIPICMPBackend().PassThroughCount()
}

func (b *TCBackend) FakeIPICMPRewriteFailureCount() (uint64, error) {
	return b.fakeIPICMPBackend().RewriteFailureCount()
}
