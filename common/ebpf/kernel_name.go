//go:build with_ebpf && (linux || android)

package ebpf

import E "github.com/sagernet/sing/common/exceptions"

// Linux exposes BPF map/program names through a 16-byte field including the
// terminating NUL, so kernel-visible names may contain at most 15 bytes.
// Longer names are truncated silently by the kernel (bpf_map_create does a
// strncpy), which turns e.g. "sb_cg_bypass_port" into "sb_cg_bypass_po" in
// /proc/self/maps dumps, bpftool output and our own occupancy report.
const kernelObjectNameLimit = 15

func validateKernelObjectName(name string) error {
	if name == "" {
		return E.New("empty eBPF kernel object name")
	}
	if len(name) > kernelObjectNameLimit {
		return E.New("eBPF kernel object name ", name, " exceeds the ", kernelObjectNameLimit, "-byte limit")
	}
	return nil
}
