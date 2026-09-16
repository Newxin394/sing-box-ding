//go:build !with_ebpf || (!linux && !android)

package route

type ebpfSelfBypassState struct{} //nolint:unused // mirrors network_ebpf.go for non-eBPF builds
