package adapter

// EBPFDiagnosticsSchemaVersion versions the shape of EBPFDiagnosticsResponse.
// Bump it whenever a field changes meaning, not merely when one is added.
const EBPFDiagnosticsSchemaVersion = 18

// EBPFDiagnosticsProvider is the no-build-tag surface the daemon uses to export
// eBPF inbound state over gRPC.
//
// The implementation lives behind the with_ebpf build tag, but its results are
// the plain structs in ebpf_diagnostics.go, so the daemon needs no build tag of
// its own. Inbounds that are not eBPF simply do not implement this interface.
type EBPFDiagnosticsProvider interface {
	// EBPFRuntimeDiagnostics returns this inbound's own state. Cheap enough for
	// ordinary polling.
	EBPFRuntimeDiagnostics() EBPFRuntimeDiagnostics
	// EBPFKernelRuntimeDiagnostics enumerates the programs and maps this process
	// owns. Expensive: only called for deep requests.
	EBPFKernelRuntimeDiagnostics() EBPFKernelRuntimeDiagnostics
}
