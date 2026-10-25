//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestKernelObjectNameLimit(t *testing.T) {
	for _, testCase := range []struct {
		name string
		ok   bool
	}{
		{name: "sb_cg_byp_port", ok: true},
		{name: "123456789012345", ok: true},
		{name: "1234567890123456", ok: false},
		{name: "", ok: false},
	} {
		err := validateKernelObjectName(testCase.name)
		if (err == nil) != testCase.ok {
			t.Errorf("validateKernelObjectName(%q) = %v, want ok=%v", testCase.name, err, testCase.ok)
		}
	}
}
