//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestInstructionsAlwaysAllowAcceptsReturnOne(t *testing.T) {
	allow := asm.Instructions{
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
	if !instructionsAlwaysAllow(allow) {
		t.Fatal("a program that only returns 1 must be recognised as a pass-through")
	}
}

func TestInstructionsAlwaysAllowAcceptsVerifierZeroExtension(t *testing.T) {
	// Some architectures zero-extend after a 32-bit move; the verifier inserts
	// that itself, so the translated program is three instructions long.
	allow := asm.Instructions{
		asm.Mov.Imm(asm.R0, 1),
		asm.Mov.Reg32(asm.R0, asm.R0),
		asm.Return(),
	}
	if !instructionsAlwaysAllow(allow) {
		t.Fatal("the zero-extension the verifier inserts must not hide a pass-through")
	}
}

func TestInstructionsAlwaysAllowRejectsRealWork(t *testing.T) {
	cases := map[string]asm.Instructions{
		"load": {
			asm.LoadMem(asm.R0, asm.R1, 0, asm.Word),
			asm.Return(),
		},
		"store": {
			asm.StoreImm(asm.R1, 0, 1, asm.Word),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		"call": {
			asm.FnGetCurrentPidTgid.Call(),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		"branch": {
			asm.JEq.Imm(asm.R1, 0, "skip"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		"returns zero": {
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		"returns something else": {
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
		"no exit": {
			asm.Mov.Imm(asm.R0, 1),
		},
		"exit before the end": {
			asm.Return(),
			asm.Mov.Imm(asm.R0, 1),
		},
	}
	for name, instructions := range cases {
		if instructionsAlwaysAllow(instructions) {
			t.Fatalf("%s: expected the program to be kept", name)
		}
	}
}

func TestInstructionsAlwaysAllowRequiresKnownResult(t *testing.T) {
	// r0 is copied from the context argument, so the exit value is unknown.
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R0, asm.R1),
		asm.Return(),
	}
	if instructionsAlwaysAllow(instructions) {
		t.Fatal("a move from an unknown register must not count as returning 1")
	}
}

func TestNetdHookPinPrefixesExcludesSocketRelease(t *testing.T) {
	if _, present := netdHookPinPrefixes[CiliumEBPF.AttachCgroupInetSockRelease]; present {
		t.Fatal("netd's socket-release program does real accounting and must never be displaced")
	}
	for _, attachType := range []CiliumEBPF.AttachType{
		CiliumEBPF.AttachCGroupInet4Connect,
		CiliumEBPF.AttachCGroupInet6Connect,
		CiliumEBPF.AttachCGroupUDP4Sendmsg,
		CiliumEBPF.AttachCGroupUDP6Sendmsg,
		CiliumEBPF.AttachCGroupUDP4Recvmsg,
		CiliumEBPF.AttachCGroupUDP6Recvmsg,
	} {
		if netdHookPinPrefixes[attachType] == "" {
			t.Fatalf("%v: expected a pin prefix", attachType)
		}
	}
	if len(netdHookPinPrefixes) != 6 {
		t.Fatalf("expected six displaceable hooks, got %d", len(netdHookPinPrefixes))
	}
}

func TestDisplaceableCgroupOwnerRefusesMultipleOwners(t *testing.T) {
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCGroupInet4Connect, []link.AttachedProgram{
		{ID: 1},
		{ID: 2},
	})
	if displaced != nil || err != nil {
		t.Fatalf("a multi-program hook must not be touched: %v %v", displaced, err)
	}
}

func TestDisplaceableCgroupOwnerRefusesSocketRelease(t *testing.T) {
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCgroupInetSockRelease, []link.AttachedProgram{{ID: 1}})
	if displaced != nil || err != nil {
		t.Fatalf("the socket-release hook must not be touched: %v %v", displaced, err)
	}
}

func TestDisplaceableCgroupOwnerRefusesMultiProgramMode(t *testing.T) {
	original := queryCgroupHookFlags
	t.Cleanup(func() { queryCgroupHookFlags = original })
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) {
		return unix.BPF_F_ALLOW_MULTI, nil
	}
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCGroupInet4Connect, []link.AttachedProgram{{ID: 1}})
	if displaced != nil || err != nil {
		t.Fatalf("a hook already in multi-program mode is not a pass-through owner: %v %v", displaced, err)
	}
}

func TestDisplaceableCgroupOwnerRefusesUnreadableFlags(t *testing.T) {
	original := queryCgroupHookFlags
	t.Cleanup(func() { queryCgroupHookFlags = original })
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) {
		return 0, errors.New("query failed")
	}
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCGroupInet4Connect, []link.AttachedProgram{{ID: 1}})
	if displaced != nil || err != nil {
		t.Fatalf("without the hook flags the owner must be left alone: %v %v", displaced, err)
	}
}

func TestDisplaceableCgroupOwnerKeepsProgramThatDoesRealWork(t *testing.T) {
	originalFlags := queryCgroupHookFlags
	originalFind := findDisplaceableOwner
	t.Cleanup(func() {
		queryCgroupHookFlags = originalFlags
		findDisplaceableOwner = originalFind
	})
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) { return 0, nil }
	findDisplaceableOwner = func(CiliumEBPF.AttachType, CiliumEBPF.ProgramID, uint32) (*displacedCgroupOwner, error) {
		return nil, errCgroupOwnerHasEffect
	}
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCGroupInet4Connect, []link.AttachedProgram{{ID: 7}})
	if displaced != nil {
		t.Fatal("a program that does real work must not be displaced")
	}
	if !errors.Is(err, errCgroupOwnerHasEffect) {
		t.Fatalf("expected the kept-owner reason, got %v", err)
	}
}

func TestDisplaceableCgroupOwnerAcceptsSingleProgramMode(t *testing.T) {
	originalFlags := queryCgroupHookFlags
	originalFind := findDisplaceableOwner
	t.Cleanup(func() {
		queryCgroupHookFlags = originalFlags
		findDisplaceableOwner = originalFind
	})
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) { return 0, nil }
	expected := &displacedCgroupOwner{id: 9, flags: 0}
	findDisplaceableOwner = func(attachType CiliumEBPF.AttachType, ownerID CiliumEBPF.ProgramID, flags uint32) (*displacedCgroupOwner, error) {
		if attachType != CiliumEBPF.AttachCGroupInet4Connect || ownerID != 9 || flags != 0 {
			return nil, errors.New("unexpected arguments")
		}
		return expected, nil
	}
	displaced, err := displaceableCgroupOwner(0, CiliumEBPF.AttachCGroupInet4Connect, []link.AttachedProgram{{ID: 9}})
	if err != nil {
		t.Fatal(err)
	}
	if displaced != expected {
		t.Fatalf("expected the pass-through owner to be displaced, got %v", displaced)
	}
}

func TestDisplacedCgroupOwnerCloseIsIdempotent(t *testing.T) {
	var nilOwner *displacedCgroupOwner
	if err := nilOwner.Close(); err != nil {
		t.Fatalf("nil owner: %v", err)
	}
	if err := (&displacedCgroupOwner{}).Close(); err != nil {
		t.Fatalf("owner without a program: %v", err)
	}
}

func TestProgramHasIDTreatsUnreadableIDAsMatch(t *testing.T) {
	if !programHasID(nil, 5) {
		t.Fatal("a nil program is the owner by construction")
	}
}

func TestRestoreNetdOwnerForStaleProgramNeedsNetd(t *testing.T) {
	original := netdPresent
	t.Cleanup(func() { netdPresent = original })
	netdPresent = func() bool { return false }
	restored, err := restoreNetdOwnerForStaleProgram(0, CiliumEBPF.AttachCGroupInet4Connect, 0)
	if restored || err != nil {
		t.Fatalf("without netd the hook is reclaimed the usual way: %v %v", restored, err)
	}
}

func TestRestoreNetdOwnerForStaleProgramSkipsSocketRelease(t *testing.T) {
	original := netdPresent
	t.Cleanup(func() { netdPresent = original })
	netdPresent = func() bool { return true }
	restored, err := restoreNetdOwnerForStaleProgram(0, CiliumEBPF.AttachCgroupInetSockRelease, 0)
	if restored || err != nil {
		t.Fatalf("the socket-release hook is not taken over, so nothing is restored: %v %v", restored, err)
	}
}

func TestNewHookPlaceholderProgramReturnsAllow(t *testing.T) {
	// Loading a program needs privileges, so only the specification is checked
	// here: the placeholder must be the same "return 1" the verifier accepts as
	// a pass-through.
	spec := &CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameHookPlaceholder,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   CiliumEBPF.AttachCGroupInet4Connect,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	}
	if !instructionsAlwaysAllow(spec.Instructions) {
		t.Fatal("the placeholder must be recognised as a pass-through by our own check")
	}
}
