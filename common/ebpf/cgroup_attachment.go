//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// lockCgroupFile takes the exclusive lock that marks this cgroup as managed
// here.
//
// A lock that is already held is still reported as EBUSY, so callers matching
// on it keep working, but it is described for what is known rather than what is
// likely. The holder may be another running instance, and it may equally be a
// handle this process itself has not let go of, because a close that could not
// detach every program keeps the cgroup open. Naming only the first would send
// the reader looking for a second process that need not exist.
func lockCgroupFile(cgroupFile *os.File) error {
	err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return E.Cause(unix.EBUSY,
			"the exclusive lock on this cgroup is already held, "+
				"either by another active instance or by an earlier close that did not finish: ",
			"lock cgroup")
	}
	return eBPFOperationError("lock cgroup", err)
}

func detachOwnedCgroupPrograms(cgroupFD int) error {
	for _, definition := range cgroupProgramDefinitions {
		if _, err := detachOwnedCgroupProgramsForAttach(cgroupFD, definition.attachType); err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease && socketReleaseUnavailable(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// detachOwnedCgroupProgramsForAttach removes only programs that belong to a
// sing-box eBPF generation. Older releases used the sing_ebpf_ prefix, while
// the current diagnostic names use sb_ebpf_. Never detach an unknown owner: the
// caller may be sharing the host cgroup with netd or another eBPF service.
func detachOwnedCgroupProgramsForAttach(cgroupFD int, attachType CiliumEBPF.AttachType) (bool, error) {
	first, err := queryCgroupProgramIDs(cgroupFD, attachType)
	if err != nil {
		return false, err
	}
	second, err := queryCgroupProgramIDs(cgroupFD, attachType)
	if err != nil {
		return false, err
	}
	if !sameProgramIDs(first, second) {
		return false, unix.ESTALE
	}
	var detached bool
	for _, programID := range first {
		name, nameErr := programNameByID(programID)
		if nameErr != nil {
			return detached, nameErr
		}
		if ownedCgroupProgramName(name) {
			program, openErr := newProgramFromID(programID)
			if openErr != nil {
				return detached, openErr
			}
			if detachErr := rawDetachProgram(cgroupFD, program, attachType); detachErr != nil {
				_ = program.Close()
				return detached, detachErr
			}
			detached = true
			if closeErr := program.Close(); closeErr != nil {
				return detached, closeErr
			}
		}
	}
	return detached, nil
}

func ownedCgroupProgramName(name string) bool {
	return strings.HasPrefix(name, "sb_ebpf_") || strings.HasPrefix(name, "sing_ebpf_")
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := queryCgroupPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

var queryCgroupPrograms = link.QueryPrograms

var newProgramFromID = CiliumEBPF.NewProgramFromID

var programNameByID = func(programID CiliumEBPF.ProgramID) (string, error) {
	program, err := newProgramFromID(programID)
	if err != nil {
		return "", err
	}
	info, infoErr := program.Info()
	closeErr := program.Close()
	if infoErr != nil {
		return "", infoErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return info.Name, nil
}

func cgroupProgramOwnerNames(result *link.QueryResult) ([]string, error) {
	owners := make([]string, 0, len(result.Programs))
	for _, attached := range result.Programs {
		name, err := programNameByID(attached.ID)
		if err != nil {
			return nil, err
		}
		if name == "" {
			name = fmt.Sprintf("program-%d", attached.ID)
		}
		owners = append(owners, name)
	}
	return owners, nil
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	attachOrder := make([]int, 0, cgroupProgramCount)
	if b.runtime.programs[cgroupProgramSocketRelease] != nil {
		attachOrder = append(attachOrder, cgroupProgramSocketRelease)
	}
	for slot := range b.runtime.programs {
		if slot != cgroupProgramSocketRelease {
			attachOrder = append(attachOrder, slot)
		}
	}
	for _, slot := range attachOrder {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programLink, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  cgroupFD,
			Program: program,
			Attach:  cgroupProgramDefinitions[slot].attachType,
		})
		if err == nil {
			b.runtime.links[slot] = programLink
		} else if cgroupLinkUnavailable(err) {
			err = attachProgramRaw(cgroupFD, program, cgroupProgramDefinitions[slot].attachType)
		}
		if err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF inbound", cgroupProgramDefinitions[slot].name, err)
		}
		b.runtime.attached[slot] = true
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported &&
		!b.runtime.attached[cgroupProgramSocketRelease] {
		_ = b.detachProgramsLocked()
		return eBPFOperationError("attach eBPF inbound UDP cleanup", unix.EINVAL)
	}
	return nil
}

func cgroupLinkUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		programLink := b.runtime.links[slot]
		var err error
		if programLink != nil {
			err = programLink.Close()
			b.runtime.links[slot] = nil
			b.runtime.attached[slot] = false
			if err != nil {
				detachErr = E.Errors(detachErr, err)
			}
			continue
		} else {
			err = rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		}
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}
