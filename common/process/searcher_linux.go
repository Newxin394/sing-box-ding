//go:build linux

package process

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

const (
	pathProc = "/proc"

	processPathsAllUsers = ^uint32(0)
)

var _ Searcher = (*linuxSearcher)(nil)

type linuxSearcher struct {
	logger           log.ContextLogger
	packageManager   tun.PackageManager
	diagConns        [4]*socketDiagConn
	processPathCache *freelru.Cache[uint32, *uidProcessPaths]
}

// uidProcessPaths holds one /proc scan, keyed by socket inode and grouped by the
// uid of the process holding it. The socket keeps the uid it was created with
// while /proc reflects the current uid of the process, so a socket created
// before a privilege drop is only reachable from a different uid. Keeping the
// uid alongside each entry lets a single scan answer both the exact match and
// the cross-user fallback, instead of rescanning /proc for the fallback.
type uidProcessPaths struct {
	entries map[uint32]map[uint32][]string
}

// lookup returns the paths holding targetInode, preferring processes running as
// uid and falling back to every uid when none of them matches.
func (u *uidProcessPaths) lookup(targetInode, uid uint32) ([]string, bool) {
	byUID, found := u.entries[targetInode]
	if !found {
		return nil, false
	}
	if paths, matched := byUID[uid]; matched {
		return paths, true
	}
	var merged []string
	for _, paths := range byUID {
		for _, path := range paths {
			if !slices.Contains(merged, path) {
				merged = append(merged, path)
			}
		}
	}
	if len(merged) == 0 {
		return nil, false
	}
	// Map iteration order is random, and the first path is the one reported to
	// the user, so keep the result stable across calls.
	slices.Sort(merged)
	return merged, true
}

func NewSearcher(config Config) (Searcher, error) {
	processPathCache := common.Must1(freelru.New[uint32, *uidProcessPaths](64, maphash.NewHasher[uint32]().Hash32, true))
	processPathCache.SetLifetime(time.Second)
	searcher := &linuxSearcher{
		logger:           config.Logger,
		packageManager:   config.PackageManager,
		processPathCache: processPathCache,
	}
	for _, family := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		for _, protocol := range []uint8{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			searcher.diagConns[socketDiagConnIndex(family, protocol)] = &socketDiagConn{
				family:   family,
				protocol: protocol,
				fd:       -1,
			}
		}
	}
	return searcher, nil
}

func (s *linuxSearcher) ResetCache() {
	s.processPathCache.Purge()
}

func (s *linuxSearcher) Close() error {
	var errs []error
	for _, conn := range s.diagConns {
		if conn == nil {
			continue
		}
		errs = append(errs, conn.Close())
	}
	return E.Errors(errs...)
}

func (s *linuxSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	inode, uid, err := s.resolveSocketByNetlink(network, source, destination)
	if err != nil {
		return nil, err
	}
	processInfo := &adapter.ConnectionOwner{
		UserId: int32(uid),
	}
	processPaths, err := s.findProcessPaths(inode, uid)
	if err != nil {
		s.logger.DebugContext(ctx, "find process path: ", err)
	} else {
		processInfo.ProcessPaths = processPaths
	}
	completeProcessInfo(processInfo, s.packageManager)
	return processInfo, nil
}

// FindProcessInfoByPID resolves process metadata without scanning socket file
// descriptors across procfs. The caller already established socket ownership.
func FindProcessInfoByPID(processID uint32, userID uint32, packageManager tun.PackageManager) (*adapter.ConnectionOwner, error) {
	processInfo := &adapter.ConnectionOwner{
		ProcessID: processID,
		UserId:    int32(userID),
	}
	processPath, err := os.Readlink(filepath.Join(pathProc, strconv.FormatUint(uint64(processID), 10), "exe"))
	if err == nil {
		processInfo.ProcessPaths = []string{processPath}
	}
	completeProcessInfo(processInfo, packageManager)
	return processInfo, err
}

func (s *linuxSearcher) resolveSocketByNetlink(network string, source netip.AddrPort, destination netip.AddrPort) (inode, uid uint32, err error) {
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	family, protocol, err := socketDiagSettings(network, source)
	if err != nil {
		return 0, 0, err
	}
	conn := s.diagConns[socketDiagConnIndex(family, protocol)]
	if conn == nil {
		return 0, 0, E.New("missing socket diag connection for family=", family, " protocol=", protocol)
	}
	if destination.IsValid() && source.Addr().BitLen() == destination.Addr().BitLen() {
		inode, uid, err = conn.query(source, destination)
		if err == nil {
			return inode, uid, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return 0, 0, err
		}
	}
	return dumpSocketDiag(family, protocol, source, destination)
}

// findProcessPaths resolves the processes holding targetInode. A single scan
// covers both the exact uid match and the cross-user fallback, so a cache miss
// walks /proc once instead of once per candidate uid.
func (s *linuxSearcher) findProcessPaths(targetInode, uid uint32) ([]string, error) {
	if cached, ok := s.processPathCache.Get(processPathsAllUsers); ok {
		if processPaths, found := cached.lookup(targetInode, uid); found {
			return processPaths, nil
		}
	}
	processPaths, err := buildProcessPaths()
	if err != nil {
		return nil, err
	}
	cached := &uidProcessPaths{entries: processPaths}
	s.processPathCache.Add(processPathsAllUsers, cached)
	if inodePaths, found := cached.lookup(targetInode, uid); found {
		return inodePaths, nil
	}
	return nil, E.New("process of uid(", uid, "), inode(", targetInode, ") not found")
}

// buildProcessPaths scans /proc once and indexes every socket inode it finds
// together with the uid of the process holding it.
func buildProcessPaths() (map[uint32]map[uint32][]string, error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, syscall.PathMax)
	processPaths := make(map[uint32]map[uint32][]string)
	for _, file := range files {
		if !file.IsDir() || !isPid(file.Name()) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		processUID := info.Sys().(*syscall.Stat_t).Uid
		processPath := filepath.Join(pathProc, file.Name())
		fdPath := filepath.Join(processPath, "fd")
		exePath, err := os.Readlink(filepath.Join(processPath, "exe"))
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			n, err := syscall.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(buffer[:n])
			if !ok {
				continue
			}
			byUID, loaded := processPaths[inode]
			if !loaded {
				byUID = make(map[uint32][]string)
				processPaths[inode] = byUID
			}
			if !slices.Contains(byUID[processUID], exePath) {
				byUID[processUID] = append(byUID[processUID], exePath)
			}
		}
	}
	return processPaths, nil
}

func isIgnorableProcError(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}

func parseSocketInode(link []byte) (uint32, bool) {
	const socketPrefix = "socket:["
	if len(link) <= len(socketPrefix) || string(link[:len(socketPrefix)]) != socketPrefix || link[len(link)-1] != ']' {
		return 0, false
	}
	var inode uint64
	for _, char := range link[len(socketPrefix) : len(link)-1] {
		if char < '0' || char > '9' {
			return 0, false
		}
		inode = inode*10 + uint64(char-'0')
		if inode > uint64(^uint32(0)) {
			return 0, false
		}
	}
	return uint32(inode), true
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}
