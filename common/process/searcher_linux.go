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
	"sync"
	"sync/atomic"
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

	// processPathCacheLifetime bounds how long a /proc snapshot stays usable.
	// Building one walks every fd of every process in procfs, so the lifetime
	// must outlast the rescan interval by a wide margin; otherwise a snapshot
	// expires before it can serve a single lookup.
	processPathCacheLifetime = time.Minute

	// processPathRescanInterval is the shortest gap allowed between two full
	// rebuilds of the snapshot under a single cache key. A new connection
	// always carries an inode the current snapshot cannot contain, so
	// rebuilding on every miss degenerates into a continuous procfs walk
	// whenever short-lived sockets arrive in bursts (DNS queries being the
	// worst case). The cost of throttling is that a freshly started process
	// stays unresolved for up to this interval.
	processPathRescanInterval = 10 * time.Second
)

var _ Searcher = (*linuxSearcher)(nil)

type linuxSearcher struct {
	logger         log.ContextLogger
	packageManager tun.PackageManager
	// needProcessPath is atomic because SetNeedProcessPath can widen it from a
	// rule-set reload callback while lookups run concurrently.
	needProcessPath  atomic.Bool
	diagConns        [4]*socketDiagConn
	processPathCache *freelru.Cache[uint32, *uidProcessPaths]
	// rebuildAccess serializes the full rebuild so a burst of concurrent misses
	// performs one walk instead of one per caller: without it, N requests
	// arriving together all see a missing or stale snapshot and each start its
	// own full /proc walk, which is what made concurrency cost many times more
	// than the serialized case.
	rebuildAccess sync.Mutex
}

// uidProcessPaths holds one /proc scan, keyed by socket inode.
type uidProcessPaths struct {
	entries map[uint32][]string
	builtAt time.Time
}

// lookup returns the paths holding targetInode.
func (u *uidProcessPaths) lookup(targetInode uint32) ([]string, bool) {
	paths, found := u.entries[targetInode]
	return paths, found
}

func NewSearcher(config Config) (Searcher, error) {
	processPathCache := common.Must1(freelru.New[uint32, *uidProcessPaths](64, maphash.NewHasher[uint32]().Hash32, true))
	processPathCache.SetLifetime(processPathCacheLifetime)
	searcher := &linuxSearcher{
		logger:           config.Logger,
		packageManager:   config.PackageManager,
		processPathCache: processPathCache,
	}
	searcher.needProcessPath.Store(config.NeedProcessPath)
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

// SetNeedProcessPath widens the procfs gate at runtime.
//
// Whether the walk is needed is decided once at start, from the static
// configuration plus the metadata of every rule-set that had been loaded at
// that point. A rule-set reloaded afterwards can introduce process_path rules
// that were absent from that metadata, and without widening here the walk stays
// off and those rules can never match. It only ever enables the walk, so
// repeated calls are harmless.
func (s *linuxSearcher) SetNeedProcessPath() {
	if s.needProcessPath.Swap(true) {
		return
	}
	// The cache may hold snapshots built for a different target inode under the
	// throttled regime, so drop them rather than let a stale snapshot answer.
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
	// Resolving the inode into an executable path walks every fd of every
	// process in procfs, which is by far the most expensive step here. The uid
	// above already answers package_name, user and user_id rules, so skip the
	// walk entirely when no rule needs a path.
	if s.needProcessPath.Load() {
		processPaths, err := s.findProcessPaths(inode, uid)
		if err != nil {
			s.logger.DebugContext(ctx, "find process path: ", err)
		} else {
			processInfo.ProcessPaths = processPaths
		}
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

// findProcessPaths resolves the processes holding targetInode.
//
// The cached snapshot is consulted first and is rebuilt at most once per
// rescan interval, because every new socket carries an inode no existing
// snapshot can contain and rebuilding per miss turns short-lived traffic (DNS
// being the worst case) into a continuous procfs walk.
//
// Rebuilds are serialized, so a burst of concurrent misses shares one walk
// rather than starting one each, and the walk itself is cheap for the common
// case: it fills the uid table first and abandons the rest of /proc as soon as
// that table answers, which is the case whenever the socket belongs to the
// process that created it.
func (s *linuxSearcher) findProcessPaths(targetInode, uid uint32) ([]string, error) {
	// Consult the caller's uid snapshot first, then the all-users snapshot.
	// The uid snapshot holds the owning process, and the all-users snapshot
	// additionally holds processes sharing the same socket.
	if cached, ok := s.processPathCache.Get(uid); ok {
		if processPaths, found := cached.lookup(targetInode); found {
			return processPaths, nil
		}
	}
	if cached, ok := s.processPathCache.Get(processPathsAllUsers); ok {
		if processPaths, found := cached.lookup(targetInode); found {
			return processPaths, nil
		}
	}
	s.rebuildAccess.Lock()
	defer s.rebuildAccess.Unlock()
	// Another caller may have completed the walk while we waited. A fresh
	// snapshot under either key throttles the rebuild: every new socket
	// carries an inode no snapshot can contain, and rebuilding per miss
	// degenerates into a continuous procfs walk on short-lived traffic.
	throttled := false
	for _, key := range []uint32{uid, processPathsAllUsers} {
		if cached, ok := s.processPathCache.Get(key); ok {
			if now := time.Now(); now.Sub(cached.builtAt) < processPathRescanInterval {
				throttled = true
				if processPaths, found := cached.lookup(targetInode); found {
					return processPaths, nil
				}
			}
		}
	}
	if throttled {
		return nil, E.New("process of uid(", uid, "), inode(", targetInode, ") not found")
	}
	uidPaths, allPaths, err := buildProcessPaths(targetInode, uid)
	if err != nil {
		return nil, err
	}
	if processPaths, found := uidPaths[targetInode]; found {
		// Cache the uid table so the next socket owned by this uid hits the
		// snapshot instead of walking /proc again. The table is complete for
		// this uid: non-owning processes are skipped for allPaths, not for
		// uidPaths.
		s.processPathCache.Add(uid, &uidProcessPaths{entries: uidPaths, builtAt: time.Now()})
		return processPaths, nil
	}
	cached := &uidProcessPaths{entries: allPaths, builtAt: time.Now()}
	s.processPathCache.Add(processPathsAllUsers, cached)
	if processPaths, found := cached.lookup(targetInode); found {
		return processPaths, nil
	}
	return nil, E.New("process of uid(", uid, "), inode(", targetInode, ") not found")
}

// buildProcessPaths walks /proc once for both tables: processes owned by uid,
// and every process.
//
// Filling the all-users table costs the exe and fd reads of processes we do not
// own, so it is abandoned as soon as the uid table holds targetInode: from that
// point the fallback can never be consulted, and the all-users table is then
// partial. When the uid table misses, no process was ever skipped, so the
// all-users table is complete and safe to cache.
func buildProcessPaths(targetInode, uid uint32) (uidPaths map[uint32][]string, allPaths map[uint32][]string, err error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return nil, nil, err
	}
	uidPaths = make(map[uint32][]string)
	allPaths = make(map[uint32][]string)
	buffer := make([]byte, syscall.PathMax)
	for _, file := range files {
		if !file.IsDir() || !isPid(file.Name()) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, nil, err
		}
		ownedByUID := info.Sys().(*syscall.Stat_t).Uid == uid
		if !ownedByUID {
			if _, matched := uidPaths[targetInode]; matched {
				continue
			}
		}
		processPath := filepath.Join(pathProc, file.Name())
		fdPath := filepath.Join(processPath, "fd")
		exePath, err := os.Readlink(filepath.Join(processPath, "exe"))
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, nil, err
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
			if ownedByUID && !slices.Contains(uidPaths[inode], exePath) {
				uidPaths[inode] = append(uidPaths[inode], exePath)
			}
			if !slices.Contains(allPaths[inode], exePath) {
				allPaths[inode] = append(allPaths[inode], exePath)
			}
		}
	}
	if _, matched := uidPaths[targetInode]; matched {
		allPaths = nil
	}
	return uidPaths, allPaths, nil
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
