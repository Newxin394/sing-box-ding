package process

import (
	"context"
	"net/netip"
	"os/user"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type Searcher interface {
	FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error)
	ResetCache()
	Close() error
}

// OwnerSearcher resolves a socket to its owning uid without walking procfs.
//
// A searcher that can answer an owner-only question more cheaply than a full
// lookup implements this, and its result is what feeds the lazy resolver. The
// full lookup stays available for callers that need the executable path.
type OwnerSearcher interface {
	FindProcessInfoByOwner(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error)
}

// FindProcessInfoByOwner resolves the socket owner through the cheapest path
// the searcher offers.
func FindProcessInfoByOwner(searcher Searcher, ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	if ownerSearcher, isOwnerSearcher := searcher.(OwnerSearcher); isOwnerSearcher {
		return ownerSearcher.FindProcessInfoByOwner(ctx, network, source, destination)
	}
	return FindProcessInfo(searcher, ctx, network, source, destination)
}

var ErrNotFound = E.New("process not found")

type Config struct {
	Logger         log.ContextLogger
	PackageManager tun.PackageManager
	// NeedProcessPath gates the procfs scan that resolves a socket's inode into
	// the owning process's executable path. Rules matching on package_name,
	// user or user_id only need the socket's uid, which netlink diagnostics
	// already returns, so the scan is pure waste for them. Leave false unless a
	// process_name / process_path / process_path_regex rule exists.
	NeedProcessPath bool
}

func FindProcessInfo(searcher Searcher, ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	info, err := searcher.FindProcessInfo(ctx, network, source, destination)
	if err != nil {
		return nil, err
	}
	completeProcessInfo(info, nil)
	return info, nil
}

func completeProcessInfo(info *adapter.ConnectionOwner, packageManager tun.PackageManager) {
	if info.UserId != -1 && info.UserName == "" {
		osUser, _ := user.LookupId(F.ToString(info.UserId))
		if osUser != nil {
			info.UserName = osUser.Username
		}
	}
	if packageManager == nil || info.UserId == -1 {
		return
	}
	appID := uint32(info.UserId) % 100000
	var packageNames []string
	if sharedPackage, loaded := packageManager.SharedPackageByID(appID); loaded {
		packageNames = append(packageNames, sharedPackage)
	}
	if packages, loaded := packageManager.PackagesByID(appID); loaded {
		packageNames = append(packageNames, packages...)
	}
	info.PackageNames = common.Uniq(packageNames)
}
