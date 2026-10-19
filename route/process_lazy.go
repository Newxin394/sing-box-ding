package route

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
)

// ProcessLookupMode selects how a socket is resolved to its owner.
//
// Owner asks for the uid only and must never walk procfs; it answers
// package_name, user and user_id rules. Full additionally resolves the
// executable path for process_name and process_path rules.
type ProcessLookupMode uint8

const (
	ProcessLookupOwner ProcessLookupMode = iota
	ProcessLookupFull
)

// resolveProcessInfoFull upgrades an owner-only result to one carrying
// executable paths. It is only reachable from ResolveProcessInfo, so a
// configuration without process_path rules never pays for the walk.
func (r *Router) resolveProcessInfoFull(ctx context.Context, metadata *adapter.InboundContext, mode ProcessLookupMode) *adapter.ConnectionOwner {
	if mode != ProcessLookupOwner || r.processSearcher == nil {
		return metadata.ProcessInfo
	}
	var originDestination netip.AddrPort
	if metadata.OriginDestination.IsValid() {
		originDestination = metadata.OriginDestination.AddrPort()
	} else if metadata.Destination.IsIP() {
		originDestination = metadata.Destination.AddrPort()
	}
	processInfo, err := r.findProcessInfoCached(ctx, ProcessLookupFull, metadata.Network, metadata.Source.AddrPort(), originDestination)
	if err != nil {
		r.logger.DebugContext(ctx, "resolve process path: ", err)
		return metadata.ProcessInfo
	}
	return processInfo
}
