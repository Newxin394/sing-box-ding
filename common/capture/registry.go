package capture

import "sync"

// Registry stores capture owners by mode. It is intentionally independent of
// inbound manager internals so a future manager integration can register one
// TC owner and one TUN owner without making either protocol package import the
// other.
type Registry struct {
	access sync.RWMutex
	owners [3]Owner
}

func (r *Registry) Register(mode Mode, owner Owner) bool {
	if r == nil || !validMode(mode) || mode == ModeNone {
		return false
	}
	r.access.Lock()
	r.owners[mode] = owner
	r.access.Unlock()
	return true
}

func (r *Registry) Owner(mode Mode) Owner {
	if r == nil || !validMode(mode) {
		return nil
	}
	r.access.RLock()
	defer r.access.RUnlock()
	return r.owners[mode]
}

func (r *Registry) Snapshot() (tc Owner, tun Owner) {
	if r == nil {
		return nil, nil
	}
	r.access.RLock()
	defer r.access.RUnlock()
	return r.owners[ModeTC], r.owners[ModeTUN]
}
