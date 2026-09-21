package route

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/x/list"
)

// processPathWidener is implemented by process searchers that can start
// resolving process paths after construction. Only the Linux searcher gates the
// procfs walk; the Windows, Darwin and platform searchers always report paths.
type processPathWidener interface {
	SetNeedProcessPath()
}

// processPathHook remembers one rule-set registration so it can be undone.
type processPathHook struct {
	ruleSet  adapter.RuleSet
	callback *list.Element[adapter.RuleSetUpdateCallback]
}

// processPathState tracks the runtime widening of the procfs process-path scan.
//
// Whether the scan is needed is decided once, at start, from the static
// configuration and the metadata of every rule-set loaded at that point. A
// local rule-set can be reloaded later with content that introduces
// process_name, process_path or process_path_regex rules, and the metadata seen
// at start cannot know about them. Without the hooks below the scan stays off
// and those rules silently never match.
type processPathState struct {
	access sync.Mutex
	hooks  []processPathHook
	// widened records that a reload already asked for the scan, so repeated
	// reloads do not re-enter the widening path.
	widened bool
}

// startProcessPathWidening registers a hook on every rule-set so that a later
// reload introducing process path rules turns the procfs scan back on.
//
// It must run after needProcessPath has been finalized, otherwise the
// start-time value would overwrite a widening performed by a reload that raced
// startup.
func (r *Router) startProcessPathWidening() {
	if r.needProcessPath {
		// The scan is already unconditional; a reload cannot turn it off.
		return
	}
	r.processPath.access.Lock()
	defer r.processPath.access.Unlock()
	if len(r.processPath.hooks) > 0 || r.processPath.widened {
		return
	}
	// No IncRef here: only the metadata is read, and metadata survives the
	// rule cleanup that a zero reference count triggers.
	hooks := make([]processPathHook, 0, len(r.ruleSets))
	for _, ruleSet := range r.ruleSets {
		hooks = append(hooks, processPathHook{
			ruleSet:  ruleSet,
			callback: ruleSet.RegisterCallback(r.widenProcessPath),
		})
	}
	r.processPath.hooks = hooks
	// A reload may already have fired between the rule-set watcher starting and
	// this registration, in which case no callback saw it. Pick up whatever
	// metadata the rule-sets publish now.
	for _, hook := range hooks {
		r.widenProcessPathLocked(hook.ruleSet)
	}
}

// stopProcessPathWidening undoes startProcessPathWidening.
func (r *Router) stopProcessPathWidening() {
	r.processPath.access.Lock()
	defer r.processPath.access.Unlock()
	for _, hook := range r.processPath.hooks {
		hook.ruleSet.UnregisterCallback(hook.callback)
	}
	r.processPath.hooks = nil
}

// widenProcessPath runs from the rule-set reload path, possibly on a watcher
// goroutine, so it takes the lock before touching the widening state.
func (r *Router) widenProcessPath(ruleSet adapter.RuleSet) {
	r.processPath.access.Lock()
	defer r.processPath.access.Unlock()
	r.widenProcessPathLocked(ruleSet)
}

// widenProcessPathLocked requires processPath.access to be held.
func (r *Router) widenProcessPathLocked(ruleSet adapter.RuleSet) {
	if r.processPath.widened || !ruleSet.Metadata().ContainsProcessPathRule {
		return
	}
	r.processPath.widened = true
	r.needProcessPath = true
	if r.processSearcher == nil {
		// No searcher was created at start because nothing needed process
		// metadata then. Creating one here would race the lookup path, which
		// reads processSearcher without synchronization.
		r.logger.Warn("rule-set ", ruleSet.Name(), " now requires the process path scan, which needs a restart")
		return
	}
	if widener, isWidener := r.processSearcher.(processPathWidener); isWidener {
		widener.SetNeedProcessPath()
	}
	// Entries cached while the scan was off carry no process paths, so drop
	// them instead of serving an unresolved owner for up to the cache lifetime.
	if r.processCache != nil {
		r.processCache.Purge()
	}
}
