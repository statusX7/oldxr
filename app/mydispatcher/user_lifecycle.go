package mydispatcher

import (
	"sync"
	"sync/atomic"
)

type userFlowRuntime struct {
	active atomic.Int64
}

func (r *userFlowRuntime) acquire() {
	r.active.Add(1)
}

func (r *userFlowRuntime) release() {
	for {
		active := r.active.Load()
		if active <= 0 {
			return
		}
		if r.active.CompareAndSwap(active, active-1) {
			return
		}
	}
}

type managedUserNode struct {
	current map[string]struct{}
	runtime map[string]*userFlowRuntime
}

type userFlowRegistry struct {
	mu    sync.Mutex
	nodes map[string]*managedUserNode
}

func (r *userFlowRegistry) node(tag string) *managedUserNode {
	if r.nodes == nil {
		r.nodes = make(map[string]*managedUserNode)
	}
	node := r.nodes[tag]
	if node == nil {
		node = &managedUserNode{
			current: make(map[string]struct{}),
			runtime: make(map[string]*userFlowRuntime),
		}
		r.nodes[tag] = node
	}
	return node
}

func (r *userFlowRegistry) register(tag string, emails []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := r.node(tag)
	for _, email := range emails {
		node.current[email] = struct{}{}
		if node.runtime[email] == nil {
			node.runtime[email] = new(userFlowRuntime)
		}
	}
}

func (r *userFlowRegistry) retire(tag string, emails []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := r.node(tag)
	for _, email := range emails {
		delete(node.current, email)
		if node.runtime[email] == nil {
			node.runtime[email] = new(userFlowRuntime)
		}
	}
}

func (r *userFlowRegistry) acquire(tag, email string) (*userFlowRuntime, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := r.nodes[tag]
	if node == nil {
		// Inbounds not managed by a panel controller retain the legacy behavior.
		runtime := new(userFlowRuntime)
		runtime.acquire()
		return runtime, true
	}
	if _, ok := node.current[email]; !ok {
		return nil, false
	}
	runtime := node.runtime[email]
	if runtime == nil {
		runtime = new(userFlowRuntime)
		node.runtime[email] = runtime
	}
	runtime.acquire()
	return runtime, true
}

func (r *userFlowRegistry) finalize(tag, email string, cleanup func() bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := r.nodes[tag]
	if node == nil {
		return false
	}
	if _, current := node.current[email]; current {
		return false
	}
	runtime := node.runtime[email]
	if runtime == nil || runtime.active.Load() != 0 {
		return false
	}
	if !cleanup() {
		return false
	}
	delete(node.runtime, email)
	return true
}

// RegisterManagedUsers publishes users that may acquire a new data-path flow.
// It is called before the corresponding runtime credentials become visible.
func (d *DefaultDispatcher) RegisterManagedUsers(tag string, emails []string) {
	d.userFlows.register(tag, emails)
}

// RetireManagedUsers prevents new flows while existing flows retain their
// traffic handles until they close.
func (d *DefaultDispatcher) RetireManagedUsers(tag string, emails []string) {
	d.userFlows.retire(tag, emails)
}

// FinalizeRetiredUser removes counters only after admission is closed and the
// last data-path flow has released its connection reference.
func (d *DefaultDispatcher) FinalizeRetiredUser(tag, email string) bool {
	return d.userFlows.finalize(tag, email, func() bool {
		uplink := d.stats.GetCounter(userUplinkCounterName(email))
		downlink := d.stats.GetCounter(userDownlinkCounterName(email))
		if (uplink != nil && uplink.Value() != 0) || (downlink != nil && downlink.Value() != 0) {
			return false
		}
		_ = d.stats.UnregisterCounter(userUplinkCounterName(email))
		_ = d.stats.UnregisterCounter(userDownlinkCounterName(email))
		return true
	})
}

func userUplinkCounterName(email string) string {
	return "user>>>" + email + ">>>traffic>>>uplink"
}

func userDownlinkCounterName(email string) string {
	return "user>>>" + email + ">>>traffic>>>downlink"
}
