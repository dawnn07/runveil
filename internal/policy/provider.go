package policy

import "sync/atomic"

// Provider holds the active *Policy and serves wait-free reads to
// every request handler. Updates from the Watcher are atomic.
//
// Safe for concurrent use. Reads via Get are wait-free
// (atomic.Pointer.Load); writes via Set are atomic.
type Provider struct {
	p atomic.Pointer[Policy]
}

// NewProvider returns a Provider holding the given initial policy.
// initial may be nil — Get on a nil-initialized Provider returns nil
// and stage code is expected to treat that as "no policy".
func NewProvider(initial *Policy) *Provider {
	pr := &Provider{}
	pr.p.Store(initial)
	return pr
}

// Get returns the currently-active policy. Wait-free.
func (pr *Provider) Get() *Policy { return pr.p.Load() }

// Set atomically swaps the active policy.
func (pr *Provider) Set(np *Policy) { pr.p.Store(np) }
