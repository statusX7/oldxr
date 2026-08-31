package antireplay

import (
	"expvar"
	"sync"
	"time"
)

const (
	exactAuthIDReplayInterval = 120 * time.Second
	exactAuthIDReplayCapacity = 100000
)

var (
	exactAuthIDCapacityRejects = expvar.NewInt("xray_vmess_authid_replay_capacity_rejects")
	exactAuthIDRotations       = expvar.NewInt("xray_vmess_authid_replay_rotations")
)

// ExactAuthIDFilter tracks complete VMess AuthIDs without probabilistic
// fingerprints. It retains the current and immediately previous time window.
type ExactAuthIDFilter struct {
	lock sync.Mutex

	current  map[[16]byte]struct{}
	previous map[[16]byte]struct{}

	windowStart time.Time
	initialized bool
	interval    time.Duration
	capacity    int
	now         func() time.Time
}

// NewExactAuthIDFilter creates the exact replay tracker used by VMess AuthID
// validation. Its maps grow lazily as AuthIDs are accepted.
func NewExactAuthIDFilter() *ExactAuthIDFilter {
	return newExactAuthIDFilter(exactAuthIDReplayInterval, exactAuthIDReplayCapacity, time.Now)
}

func newExactAuthIDFilter(interval time.Duration, capacity int, now func() time.Time) *ExactAuthIDFilter {
	if interval <= 0 {
		panic("antireplay: exact AuthID interval must be positive")
	}
	if capacity <= 0 {
		panic("antireplay: exact AuthID capacity must be positive")
	}
	if now == nil {
		panic("antireplay: exact AuthID clock must not be nil")
	}
	return &ExactAuthIDFilter{
		interval: interval,
		capacity: capacity,
		now:      now,
	}
}

// Check atomically checks and records a complete AuthID. It returns true only
// for a previously unseen AuthID that fits in the current window.
func (filter *ExactAuthIDFilter) Check(authID [16]byte) bool {
	filter.lock.Lock()
	defer filter.lock.Unlock()

	filter.rotateLocked(filter.now())
	if _, found := filter.current[authID]; found {
		return false
	}
	if _, found := filter.previous[authID]; found {
		return false
	}
	if len(filter.current) >= filter.capacity {
		exactAuthIDCapacityRejects.Add(1)
		return false
	}
	if filter.current == nil {
		filter.current = make(map[[16]byte]struct{})
	}
	filter.current[authID] = struct{}{}
	return true
}

func (filter *ExactAuthIDFilter) rotateLocked(now time.Time) {
	if !filter.initialized {
		filter.windowStart = now
		filter.initialized = true
		return
	}
	if now.Before(filter.windowStart) {
		return
	}

	elapsed := now.Sub(filter.windowStart)
	if elapsed < filter.interval {
		return
	}
	windows := elapsed / filter.interval
	if windows == 1 {
		expired := filter.previous
		filter.previous = filter.current
		filter.current = expired
		resetExactAuthIDWindow(filter.current)
	} else {
		resetExactAuthIDWindow(filter.current)
		resetExactAuthIDWindow(filter.previous)
	}
	filter.windowStart = filter.windowStart.Add(windows * filter.interval)
	exactAuthIDRotations.Add(1)
}

func resetExactAuthIDWindow(window map[[16]byte]struct{}) {
	for authID := range window {
		delete(window, authID)
	}
}
