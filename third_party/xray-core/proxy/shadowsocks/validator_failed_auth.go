package shadowsocks

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSourceFailureBurst    = 2
	defaultSourceFailureCooldown = 2 * time.Second
	defaultGlobalFailureBurst    = 8
	defaultGlobalFailureCooldown = time.Second
	defaultGlobalFailureWindow   = 10 * time.Second
	defaultColdScanParallelism   = 32
	defaultColdScanMaxWaiters    = 1024
)

type authMatchLayer uint8

const (
	authMatchNone authMatchLayer = iota
	authMatchSource
	authMatchGlobal
	authMatchCold
)

type validatorAuthMetrics struct {
	sourceHits        atomic.Uint64
	globalHits        atomic.Uint64
	coldHits          atomic.Uint64
	coldScans         atomic.Uint64
	admissionRejects  atomic.Uint64
	candidateAttempts atomic.Uint64
}

type validatorAuthMetricsSnapshot struct {
	sourceHits        uint64
	globalHits        uint64
	coldHits          uint64
	coldScans         uint64
	admissionRejects  uint64
	candidateAttempts uint64
}

func (m *validatorAuthMetrics) snapshot() validatorAuthMetricsSnapshot {
	return validatorAuthMetricsSnapshot{
		sourceHits:        m.sourceHits.Load(),
		globalHits:        m.globalHits.Load(),
		coldHits:          m.coldHits.Load(),
		coldScans:         m.coldScans.Load(),
		admissionRejects:  m.admissionRejects.Load(),
		candidateAttempts: m.candidateAttempts.Load(),
	}
}

// coldScanBudget is process-wide resource protection only. It never stores
// users or source identities, so authentication state remains validator-local.
type coldScanBudget struct {
	mu           sync.Mutex
	slots        chan struct{}
	waiters      atomic.Int32
	windowStart  int64
	blockedUntil int64
	failures     int
	maxWaiters   int32
}

func newColdScanBudget(parallelism, maxWaiters int) *coldScanBudget {
	return &coldScanBudget{
		slots:      make(chan struct{}, parallelism),
		maxWaiters: int32(maxWaiters),
	}
}

func (b *coldScanBudget) blocked(now int64) bool {
	b.mu.Lock()
	blocked := now < b.blockedUntil
	b.mu.Unlock()
	return blocked
}

func (b *coldScanBudget) acquire() bool {
	now := time.Now().UnixNano()
	if b.blocked(now) {
		return false
	}
	if b.waiters.Add(1) > b.maxWaiters {
		b.waiters.Add(-1)
		return false
	}
	b.slots <- struct{}{}
	b.waiters.Add(-1)
	if b.blocked(time.Now().UnixNano()) {
		<-b.slots
		return false
	}
	return true
}

func (b *coldScanBudget) release() {
	<-b.slots
}

func (b *coldScanBudget) recordFailure(now int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.windowStart == 0 || now-b.windowStart > int64(defaultGlobalFailureWindow) {
		b.windowStart = now
		b.failures = 0
	}
	b.failures++
	if b.failures >= defaultGlobalFailureBurst {
		b.failures = 0
		b.blockedUntil = now + int64(defaultGlobalFailureCooldown)
	}
}

func (b *coldScanBudget) resetForTest() {
	b.mu.Lock()
	b.windowStart = 0
	b.blockedUntil = 0
	b.failures = 0
	b.mu.Unlock()
}

var processColdScanBudget = newColdScanBudget(defaultColdScanParallelism, defaultColdScanMaxWaiters)

func (v *Validator) effectiveSourceFailureBurst() uint8 {
	if v.sourceFailureBurst < 0 {
		return 0
	}
	if v.sourceFailureBurst > 0 {
		if v.sourceFailureBurst > 255 {
			return 255
		}
		return uint8(v.sourceFailureBurst)
	}
	return defaultSourceFailureBurst
}

func (v *Validator) effectiveSourceFailureCooldown() time.Duration {
	if v.sourceFailureCooldown > 0 {
		return v.sourceFailureCooldown
	}
	return defaultSourceFailureCooldown
}
