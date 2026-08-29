//go:build linux

package owner

import (
	"sync"
	"sync/atomic"
	"time"
)

// IdleTimer implements the Xray connection-idle policy without resetting a
// runtime timer on every payload callback. Update is lock-free; a timer is
// rescheduled only when its current deadline is reached or policy changes.
type IdleTimer struct {
	activity atomic.Bool

	mu      sync.Mutex
	timer   *time.Timer
	timeout time.Duration
	expire  func()
	stopped bool
}

// Start arms the timer. It must be called once after both owned endpoints are
// available.
func (t *IdleTimer) Start(timeout time.Duration, expire func()) {
	t.activity.Store(true)

	t.mu.Lock()
	if t.timer != nil || t.stopped {
		t.mu.Unlock()
		return
	}
	t.timeout = timeout
	t.expire = expire
	if timeout <= 0 {
		t.stopped = true
		t.mu.Unlock()
		if expire != nil {
			expire()
		}
		return
	}
	t.timer = time.AfterFunc(timeout, t.check)
	t.mu.Unlock()
}

// Update records payload activity without taking the timer mutex.
func (t *IdleTimer) Update() {
	t.activity.Store(true)
}

// SetTimeout switches to the one-direction timeout after one side finishes.
// A zero timeout preserves Xray's immediate-cancel semantics.
func (t *IdleTimer) SetTimeout(timeout time.Duration) {
	t.activity.Store(true)

	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.timeout = timeout
	if timeout <= 0 {
		t.stopped = true
		if t.timer != nil {
			t.timer.Stop()
		}
		expire := t.expire
		t.mu.Unlock()
		if expire != nil {
			expire()
		}
		return
	}
	if t.timer == nil {
		t.timer = time.AfterFunc(timeout, t.check)
	} else {
		t.timer.Stop()
		t.timer.Reset(timeout)
	}
	t.mu.Unlock()
}

// Stop prevents future expiry callbacks.
func (t *IdleTimer) Stop() {
	t.mu.Lock()
	if !t.stopped {
		t.stopped = true
		if t.timer != nil {
			t.timer.Stop()
		}
	}
	t.mu.Unlock()
}

func (t *IdleTimer) check() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	if t.activity.Swap(false) {
		t.timer.Reset(t.timeout)
		t.mu.Unlock()
		return
	}
	t.stopped = true
	expire := t.expire
	t.mu.Unlock()
	if expire != nil {
		expire()
	}
}
