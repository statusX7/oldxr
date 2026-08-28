//go:build linux

package owner

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleTimerUpdateDefersExpiry(t *testing.T) {
	var fired atomic.Int32
	firedAt := make(chan time.Time, 1)
	var timer IdleTimer
	timer.Start(80*time.Millisecond, func() {
		fired.Add(1)
		firedAt <- time.Now()
	})
	defer timer.Stop()

	time.Sleep(50 * time.Millisecond)
	updatedAt := time.Now()
	timer.Update()

	select {
	case <-firedAt:
		t.Fatal("timer expired before the refreshed idle interval")
	case <-time.After(45 * time.Millisecond):
	}
	select {
	case at := <-firedAt:
		if at.Sub(updatedAt) < 70*time.Millisecond {
			t.Fatalf("timer expired too early after update: %v", at.Sub(updatedAt))
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timer did not expire")
	}
	if got := fired.Load(); got != 1 {
		t.Fatalf("expiry count = %d, want 1", got)
	}
}

func TestIdleTimerZeroTimeoutExpiresImmediately(t *testing.T) {
	fired := make(chan struct{}, 1)
	var timer IdleTimer
	timer.Start(time.Minute, func() { fired <- struct{}{} })
	timer.SetTimeout(0)
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("zero timeout did not expire immediately")
	}
	timer.Stop()
}
