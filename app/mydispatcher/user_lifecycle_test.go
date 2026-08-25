package mydispatcher

import (
	"context"
	"sync"
	"testing"

	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

func newLifecycleTestDispatcher(t *testing.T) (*DefaultDispatcher, stats.Manager) {
	t.Helper()
	manager, err := corestats.NewManager(context.Background(), &corestats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &DefaultDispatcher{stats: manager}, manager
}

func TestManagedUserRetirementDrainsBeforeCounterCleanup(t *testing.T) {
	dispatcher, manager := newLifecycleTestDispatcher(t)
	const (
		tag   = "node"
		email = "node|user@example.com|7"
	)
	dispatcher.RegisterManagedUsers(tag, []string{email})
	runtime, allowed := dispatcher.userFlows.acquire(tag, email)
	if !allowed {
		t.Fatal("registered user was denied")
	}
	uplink, err := stats.GetOrRegisterCounter(manager, userUplinkCounterName(email))
	if err != nil {
		t.Fatal(err)
	}
	downlink, err := stats.GetOrRegisterCounter(manager, userDownlinkCounterName(email))
	if err != nil {
		t.Fatal(err)
	}
	flow := &userIO{runtime: runtime, uplinkCounter: uplink, downlinkCounter: downlink}
	flow.AddUplink(11)
	flow.AddDownlink(13)

	dispatcher.RetireManagedUsers(tag, []string{email})
	if _, allowed := dispatcher.userFlows.acquire(tag, email); allowed {
		t.Fatal("retiring user acquired a new flow")
	}
	if dispatcher.FinalizeRetiredUser(tag, email) {
		t.Fatal("active flow was finalized")
	}
	flow.Release()
	if dispatcher.FinalizeRetiredUser(tag, email) {
		t.Fatal("pending traffic was finalized")
	}
	if got := uplink.Set(0); got != 11 {
		t.Fatalf("uplink drain = %d, want 11", got)
	}
	if got := downlink.Set(0); got != 13 {
		t.Fatalf("downlink drain = %d, want 13", got)
	}
	if !dispatcher.FinalizeRetiredUser(tag, email) {
		t.Fatal("idle drained flow was not finalized")
	}
	if manager.GetCounter(userUplinkCounterName(email)) != nil || manager.GetCounter(userDownlinkCounterName(email)) != nil {
		t.Fatal("retired counters remain registered")
	}
	if _, allowed := dispatcher.userFlows.acquire(tag, email); allowed {
		t.Fatal("finalized user was implicitly re-enabled")
	}

	dispatcher.RegisterManagedUsers(tag, []string{email})
	runtime, allowed = dispatcher.userFlows.acquire(tag, email)
	if !allowed {
		t.Fatal("explicitly re-added user was denied")
	}
	(&userIO{runtime: runtime}).Release()
}

type lifecycleTestWriter struct {
	closes     int
	interrupts int
}

func (*lifecycleTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (w *lifecycleTestWriter) Close() error {
	w.closes++
	return nil
}

func (w *lifecycleTestWriter) Interrupt() {
	w.interrupts++
}

func TestUserConnectionLifecycleWaitsForBothDirections(t *testing.T) {
	runtime := new(userFlowRuntime)
	runtime.acquire()
	flow := &userIO{runtime: runtime}
	lifecycle := newUserConnectionLifecycle(flow, 2)
	firstBase := new(lifecycleTestWriter)
	secondBase := new(lifecycleTestWriter)
	first := &lifecycleWriter{Writer: firstBase, lifecycle: lifecycle}
	second := &lifecycleWriter{Writer: secondBase, lifecycle: lifecycle}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if active := runtime.active.Load(); active != 1 {
		t.Fatalf("active after one direction = %d, want 1", active)
	}
	common.Interrupt(first)
	if active := runtime.active.Load(); active != 1 {
		t.Fatalf("double-close released flow early: %d", active)
	}
	common.Interrupt(second)
	if active := runtime.active.Load(); active != 0 {
		t.Fatalf("active after both directions = %d, want 0", active)
	}
}

func TestManagedUserAcquireRetireConcurrent(t *testing.T) {
	dispatcher, _ := newLifecycleTestDispatcher(t)
	const (
		tag   = "node"
		email = "node|race@example.com|8"
	)
	dispatcher.RegisterManagedUsers(tag, []string{email})

	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if runtime, allowed := dispatcher.userFlows.acquire(tag, email); allowed {
				(&userIO{runtime: runtime}).Release()
			}
		}()
	}
	close(start)
	dispatcher.RetireManagedUsers(tag, []string{email})
	workers.Wait()
	if _, allowed := dispatcher.userFlows.acquire(tag, email); allowed {
		t.Fatal("retired user acquired a flow after concurrent drain")
	}
	if !dispatcher.FinalizeRetiredUser(tag, email) {
		t.Fatal("concurrent retirement did not reach idle")
	}
}
