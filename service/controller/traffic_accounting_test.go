package controller

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/features/stats"
)

type testTrafficCounter struct {
	value int64
}

func (c *testTrafficCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testTrafficCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testTrafficCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value)
}

type testTrafficReporter struct {
	report func(*[]api.UserTraffic) error
}

func (r testTrafficReporter) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	return r.report(traffic)
}

func TestTrafficDrainConservesConcurrentIncrement(t *testing.T) {
	counter := &testTrafficCounter{value: 100}
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}

	reportStarted := make(chan struct{})
	allowReport := make(chan struct{})
	reportDone := make(chan error, 1)
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error {
		close(reportStarted)
		<-allowReport
		return nil
	}}
	go func() {
		reportDone <- flushUserTraffic(
			reporter,
			false,
			[]api.UserTraffic{{UID: 1, Upload: delta.value}},
			[]trafficCounterDelta{delta},
		)
	}()

	<-reportStarted
	counter.Add(7)
	close(allowReport)
	if err := <-reportDone; err != nil {
		t.Fatal(err)
	}

	if got, want := delta.value+counter.Value(), int64(107); got != want {
		t.Fatalf("traffic is not conserved: reported + pending = %d, want %d", got, want)
	}
}

func TestTrafficDrainRestoresFailedReport(t *testing.T) {
	counter := &testTrafficCounter{value: 100}
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}
	counter.Add(7)
	wantErr := errors.New("submit failed")
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error { return wantErr }}
	if err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta}); !errors.Is(err, wantErr) {
		t.Fatalf("flush error = %v, want %v", err, wantErr)
	}
	if got, want := counter.Value(), int64(107); got != want {
		t.Fatalf("restored counter = %d, want %d", got, want)
	}
}

func TestTrafficDrainRestoresReporterPanic(t *testing.T) {
	counter := &testTrafficCounter{value: 100}
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error { panic("submit panic") }}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected reporter panic")
			}
		}()
		_ = flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta})
	}()
	if got, want := counter.Value(), int64(100); got != want {
		t.Fatalf("restored counter after panic = %d, want %d", got, want)
	}
}

func TestTrafficDrainDisabledDiscardsLegacySample(t *testing.T) {
	counter := &testTrafficCounter{value: 100}
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}
	called := false
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error {
		called = true
		return nil
	}}
	if err := flushUserTraffic(reporter, true, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("disabled reporter was called")
	}
	if got := counter.Value(); got != 0 {
		t.Fatalf("disabled traffic counter = %d, want discarded value 0", got)
	}
}

func TestDrainTrafficCounterPreservesNegativeValue(t *testing.T) {
	counter := &testTrafficCounter{value: -7}
	if _, ok := drainTrafficCounter(counter); ok {
		t.Fatal("unexpected delta for negative counter")
	}
	if got := counter.Value(); got != -7 {
		t.Fatalf("negative counter = %d, want -7", got)
	}
}

func TestTrafficDrainConcurrentStressConservesBytes(t *testing.T) {
	const (
		writers    = 8
		increments = 10_000
	)
	counter := new(testTrafficCounter)
	var active atomic.Int32
	active.Store(writers)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer workers.Done()
			defer active.Add(-1)
			<-start
			for j := 0; j < increments; j++ {
				counter.Add(1)
			}
		}()
	}
	close(start)

	var drained int64
	for active.Load() > 0 {
		if delta, ok := drainTrafficCounter(counter); ok {
			drained += delta.value
		}
		runtime.Gosched()
	}
	workers.Wait()
	if delta, ok := drainTrafficCounter(counter); ok {
		drained += delta.value
	}
	if got, want := drained+counter.Value(), int64(writers*increments); got != want {
		t.Fatalf("concurrent traffic = %d, want %d", got, want)
	}
}

func TestAppendUserTrafficMergesRetiredGenerationByUID(t *testing.T) {
	var traffic []api.UserTraffic
	index := make(map[int]int)
	appendUserTraffic(&traffic, index, api.UserInfo{UID: 7, Email: "current@example.com"}, 11, 13)
	appendUserTraffic(&traffic, index, api.UserInfo{UID: 7, Email: "old@example.com"}, 17, 19)
	if len(traffic) != 1 {
		t.Fatalf("traffic rows = %d, want 1", len(traffic))
	}
	if got := traffic[0]; got.Email != "current@example.com" || got.Upload != 28 || got.Download != 32 {
		t.Fatalf("merged traffic = %+v", got)
	}
}

func TestRetiringTrafficFailureRestoresThenFinalizes(t *testing.T) {
	manager, err := corestats.NewManager(context.Background(), &corestats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := new(mydispatcher.DefaultDispatcher)
	if err := dispatcher.Init(&mydispatcher.Config{}, nil, nil, nil, manager, nil); err != nil {
		t.Fatal(err)
	}
	c := &Controller{
		stm:           manager,
		dispatcher:    dispatcher,
		retiringUsers: make(map[retiringUserKey]retiringUser),
	}
	const tag = "node"
	user := api.UserInfo{UID: 9, Email: "retired@example.com"}
	email := c.buildUserTagWithTag(tag, &user)
	dispatcher.RegisterManagedUsers(tag, []string{email})
	c.retireManagedUsers(tag, &[]api.UserInfo{user})
	uplink, err := stats.GetOrRegisterCounter(manager, "user>>>"+email+">>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	uplink.Add(101)

	retiring := c.retiringUserSnapshot()
	up, down, deltas := c.drainTraffic(email)
	traffic := []api.UserTraffic{{UID: user.UID, Email: user.Email, Upload: up, Download: down}}
	wantErr := errors.New("submit failed")
	if err := flushUserTraffic(testTrafficReporter{report: func(*[]api.UserTraffic) error { return wantErr }}, false, traffic, deltas); !errors.Is(err, wantErr) {
		t.Fatalf("flush error = %v, want %v", err, wantErr)
	}
	if got := uplink.Value(); got != 101 {
		t.Fatalf("restored late traffic = %d, want 101", got)
	}
	if len(c.retiringUserSnapshot()) != 1 {
		t.Fatal("failed report removed retiring user")
	}

	up, down, deltas = c.drainTraffic(email)
	traffic = []api.UserTraffic{{UID: user.UID, Email: user.Email, Upload: up, Download: down}}
	if err := flushUserTraffic(testTrafficReporter{report: func(*[]api.UserTraffic) error { return nil }}, false, traffic, deltas); err != nil {
		t.Fatal(err)
	}
	c.finalizeRetiringUsers(retiring)
	if len(c.retiringUserSnapshot()) != 0 {
		t.Fatal("successful report retained idle user")
	}
	if manager.GetCounter("user>>>"+email+">>>traffic>>>uplink") != nil {
		t.Fatal("successful report retained traffic counter")
	}
}
