package controller

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XrayR-project/XrayR/api"
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
