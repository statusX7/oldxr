package controller

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	statsapp "github.com/xtls/xray-core/app/stats"
)

type testTrafficCounter struct {
	value int64
}

func newTestTrafficCounter(value int64) *testTrafficCounter {
	return &testTrafficCounter{value: value}
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
	counter := newTestTrafficCounter(100)
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}

	reportStarted := make(chan struct{})
	allowReport := make(chan struct{})
	reportDone := make(chan error, 1)
	reporter := testTrafficReporter{report: func(traffic *[]api.UserTraffic) error {
		close(reportStarted)
		<-allowReport
		return nil
	}}

	go func() {
		reportDone <- flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta})
	}()

	<-reportStarted
	counter.Add(7)
	close(allowReport)
	if err := <-reportDone; err != nil {
		t.Fatalf("flushUserTraffic: %v", err)
	}

	if got, want := delta.value+counter.Value(), int64(107); got != want {
		t.Fatalf("traffic is not conserved: reported + remaining = %d, want %d", got, want)
	}
}

func TestCollectTrafficByCounterVisitDrainsOnlyControllerCounters(t *testing.T) {
	manager, err := statsapp.NewManager(context.Background(), &statsapp.Config{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	register := func(name string, value int64) *statsapp.Counter {
		t.Helper()
		counter, err := manager.RegisterCounter(name)
		if err != nil {
			t.Fatalf("RegisterCounter(%q): %v", name, err)
		}
		counter.Add(value)
		return counter.(*statsapp.Counter)
	}

	uplink := register("user>>>node-tag|user@example.com|42>>>traffic>>>uplink", 100)
	downlink := register("user>>>node-tag|user@example.com|42>>>traffic>>>downlink", 200)
	otherController := register("user>>>other-tag|user@example.com|42>>>traffic>>>uplink", 300)
	unknownDirection := register("user>>>node-tag|user@example.com|42>>>traffic>>>other", 400)
	controller := &Controller{stm: manager, Tag: "node-tag"}

	traffic, deltas, ok := controller.collectTrafficByCounterVisit()
	if !ok {
		t.Fatal("stats manager must support counter visiting")
	}
	if len(traffic) != 1 || traffic[0].UID != 42 || traffic[0].Email != "user@example.com" || traffic[0].Upload != 100 || traffic[0].Download != 200 {
		t.Fatalf("unexpected traffic: %#v", traffic)
	}
	if len(deltas) != 2 {
		t.Fatalf("deltas = %d, want 2", len(deltas))
	}
	if uplink.Value() != 0 || downlink.Value() != 0 {
		t.Fatalf("controller counters were not drained: up=%d down=%d", uplink.Value(), downlink.Value())
	}
	if got := otherController.Value(); got != 300 {
		t.Fatalf("other controller counter = %d, want 300", got)
	}
	if got := unknownDirection.Value(); got != 400 {
		t.Fatalf("unknown direction counter = %d, want 400", got)
	}
}

func TestTrafficReportFailureRestoresConcurrentTraffic(t *testing.T) {
	uplink := newTestTrafficCounter(100)
	downlink := newTestTrafficCounter(200)
	upDelta, upOK := drainTrafficCounter(uplink)
	downDelta, downOK := drainTrafficCounter(downlink)
	if !upOK || !downOK {
		t.Fatal("expected both traffic deltas")
	}

	// These increments arrive after the atomic drain and must survive restoration.
	uplink.Add(7)
	downlink.Add(11)
	wantErr := errors.New("panel unavailable")
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error { return wantErr }}
	err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: 100, Download: 200}}, []trafficCounterDelta{upDelta, downDelta})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if got, want := uplink.Value(), int64(107); got != want {
		t.Fatalf("uplink after restore = %d, want %d", got, want)
	}
	if got, want := downlink.Value(), int64(211); got != want {
		t.Fatalf("downlink after restore = %d, want %d", got, want)
	}
}

func TestTrafficFailedThenSuccessfulReportConservesTotal(t *testing.T) {
	counter := newTestTrafficCounter(100)
	reportCalls := 0
	successfullyReported := int64(0)
	reporter := testTrafficReporter{report: func(traffic *[]api.UserTraffic) error {
		reportCalls++
		if reportCalls == 1 {
			return errors.New("temporary failure")
		}
		for _, item := range *traffic {
			successfullyReported += item.Upload + item.Download
		}
		return nil
	}}

	first, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected first delta")
	}
	if err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: first.value}}, []trafficCounterDelta{first}); err == nil {
		t.Fatal("expected first report to fail")
	}
	counter.Add(7)

	second, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected restored second delta")
	}
	if err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: second.value}}, []trafficCounterDelta{second}); err != nil {
		t.Fatalf("second report: %v", err)
	}

	if got, want := successfullyReported+counter.Value(), int64(107); got != want {
		t.Fatalf("successful reports + remaining = %d, want %d", got, want)
	}
}

func TestTrafficConsecutiveSuccessfulReportsDoNotDuplicate(t *testing.T) {
	counter := newTestTrafficCounter(0)
	successfullyReported := int64(0)
	reporter := testTrafficReporter{report: func(traffic *[]api.UserTraffic) error {
		for _, item := range *traffic {
			successfullyReported += item.Upload + item.Download
		}
		return nil
	}}

	for _, value := range []int64{100, 50, 25} {
		counter.Add(value)
		delta, ok := drainTrafficCounter(counter)
		if !ok {
			t.Fatalf("expected delta for %d", value)
		}
		if err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta}); err != nil {
			t.Fatalf("flushUserTraffic: %v", err)
		}
	}

	if got, want := successfullyReported, int64(175); got != want {
		t.Fatalf("successfully reported = %d, want %d", got, want)
	}
	if got := counter.Value(); got != 0 {
		t.Fatalf("remaining counter = %d, want 0", got)
	}
}

func TestTrafficReportFailureRestoresAfterCounterReset(t *testing.T) {
	counter := newTestTrafficCounter(100)
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}

	// Simulate a runtime counter reset while the HTTP report is in flight.
	counter.Set(0)
	counter.Add(7)
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error { return errors.New("report failed") }}
	if err := flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta}); err == nil {
		t.Fatal("expected report failure")
	}
	if got, want := counter.Value(), int64(107); got != want {
		t.Fatalf("counter after reset and restore = %d, want %d", got, want)
	}
}

func TestTrafficConcurrentAddsAreConserved(t *testing.T) {
	const (
		workers       = 8
		addsPerWorker = 10_000
	)
	counter := newTestTrafficCounter(0)
	start := make(chan struct{})
	addsDone := make(chan struct{})
	var adders sync.WaitGroup
	adders.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer adders.Done()
			<-start
			for j := 0; j < addsPerWorker; j++ {
				counter.Add(1)
			}
		}()
	}

	drained := make(chan int64, 1)
	go func() {
		var total int64
		for {
			select {
			case <-addsDone:
				if delta, ok := drainTrafficCounter(counter); ok {
					total += delta.value
				}
				drained <- total
				return
			default:
				if delta, ok := drainTrafficCounter(counter); ok {
					total += delta.value
				}
			}
		}
	}()

	close(start)
	adders.Wait()
	close(addsDone)
	reported := <-drained
	if got, want := reported+counter.Value(), int64(workers*addsPerWorker); got != want {
		t.Fatalf("drained + remaining = %d, want %d", got, want)
	}
}

func TestTrafficReportPanicRestoresDelta(t *testing.T) {
	counter := newTestTrafficCounter(100)
	delta, ok := drainTrafficCounter(counter)
	if !ok {
		t.Fatal("expected traffic delta")
	}
	reporter := testTrafficReporter{report: func(*[]api.UserTraffic) error { panic("report panic") }}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		_ = flushUserTraffic(reporter, false, []api.UserTraffic{{UID: 1, Upload: delta.value}}, []trafficCounterDelta{delta})
	}()

	if got, want := counter.Value(), int64(100); got != want {
		t.Fatalf("counter after panic = %d, want %d", got, want)
	}
}

func TestTrafficUploadDisabledKeepsLegacyDiscardBehavior(t *testing.T) {
	counter := newTestTrafficCounter(100)
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
		t.Fatalf("flushUserTraffic: %v", err)
	}
	if called {
		t.Fatal("disabled upload called reporter")
	}
	if got := counter.Value(); got != 0 {
		t.Fatalf("remaining counter = %d, want legacy discard value 0", got)
	}
}

func TestDrainTrafficCounterPreservesNegativeValue(t *testing.T) {
	counter := newTestTrafficCounter(-1)
	if _, ok := drainTrafficCounter(counter); ok {
		t.Fatal("negative counter must not produce reportable traffic")
	}
	if got, want := counter.Value(), int64(-1); got != want {
		t.Fatalf("negative counter = %d, want %d", got, want)
	}
}

func BenchmarkTrafficCounterCycle(b *testing.B) {
	counter := newTestTrafficCounter(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		counter.Add(1024)
		if _, ok := drainTrafficCounter(counter); !ok {
			b.Fatal("expected traffic delta")
		}
	}
}
