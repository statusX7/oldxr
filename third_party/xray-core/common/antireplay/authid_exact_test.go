package antireplay

import (
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metro "github.com/dgryski/go-metro"
)

type exactAuthIDFakeClock struct {
	now time.Time
}

func (clock *exactAuthIDFakeClock) Now() time.Time {
	return clock.now
}

func exactAuthIDForSequence(sequence uint64) [16]byte {
	var authID [16]byte
	binary.BigEndian.PutUint64(authID[:8], sequence)
	binary.BigEndian.PutUint64(authID[8:], ^sequence)
	return authID
}

func TestExactAuthIDFilterRejectsNoCuckooFingerprintCollision(t *testing.T) {
	type oldFingerprintLocation struct {
		bucket      uint32
		fingerprint byte
	}
	seen := make(map[oldFingerprintLocation][16]byte)
	var first, second [16]byte
	for sequence := uint64(0); sequence < 100000; sequence++ {
		candidate := exactAuthIDForSequence(sequence)
		hash := metro.Hash64(candidate[:], 1337)
		location := oldFingerprintLocation{
			bucket:      uint32(hash>>32) & ((1 << 15) - 1),
			fingerprint: byte(hash%255 + 1),
		}
		if previous, found := seen[location]; found {
			first, second = previous, candidate
			break
		}
		seen[location] = candidate
	}
	if first == second {
		t.Fatal("failed to find deterministic one-byte fingerprint collision")
	}

	old := NewReplayFilter(120)
	if !old.Check(first[:]) {
		t.Fatal("old filter rejected the first colliding AuthID")
	}
	if old.Check(second[:]) {
		t.Fatal("test inputs do not collide in the old one-byte fingerprint filter")
	}

	clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
	exact := newExactAuthIDFilter(120*time.Second, 100000, clock.Now)
	if !exact.Check(first) || !exact.Check(second) {
		t.Fatal("exact filter rejected a distinct AuthID")
	}
}

func TestExactAuthIDFilterSerialAndConcurrentDuplicates(t *testing.T) {
	clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
	filter := newExactAuthIDFilter(120*time.Second, 100000, clock.Now)
	authID := exactAuthIDForSequence(1)
	if !filter.Check(authID) {
		t.Fatal("first AuthID was rejected")
	}
	if filter.Check(authID) {
		t.Fatal("serial duplicate AuthID was accepted")
	}

	concurrent := newExactAuthIDFilter(120*time.Second, 100000, clock.Now)
	const goroutines = 128
	start := make(chan struct{})
	var successes atomic.Int64
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wait.Done()
			<-start
			if concurrent.Check(authID) {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent successes=%d want=1", got)
	}
}

func TestExactAuthIDFilterConcurrentUniqueBeforeCapacity(t *testing.T) {
	clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
	const entries = 1024
	filter := newExactAuthIDFilter(120*time.Second, entries, clock.Now)
	start := make(chan struct{})
	var successes atomic.Int64
	var wait sync.WaitGroup
	wait.Add(entries)
	for i := 0; i < entries; i++ {
		authID := exactAuthIDForSequence(uint64(i + 1))
		go func() {
			defer wait.Done()
			<-start
			if filter.Check(authID) {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := successes.Load(); got != entries {
		t.Fatalf("unique successes=%d want=%d", got, entries)
	}
	if got := len(filter.current); got != entries {
		t.Fatalf("current entries=%d want=%d", got, entries)
	}
}

func TestExactAuthIDFilterWindowBoundaries(t *testing.T) {
	base := time.Unix(1000, 0)
	clock := &exactAuthIDFakeClock{now: base}
	filter := newExactAuthIDFilter(120*time.Second, 16, clock.Now)
	authID := exactAuthIDForSequence(1)
	if !filter.Check(authID) {
		t.Fatal("t=0 first AuthID was rejected")
	}

	for _, offset := range []time.Duration{120*time.Second - time.Nanosecond, 120 * time.Second, 240*time.Second - time.Nanosecond} {
		clock.now = base.Add(offset)
		if filter.Check(authID) {
			t.Fatalf("duplicate accepted at offset %s", offset)
		}
	}
	clock.now = base.Add(240 * time.Second)
	if !filter.Check(authID) {
		t.Fatal("AuthID did not expire at the second complete window")
	}
}

func TestExactAuthIDFilterLargeJumpAndClockRollback(t *testing.T) {
	base := time.Unix(2000, 0)
	clock := &exactAuthIDFakeClock{now: base}
	filter := newExactAuthIDFilter(120*time.Second, 16, clock.Now)
	first := exactAuthIDForSequence(1)
	second := exactAuthIDForSequence(2)
	if !filter.Check(first) {
		t.Fatal("first AuthID was rejected")
	}

	clock.now = base.Add(120 * time.Second)
	if !filter.Check(second) {
		t.Fatal("second-window AuthID was rejected")
	}
	clock.now = base.Add(60 * time.Second)
	if filter.Check(first) || filter.Check(second) {
		t.Fatal("clock rollback prematurely forgot replay history")
	}

	clock.now = base.Add(5 * 120 * time.Second)
	if !filter.Check(first) || !filter.Check(second) {
		t.Fatal("large forward jump did not expire both retained windows")
	}
	if len(filter.current)+len(filter.previous) != 2 {
		t.Fatalf("retained entries=%d want=2", len(filter.current)+len(filter.previous))
	}
}

func TestExactAuthIDFilterCapacityFailClosedAndRecovers(t *testing.T) {
	base := time.Unix(3000, 0)
	clock := &exactAuthIDFakeClock{now: base}
	filter := newExactAuthIDFilter(120*time.Second, 2, clock.Now)
	first := exactAuthIDForSequence(1)
	second := exactAuthIDForSequence(2)
	third := exactAuthIDForSequence(3)
	fourth := exactAuthIDForSequence(4)
	beforeRejects := exactAuthIDCapacityRejects.Value()

	if !filter.Check(first) || !filter.Check(second) {
		t.Fatal("unique AuthID was rejected before capacity")
	}
	if filter.Check(first) {
		t.Fatal("duplicate AuthID was accepted at capacity")
	}
	if got := exactAuthIDCapacityRejects.Value(); got != beforeRejects {
		t.Fatalf("duplicate changed capacity metric: before=%d after=%d", beforeRejects, got)
	}
	if filter.Check(third) || filter.Check(fourth) {
		t.Fatal("unique AuthID was accepted after capacity")
	}
	if got := exactAuthIDCapacityRejects.Value() - beforeRejects; got != 2 {
		t.Fatalf("capacity rejects=%d want=2", got)
	}

	clock.now = base.Add(120 * time.Second)
	if !filter.Check(third) {
		t.Fatal("rotation did not restore current-window capacity")
	}
	if filter.Check(first) {
		t.Fatal("previous-window duplicate was accepted")
	}
	clock.now = base.Add(240 * time.Second)
	if !filter.Check(first) {
		t.Fatal("expired previous-window AuthID remained rejected")
	}
	if len(filter.current) > filter.capacity || len(filter.previous) > filter.capacity {
		t.Fatalf("window capacity exceeded: current=%d previous=%d", len(filter.current), len(filter.previous))
	}
}

func TestExactAuthIDFilterConcurrentCapacityMetric(t *testing.T) {
	clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
	filter := newExactAuthIDFilter(120*time.Second, 1, clock.Now)
	if !filter.Check(exactAuthIDForSequence(1)) {
		t.Fatal("failed to fill current window")
	}
	const rejected = 256
	beforeRejects := exactAuthIDCapacityRejects.Value()
	start := make(chan struct{})
	var accepted atomic.Int64
	var wait sync.WaitGroup
	wait.Add(rejected)
	for i := 0; i < rejected; i++ {
		authID := exactAuthIDForSequence(uint64(i + 2))
		go func() {
			defer wait.Done()
			<-start
			if filter.Check(authID) {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := accepted.Load(); got != 0 {
		t.Fatalf("accepted at capacity=%d want=0", got)
	}
	if got := exactAuthIDCapacityRejects.Value() - beforeRejects; got != rejected {
		t.Fatalf("concurrent capacity rejects=%d want=%d", got, rejected)
	}
}

func TestExactAuthIDFilterAllocatesMapsLazily(t *testing.T) {
	clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
	filter := newExactAuthIDFilter(120*time.Second, 100000, clock.Now)
	if filter.current != nil || filter.previous != nil {
		t.Fatal("exact AuthID maps were allocated eagerly")
	}
	if !filter.Check(exactAuthIDForSequence(1)) {
		t.Fatal("first AuthID was rejected")
	}
	if filter.current == nil {
		t.Fatal("current map was not allocated on first insert")
	}
	if filter.previous != nil {
		t.Fatal("previous map was allocated before a rotation")
	}
}

func BenchmarkExactAuthIDFilterRetainedMemory(b *testing.B) {
	for iteration := 0; iteration < b.N; iteration++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		base := time.Unix(4000, 0)
		clock := &exactAuthIDFakeClock{now: base}
		filter := newExactAuthIDFilter(120*time.Second, exactAuthIDReplayCapacity, clock.Now)
		for i := 0; i < exactAuthIDReplayCapacity; i++ {
			if !filter.Check(exactAuthIDForSequence(uint64(i))) {
				b.Fatalf("first-window AuthID %d was rejected", i)
			}
		}
		clock.now = base.Add(120 * time.Second)
		for i := 0; i < exactAuthIDReplayCapacity; i++ {
			if !filter.Check(exactAuthIDForSequence(uint64(exactAuthIDReplayCapacity + i))) {
				b.Fatalf("second-window AuthID %d was rejected", i)
			}
		}

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		retained := uint64(0)
		if after.HeapAlloc > before.HeapAlloc {
			retained = after.HeapAlloc - before.HeapAlloc
		}
		b.ReportMetric(float64(retained), "retained-B")
		if retained > 8<<20 {
			b.Fatalf("two full replay windows retained %d bytes, limit=%d", retained, 8<<20)
		}
		runtime.KeepAlive(filter)
	}
}

func FuzzExactAuthIDFilter(f *testing.F) {
	f.Add(make([]byte, 16), append(make([]byte, 15), 1))
	f.Fuzz(func(t *testing.T, firstBytes, secondBytes []byte) {
		if len(firstBytes) != 16 || len(secondBytes) != 16 {
			return
		}
		var first, second [16]byte
		copy(first[:], firstBytes)
		copy(second[:], secondBytes)
		clock := &exactAuthIDFakeClock{now: time.Unix(1, 0)}
		filter := newExactAuthIDFilter(120*time.Second, 2, clock.Now)
		if !filter.Check(first) {
			t.Fatal("first AuthID was rejected")
		}
		if filter.Check(first) {
			t.Fatal("duplicate AuthID was accepted")
		}
		acceptedSecond := filter.Check(second)
		if acceptedSecond != (first != second) {
			t.Fatalf("second AuthID acceptance=%v distinct=%v", acceptedSecond, first != second)
		}
	})
}
