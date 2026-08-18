package mydispatcher

import (
	"context"
	"strconv"
	"sync"
	"testing"

	statsapp "github.com/xtls/xray-core/app/stats"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func newTestUserTrafficCounterIndex(t *testing.T) (*userTrafficCounterIndex, *statsapp.Manager) {
	t.Helper()
	manager, err := statsapp.NewManager(context.Background(), &statsapp.Config{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return newUserTrafficCounterIndex(manager), manager
}

func TestUserTrafficCounterIndexConcurrentFirstRegistration(t *testing.T) {
	index, manager := newTestUserTrafficCounterIndex(t)
	const workers = 100
	counters := make([]featurestats.Counter, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		go func() {
			defer wg.Done()
			<-start
			counters[worker] = index.getOrRegister("node-1", "node-1|user@example.com|42", "uplink")
		}()
	}
	close(start)
	wg.Wait()

	if counters[0] == nil {
		t.Fatal("first counter is nil")
	}
	for worker, counter := range counters {
		if counter == nil {
			t.Fatalf("worker %d received a nil counter", worker)
		}
		if counter != counters[0] {
			t.Fatalf("worker %d received a different counter", worker)
		}
	}
	if got := manager.GetCounter("user>>>node-1|user@example.com|42>>>traffic>>>uplink"); got != counters[0] {
		t.Fatal("registered manager counter does not match the indexed counter")
	}
}

func TestUserTrafficCounterIndexVisitIsIsolatedByTag(t *testing.T) {
	index, _ := newTestUserTrafficCounterIndex(t)
	up := index.getOrRegister("node-1", "node-1|first@example.com|1", "uplink")
	down := index.getOrRegister("node-1", "node-1|first@example.com|1", "downlink")
	other := index.getOrRegister("node-2", "node-2|other@example.com|2", "uplink")
	if up == nil || down == nil || other == nil {
		t.Fatal("expected all counters to be registered")
	}

	visited := make(map[string]featurestats.Counter)
	index.visit("node-1", func(taggedEmail, direction string, counter featurestats.Counter) bool {
		visited[taggedEmail+"/"+direction] = counter
		return true
	})
	if len(visited) != 2 {
		t.Fatalf("visited %d counters, want 2", len(visited))
	}
	if visited["node-1|first@example.com|1/uplink"] != up {
		t.Fatal("uplink counter missing from tag-local visit")
	}
	if visited["node-1|first@example.com|1/downlink"] != down {
		t.Fatal("downlink counter missing from tag-local visit")
	}
	if _, exists := visited["node-2|other@example.com|2/uplink"]; exists {
		t.Fatal("visit leaked a counter from another tag")
	}
}

func TestUserTrafficCounterIndexVisitsCounterPairs(t *testing.T) {
	index, _ := newTestUserTrafficCounterIndex(t)
	taggedEmail := "node-1|first@example.com|1"
	uplink := index.getOrRegister("node-1", taggedEmail, "uplink")
	downlink := index.getOrRegister("node-1", taggedEmail, "downlink")
	if uplink == nil || downlink == nil {
		t.Fatal("expected both counters")
	}

	visits := 0
	index.visitPairs("node-1", func(email string, up, down featurestats.Counter) bool {
		visits++
		if email != taggedEmail || up != uplink || down != downlink {
			t.Fatalf("unexpected pair: email=%q up=%p down=%p", email, up, down)
		}
		return true
	})
	if visits != 1 {
		t.Fatalf("pair visits = %d, want 1", visits)
	}
}

func TestUserTrafficCounterIndexConcurrentVisitAndRegistration(t *testing.T) {
	index, _ := newTestUserTrafficCounterIndex(t)
	const users = 1_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for user := 0; user < users; user++ {
			taggedEmail := "node-1|user-" + strconv.Itoa(user) + "|" + strconv.Itoa(user)
			if counter := index.getOrRegister("node-1", taggedEmail, "uplink"); counter == nil {
				t.Errorf("user %d received a nil counter", user)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for visit := 0; visit < users; visit++ {
			index.visit("node-1", func(string, string, featurestats.Counter) bool { return true })
		}
	}()
	close(start)
	wg.Wait()
}

func BenchmarkUserTrafficCounterLookup(b *testing.B) {
	taggedEmail := "node-1|user@example.com|42"
	tag := "node-1"
	direction := "uplink"
	manager, err := statsapp.NewManager(context.Background(), &statsapp.Config{})
	if err != nil {
		b.Fatalf("NewManager: %v", err)
	}
	index := newUserTrafficCounterIndex(manager)
	if counter := index.getOrRegister(tag, taggedEmail, direction); counter == nil {
		b.Fatal("failed to register benchmark counter")
	}

	b.Run("global", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			name := "user>>>" + taggedEmail + ">>>traffic>>>" + direction
			counter, _ := featurestats.GetOrRegisterCounter(manager, name)
			if counter == nil {
				b.Fatal("global lookup returned nil")
			}
		}
	})

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if counter := index.getOrRegister(tag, taggedEmail, direction); counter == nil {
				b.Fatal("indexed lookup returned nil")
			}
		}
	})

	b.Run("global-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				name := "user>>>" + taggedEmail + ">>>traffic>>>" + direction
				counter, _ := featurestats.GetOrRegisterCounter(manager, name)
				if counter == nil {
					b.Fatal("global lookup returned nil")
				}
			}
		})
	})

	b.Run("indexed-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if counter := index.getOrRegister(tag, taggedEmail, direction); counter == nil {
					b.Fatal("indexed lookup returned nil")
				}
			}
		})
	})
}
