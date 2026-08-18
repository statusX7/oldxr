package controller

import (
	"fmt"
	"sync"
	"testing"

	featurestats "github.com/xtls/xray-core/features/stats"
)

type benchmarkStatsManager struct {
	mu       sync.RWMutex
	counters map[string]featurestats.Counter
}

type benchmarkUserTrafficCounterVisitor struct {
	byTag map[string]*benchmarkUserTrafficCounterSet
}

type benchmarkUserTrafficCounterSet struct {
	mu      sync.RWMutex
	byEmail map[string]*benchmarkUserTrafficCounterPair
}

type benchmarkUserTrafficCounterPair struct {
	uplink   featurestats.Counter
	downlink featurestats.Counter
}

func (v *benchmarkUserTrafficCounterVisitor) VisitUserTrafficCounters(tag string, visitor func(string, string, featurestats.Counter) bool) bool {
	set := v.byTag[tag]
	if set == nil {
		return true
	}
	set.mu.RLock()
	defer set.mu.RUnlock()
	for taggedEmail, pair := range set.byEmail {
		if pair.uplink != nil && !visitor(taggedEmail, "uplink", pair.uplink) {
			return true
		}
		if pair.downlink != nil && !visitor(taggedEmail, "downlink", pair.downlink) {
			return true
		}
	}
	return true
}

func (v *benchmarkUserTrafficCounterVisitor) add(tag, taggedEmail, direction string, counter featurestats.Counter) {
	set := v.byTag[tag]
	if set == nil {
		set = &benchmarkUserTrafficCounterSet{byEmail: make(map[string]*benchmarkUserTrafficCounterPair)}
		v.byTag[tag] = set
	}
	pair := set.byEmail[taggedEmail]
	if pair == nil {
		pair = new(benchmarkUserTrafficCounterPair)
		set.byEmail[taggedEmail] = pair
	}
	if direction == "uplink" {
		pair.uplink = counter
	} else {
		pair.downlink = counter
	}
}

func newBenchmarkStatsManager() *benchmarkStatsManager {
	return &benchmarkStatsManager{counters: make(map[string]featurestats.Counter)}
}

func (*benchmarkStatsManager) Type() interface{} { return featurestats.ManagerType() }
func (*benchmarkStatsManager) Start() error      { return nil }
func (*benchmarkStatsManager) Close() error      { return nil }

func (m *benchmarkStatsManager) RegisterCounter(name string) (featurestats.Counter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.counters[name]; exists {
		return nil, fmt.Errorf("counter %q already exists", name)
	}
	counter := newTestTrafficCounter(0)
	m.counters[name] = counter
	return counter, nil
}

func (m *benchmarkStatsManager) UnregisterCounter(name string) error {
	m.mu.Lock()
	delete(m.counters, name)
	m.mu.Unlock()
	return nil
}

func (m *benchmarkStatsManager) GetCounter(name string) featurestats.Counter {
	m.mu.RLock()
	counter := m.counters[name]
	m.mu.RUnlock()
	return counter
}

func (*benchmarkStatsManager) RegisterChannel(string) (featurestats.Channel, error) {
	return nil, fmt.Errorf("channels are not supported by the benchmark manager")
}

func (*benchmarkStatsManager) UnregisterChannel(string) error { return nil }
func (*benchmarkStatsManager) GetChannel(string) featurestats.Channel {
	return nil
}

func (m *benchmarkStatsManager) VisitCounters(visitor func(string, featurestats.Counter) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for name, counter := range m.counters {
		if !visitor(name, counter) {
			return
		}
	}
}

func BenchmarkCollectTrafficByCounterVisit(b *testing.B) {
	for _, mode := range []string{"global", "indexed"} {
		for _, counterCount := range []int{1_000, 10_000, 50_000} {
			for _, controllerCount := range []int{1, 10, 100} {
				for _, stalePercent := range []int{0, 50, 90} {
					name := fmt.Sprintf("mode=%s/counters=%d/controllers=%d/stale=%d", mode, counterCount, controllerCount, stalePercent)
					b.Run(name, func(b *testing.B) {
						manager := newBenchmarkStatsManager()
						index := &benchmarkUserTrafficCounterVisitor{byTag: make(map[string]*benchmarkUserTrafficCounterSet, controllerCount)}

						controllers := make([]*Controller, controllerCount)
						for i := range controllers {
							controllers[i] = &Controller{stm: manager}
							if mode == "indexed" {
								controllers[i].trafficCounters = index
							}
						}

						activeCount := counterCount * (100 - stalePercent) / 100
						activeCounters := make([]*testTrafficCounter, 0, activeCount)
						for i := 0; i < counterCount; i++ {
							tag := fmt.Sprintf("node-%d", i%controllerCount)
							direction := "uplink"
							if i%2 != 0 {
								direction = "downlink"
							}
							counterName := fmt.Sprintf("user>>>%s|user-%d@example.com|%d>>>traffic>>>%s", tag, i/2, i/2, direction)
							counter, registerErr := manager.RegisterCounter(counterName)
							if registerErr != nil {
								b.Fatalf("RegisterCounter: %v", registerErr)
							}
							if i < activeCount {
								activeCounters = append(activeCounters, counter.(*testTrafficCounter))
							}
							index.add(tag, fmt.Sprintf("%s|user-%d@example.com|%d", tag, i/2, i/2), direction, counter)
						}

						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							for _, counter := range activeCounters {
								counter.Set(1)
							}
							for controllerID, controller := range controllers {
								traffic, _, ok := controller.collectTrafficByCounterVisit(fmt.Sprintf("node-%d", controllerID))
								if !ok {
									b.Fatal("stats manager does not support counter visiting")
								}
								if len(traffic) == 0 && activeCount > 0 {
									b.Fatal("active traffic was not collected")
								}
							}
						}
						visits := counterCount
						if mode == "global" {
							visits *= controllerCount
						}
						b.ReportMetric(float64(visits), "counter-visits/op")
					})
				}
			}
		}
	}
}
