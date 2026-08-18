package mydispatcher

import (
	"sync"

	"github.com/xtls/xray-core/features/stats"
)

type userTrafficCounterPair struct {
	uplink   stats.Counter
	downlink stats.Counter
}

type userTrafficCounterSet struct {
	mu      sync.RWMutex
	byEmail map[string]*userTrafficCounterPair
}

type userTrafficCounterIndex struct {
	manager stats.Manager
	sets    sync.Map
}

func newUserTrafficCounterIndex(manager stats.Manager) *userTrafficCounterIndex {
	return &userTrafficCounterIndex{manager: manager}
}

func (i *userTrafficCounterIndex) counterSet(tag string) *userTrafficCounterSet {
	if loaded, ok := i.sets.Load(tag); ok {
		return loaded.(*userTrafficCounterSet)
	}
	created := &userTrafficCounterSet{byEmail: make(map[string]*userTrafficCounterPair)}
	actual, _ := i.sets.LoadOrStore(tag, created)
	return actual.(*userTrafficCounterSet)
}

func (i *userTrafficCounterIndex) getOrRegister(tag, taggedEmail, direction string) stats.Counter {
	if direction != "uplink" && direction != "downlink" {
		return nil
	}
	set := i.counterSet(tag)
	set.mu.RLock()
	pair := set.byEmail[taggedEmail]
	if pair != nil {
		if direction == "uplink" && pair.uplink != nil {
			counter := pair.uplink
			set.mu.RUnlock()
			return counter
		}
		if direction == "downlink" && pair.downlink != nil {
			counter := pair.downlink
			set.mu.RUnlock()
			return counter
		}
	}
	set.mu.RUnlock()

	set.mu.Lock()
	defer set.mu.Unlock()
	pair = set.byEmail[taggedEmail]
	if pair == nil {
		pair = new(userTrafficCounterPair)
		set.byEmail[taggedEmail] = pair
	}
	if direction == "uplink" && pair.uplink != nil {
		return pair.uplink
	}
	if direction == "downlink" && pair.downlink != nil {
		return pair.downlink
	}

	name := "user>>>" + taggedEmail + ">>>traffic>>>" + direction
	counter := i.manager.GetCounter(name)
	if counter == nil {
		registered, err := i.manager.RegisterCounter(name)
		if err == nil {
			counter = registered
		} else {
			// Another registrar may have won between GetCounter and
			// RegisterCounter. Never leave this connection unaccounted merely
			// because the counter now exists.
			counter = i.manager.GetCounter(name)
		}
	}
	if counter == nil {
		return nil
	}

	if direction == "uplink" {
		pair.uplink = counter
	} else {
		pair.downlink = counter
	}
	return counter
}

func (i *userTrafficCounterIndex) visit(tag string, visitor func(string, string, stats.Counter) bool) {
	loaded, ok := i.sets.Load(tag)
	if !ok {
		return
	}
	set := loaded.(*userTrafficCounterSet)
	set.mu.RLock()
	defer set.mu.RUnlock()
	for taggedEmail, pair := range set.byEmail {
		if pair.uplink != nil && !visitor(taggedEmail, "uplink", pair.uplink) {
			return
		}
		if pair.downlink != nil && !visitor(taggedEmail, "downlink", pair.downlink) {
			return
		}
	}
}

func (i *userTrafficCounterIndex) visitPairs(tag string, visitor func(string, stats.Counter, stats.Counter) bool) {
	loaded, ok := i.sets.Load(tag)
	if !ok {
		return
	}
	set := loaded.(*userTrafficCounterSet)
	set.mu.RLock()
	defer set.mu.RUnlock()
	for taggedEmail, pair := range set.byEmail {
		if !visitor(taggedEmail, pair.uplink, pair.downlink) {
			return
		}
	}
}

// VisitUserTrafficCounters visits only counters that belong to tag. The
// callback runs under the tag-local read lock, not xray-core's global stats
// manager lock.
func (d *DefaultDispatcher) VisitUserTrafficCounters(tag string, visitor func(string, string, stats.Counter) bool) bool {
	if d.trafficCounters == nil {
		return false
	}
	d.trafficCounters.visit(tag, visitor)
	return true
}

// VisitUserTrafficCounterPairs visits each user's counters together so traffic
// reporting can parse the identity and build its report once per user.
func (d *DefaultDispatcher) VisitUserTrafficCounterPairs(tag string, visitor func(string, stats.Counter, stats.Counter) bool) bool {
	if d.trafficCounters == nil {
		return false
	}
	d.trafficCounters.visitPairs(tag, visitor)
	return true
}
