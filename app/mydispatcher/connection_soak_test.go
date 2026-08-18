//go:build soak

package mydispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	statsapp "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/limiter"
	"github.com/XrayR-project/XrayR/common/rule"
)

type syntheticResourceSample struct {
	At           string `json:"at"`
	Elapsed      string `json:"elapsed"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapObjects  uint64 `json:"heap_objects"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	Sys          uint64 `json:"sys"`
	RSS          uint64 `json:"rss"`
	Goroutines   int    `json:"goroutines"`
	GCCount      uint32 `json:"gc_count"`
	GCPauseTotal uint64 `json:"gc_pause_total_ns"`
	FDCount      int    `json:"fd_count"`
}

type syntheticLinkPair struct {
	inbound  *transport.Link
	outbound *transport.Link
}

type syntheticDispatcher struct {
	dispatcher *DefaultDispatcher
	tag        string
	contexts   []context.Context
}

type syntheticStatsManager struct {
	mu       sync.RWMutex
	counters map[string]featurestats.Counter
}

func newSyntheticStatsManager() *syntheticStatsManager {
	return &syntheticStatsManager{counters: make(map[string]featurestats.Counter)}
}

func (*syntheticStatsManager) Type() interface{} { return featurestats.ManagerType() }
func (*syntheticStatsManager) Start() error      { return nil }
func (*syntheticStatsManager) Close() error      { return nil }

func (m *syntheticStatsManager) RegisterCounter(name string) (featurestats.Counter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.counters[name]; exists {
		return nil, fmt.Errorf("counter %q already exists", name)
	}
	counter := new(statsapp.Counter)
	m.counters[name] = counter
	return counter, nil
}

func (m *syntheticStatsManager) UnregisterCounter(name string) error {
	m.mu.Lock()
	delete(m.counters, name)
	m.mu.Unlock()
	return nil
}

func (m *syntheticStatsManager) GetCounter(name string) featurestats.Counter {
	m.mu.RLock()
	counter := m.counters[name]
	m.mu.RUnlock()
	return counter
}

func (*syntheticStatsManager) RegisterChannel(string) (featurestats.Channel, error) {
	return nil, fmt.Errorf("channels are not supported by synthetic stats")
}

func (*syntheticStatsManager) UnregisterChannel(string) error { return nil }
func (*syntheticStatsManager) GetChannel(string) featurestats.Channel {
	return nil
}

func newSyntheticDispatcher(t *testing.T, users, deviceLimit int, speedLimit uint64, enableRule bool) *syntheticDispatcher {
	t.Helper()
	const tag = "synthetic-node"
	manager := newSyntheticStatsManager()
	userList := make([]api.UserInfo, users)
	contexts := make([]context.Context, users)
	for user := 0; user < users; user++ {
		email := fmt.Sprintf("user-%d@example.com", user)
		userList[user] = api.UserInfo{
			UID:         user + 1,
			Email:       email,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
		}
		contexts[user] = session.ContextWithInbound(context.Background(), &session.Inbound{
			Source: xnet.TCPDestination(xnet.IPAddress([]byte{198, 51, byte(user%254 + 1), 1}), 12345),
			Tag:    tag,
			User:   &protocol.MemoryUser{Email: fmt.Sprintf("%s|%s|%d", tag, email, user+1)},
		})
	}
	connectionLimiter := limiter.New()
	if err := connectionLimiter.AddInboundLimiter(tag, 0, &userList, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}
	dispatcher := &DefaultDispatcher{
		policy: &benchmarkPolicyManager{session: policy.Session{Stats: policy.Stats{
			UserUplink:   enableRule,
			UserDownlink: enableRule,
		}}},
		Limiter:         connectionLimiter,
		RuleManager:     rule.New(),
		trafficCounters: newUserTrafficCounterIndex(manager),
	}
	if enableRule {
		compiled, compileErr := api.CompileDetectRule(-1, `^blocked\.example`)
		if compileErr != nil {
			t.Fatalf("CompileDetectRule: %v", compileErr)
		}
		if err := dispatcher.RuleManager.UpdateRule(tag, []api.DetectRule{compiled}); err != nil {
			t.Fatalf("UpdateRule: %v", err)
		}
	}
	return &syntheticDispatcher{dispatcher: dispatcher, tag: tag, contexts: contexts}
}

func (s *syntheticDispatcher) open(t testing.TB, user, connection int, enableRule bool) syntheticLinkPair {
	t.Helper()
	inboundSession := session.InboundFromContext(s.contexts[user])
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.IPAddress([]byte{198, 51, byte(user%254 + 1), byte(connection%254 + 1)}), 12345),
		Tag:    inboundSession.Tag,
		User:   inboundSession.User,
	})
	inbound, outbound, err := s.dispatcher.getLink(ctx, xnet.Network_TCP, session.SniffingRequest{})
	if err != nil {
		t.Fatalf("getLink user=%d connection=%d: %v", user, connection, err)
	}
	if enableRule && s.dispatcher.RuleManager.Detect(s.tag, "allowed.example:443", inboundSession.User.Email) {
		t.Fatal("synthetic allowed destination was rejected")
	}
	return syntheticLinkPair{inbound: inbound, outbound: outbound}
}

func (pair syntheticLinkPair) close() {
	closeBenchmarkLink(pair.inbound)
	closeBenchmarkLink(pair.outbound)
}

func sampleSyntheticResources(start time.Time) syntheticResourceSample {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	fdCount := -1
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		fdCount = len(entries)
	}
	return syntheticResourceSample{
		At:           time.Now().Format(time.RFC3339),
		Elapsed:      time.Since(start).Round(time.Millisecond).String(),
		HeapAlloc:    memory.HeapAlloc,
		HeapInuse:    memory.HeapInuse,
		HeapObjects:  memory.HeapObjects,
		TotalAlloc:   memory.TotalAlloc,
		Mallocs:      memory.Mallocs,
		Frees:        memory.Frees,
		Sys:          memory.Sys,
		RSS:          readSyntheticRSS(),
		Goroutines:   runtime.NumGoroutine(),
		GCCount:      memory.NumGC,
		GCPauseTotal: memory.PauseTotalNs,
		FDCount:      fdCount,
	}
}

func readSyntheticRSS() uint64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" {
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr == nil {
				return value * 1024
			}
		}
	}
	return 0
}

func logSyntheticSample(t *testing.T, label string, sample syntheticResourceSample) {
	t.Helper()
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("Marshal resource sample: %v", err)
	}
	t.Logf("RESOURCE label=%s %s", label, encoded)
}

func TestSyntheticConnectionMatrix(t *testing.T) {
	const users = 100
	for _, connectionsPerUser := range []int{1, 5, 20} {
		for _, features := range []bool{false, true} {
			name := fmt.Sprintf("users=%d/connections-per-user=%d/features=%t", users, connectionsPerUser, features)
			t.Run(name, func(t *testing.T) {
				deviceLimit := 0
				speedLimit := uint64(0)
				if features {
					deviceLimit = connectionsPerUser
					speedLimit = 1_000_000
				}
				testStart := time.Now()
				synthetic := newSyntheticDispatcher(t, users, deviceLimit, speedLimit, features)
				runtime.GC()
				logSyntheticSample(t, "before", sampleSyntheticResources(testStart))

				links := make([]syntheticLinkPair, 0, users*connectionsPerUser)
				setupStart := time.Now()
				for user := 0; user < users; user++ {
					for connection := 0; connection < connectionsPerUser; connection++ {
						links = append(links, synthetic.open(t, user, connection, features))
					}
				}
				setupDuration := time.Since(setupStart)
				logSyntheticSample(t, "live", sampleSyntheticResources(testStart))

				shutdownStart := time.Now()
				for _, pair := range links {
					pair.close()
				}
				shutdownDuration := time.Since(shutdownStart)
				links = nil
				_, _ = synthetic.dispatcher.Limiter.GetOnlineDevice(synthetic.tag)
				_, _ = synthetic.dispatcher.Limiter.GetOnlineDevice(synthetic.tag)
				_ = synthetic.dispatcher.Limiter.DeleteInboundLimiter(synthetic.tag)
				runtime.GC()
				debug.FreeOSMemory()
				logSyntheticSample(t, "after-cleanup", sampleSyntheticResources(testStart))
				t.Logf("TIMING connections=%d setup=%s setup-per-connection=%s shutdown=%s", users*connectionsPerUser, setupDuration, setupDuration/time.Duration(users*connectionsPerUser), shutdownDuration)
			})
		}
	}
}

func TestSyntheticConnectionSoak(t *testing.T) {
	duration := syntheticDurationFromEnv(t, "OLDXR_SOAK_DURATION", 15*time.Minute)
	sampleInterval := syntheticDurationFromEnv(t, "OLDXR_SOAK_SAMPLE_INTERVAL", time.Minute)
	const (
		users              = 100
		connectionsPerUser = 5
		churnBatch         = 10
	)
	testStart := time.Now()
	synthetic := newSyntheticDispatcher(t, users, connectionsPerUser+1, 1_000_000, true)
	longLived := make([]syntheticLinkPair, 0, users*connectionsPerUser)
	for user := 0; user < users; user++ {
		for connection := 0; connection < connectionsPerUser; connection++ {
			longLived = append(longLived, synthetic.open(t, user, connection, true))
		}
	}
	logSyntheticSample(t, "soak-start", sampleSyntheticResources(testStart))

	churnTicker := time.NewTicker(10 * time.Millisecond)
	defer churnTicker.Stop()
	sampleTicker := time.NewTicker(sampleInterval)
	defer sampleTicker.Stop()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	churnConnections := uint64(0)
	for {
		select {
		case <-churnTicker.C:
			for i := 0; i < churnBatch; i++ {
				sequence := churnConnections + uint64(i)
				pair := synthetic.open(t, int(sequence%users), connectionsPerUser, true)
				pair.close()
			}
			churnConnections += churnBatch
		case <-sampleTicker.C:
			logSyntheticSample(t, fmt.Sprintf("soak-churn-%d", churnConnections), sampleSyntheticResources(testStart))
		case <-deadline.C:
			shutdownStart := time.Now()
			for _, pair := range longLived {
				pair.close()
			}
			longLived = nil
			_, _ = synthetic.dispatcher.Limiter.GetOnlineDevice(synthetic.tag)
			_, _ = synthetic.dispatcher.Limiter.GetOnlineDevice(synthetic.tag)
			_ = synthetic.dispatcher.Limiter.DeleteInboundLimiter(synthetic.tag)
			runtime.GC()
			debug.FreeOSMemory()
			logSyntheticSample(t, fmt.Sprintf("soak-end-churn-%d", churnConnections), sampleSyntheticResources(testStart))
			t.Logf("SOAK duration=%s churn-connections=%d shutdown-cleanup=%s", duration, churnConnections, time.Since(shutdownStart))
			return
		}
	}
}

func syntheticDurationFromEnv(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		t.Fatalf("invalid %s=%q", name, value)
	}
	return duration
}
