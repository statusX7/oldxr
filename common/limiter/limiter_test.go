package limiter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"

	"github.com/XrayR-project/XrayR/api"
)

func newTestGlobalInbound() *InboundInfo {
	inboundInfo := &InboundInfo{Tag: "node-tag"}
	inboundInfo.GlobalLimit.config = &GlobalDeviceLimitConfig{
		Enable:  true,
		Timeout: 1,
		Expiry:  60,
	}
	inboundInfo.GlobalLimit.globalOnlineIP = &layeredGlobalIPCache{
		local:       make(map[string]globalIPCacheEntry),
		localExpiry: time.Minute,
	}
	return inboundInfo
}

func globalTestKey(email string, deviceLimit int) string {
	return fmt.Sprintf("%d%s", deviceLimit, email[len("node-tag"):])
}

func TestGlobalDeviceLimitRejectsNewIPAtBoundary(t *testing.T) {
	inboundInfo := newTestGlobalInbound()
	email := "node-tag|user@example.com|1"
	key := globalTestKey(email, 1)
	existing := map[string]int{"192.0.2.1": 1}
	if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(context.Background(), key, &existing); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	if reject := globalLimit(inboundInfo, email, 1, "192.0.2.1", 1); reject {
		t.Fatal("same IP was rejected at the limit")
	}
	if reject := globalLimit(inboundInfo, email, 1, "192.0.2.2", 1); !reject {
		t.Fatal("new IP was accepted when len(ipMap) == deviceLimit")
	}
}

func TestGlobalDeviceLimitConcurrentBurstHonorsLimit(t *testing.T) {
	inboundInfo := newTestGlobalInbound()
	email := "node-tag|burst@example.com|2"
	const (
		deviceLimit = 5
		connections = 100
	)

	start := make(chan struct{})
	var accepted int64
	var wg sync.WaitGroup
	wg.Add(connections)
	for i := 0; i < connections; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			if !globalLimit(inboundInfo, email, 2, fmt.Sprintf("198.51.100.%d", i+1), deviceLimit) {
				atomic.AddInt64(&accepted, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&accepted); got > deviceLimit {
		t.Fatalf("accepted %d concurrent IPs, limit is %d", got, deviceLimit)
	}
}

func newLocalTestLimiter(t testing.TB, deviceLimit int) (*Limiter, string) {
	t.Helper()
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: deviceLimit}}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}
	return l, "node-tag|user@example.com|1"
}

func TestLocalDeviceLimitBoundaryAndSameIP(t *testing.T) {
	l, email := newLocalTestLimiter(t, 1)
	if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		t.Fatal("first IP rejected")
	}
	if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		t.Fatal("same IP rejected at boundary")
	}
	if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.2"); !reject {
		t.Fatal("second IP accepted with deviceLimit=1")
	}
}

func TestLocalDeviceLimitConcurrentBurstHonorsLimit(t *testing.T) {
	const (
		deviceLimit = 5
		connections = 100
	)
	l, email := newLocalTestLimiter(t, deviceLimit)
	start := make(chan struct{})
	var accepted int64
	var wg sync.WaitGroup
	wg.Add(connections)
	for i := 0; i < connections; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			if _, _, reject := l.GetUserBucket("node-tag", email, fmt.Sprintf("198.51.100.%d", i+1)); !reject {
				atomic.AddInt64(&accepted, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt64(&accepted); got != deviceLimit {
		t.Fatalf("accepted %d concurrent IPs, want exactly %d", got, deviceLimit)
	}
}

func TestLocalDeviceLimitZeroIsUnlimited(t *testing.T) {
	l, email := newLocalTestLimiter(t, 0)
	for i := 0; i < 100; i++ {
		if _, _, reject := l.GetUserBucket("node-tag", email, fmt.Sprintf("203.0.113.%d", i+1)); reject {
			t.Fatalf("unlimited user rejected at IP %d", i+1)
		}
	}
}

type testGlobalIPCache struct {
	mu         sync.Mutex
	values     map[any]map[string]int
	getErr     error
	setErr     error
	setStarted chan struct{}
	allowSet   chan struct{}
	closed     int32
	setOnce    sync.Once
}

func (c *testGlobalIPCache) Get(_ context.Context, key any, returnObj any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getErr != nil {
		return nil, c.getErr
	}
	value, exists := c.values[key]
	if !exists {
		return nil, store.NotFoundWithCause(errors.New("not found"))
	}
	result := returnObj.(*map[string]int)
	*result = make(map[string]int, len(value))
	for ip, uid := range value {
		(*result)[ip] = uid
	}
	return result, nil
}

func (c *testGlobalIPCache) Set(_ context.Context, key, object any, _ ...store.Option) error {
	if c.setStarted != nil {
		c.setOnce.Do(func() { close(c.setStarted) })
	}
	if c.allowSet != nil {
		<-c.allowSet
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.setErr != nil {
		return c.setErr
	}
	value := *(object.(*map[string]int))
	copyValue := make(map[string]int, len(value))
	for ip, uid := range value {
		copyValue[ip] = uid
	}
	if c.values == nil {
		c.values = make(map[any]map[string]int)
	}
	c.values[key] = copyValue
	return nil
}

func (c *testGlobalIPCache) Close() error {
	atomic.AddInt32(&c.closed, 1)
	return nil
}

func TestGlobalDeviceLimitDoesNotDetachSlowSet(t *testing.T) {
	cache := &testGlobalIPCache{
		setStarted: make(chan struct{}),
		allowSet:   make(chan struct{}),
	}
	inboundInfo := newTestGlobalInbound()
	inboundInfo.GlobalLimit.globalOnlineIP = cache
	returned := make(chan bool, 1)
	go func() {
		returned <- globalLimit(inboundInfo, "node-tag|slow@example.com|3", 3, "192.0.2.1", 1)
	}()
	<-cache.setStarted
	select {
	case <-returned:
		t.Fatal("globalLimit returned while cache Set was still running")
	case <-time.After(25 * time.Millisecond):
	}
	close(cache.allowSet)
	select {
	case reject := <-returned:
		if reject {
			t.Fatal("first IP was rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("globalLimit did not return after Set completed")
	}
}

func TestGlobalDeviceLimitCacheUnavailableFailsOpen(t *testing.T) {
	wantErr := errors.New("redis unavailable")
	cache := &testGlobalIPCache{getErr: wantErr}
	inboundInfo := newTestGlobalInbound()
	inboundInfo.GlobalLimit.globalOnlineIP = cache
	if reject := globalLimit(inboundInfo, "node-tag|offline@example.com|4", 4, "192.0.2.1", 1); reject {
		t.Fatal("cache failure changed legacy fail-open behavior")
	}
}

func TestGlobalIPCacheClosedOnDeleteAndReplace(t *testing.T) {
	first := &testGlobalIPCache{}
	second := &testGlobalIPCache{}
	firstInbound := &InboundInfo{}
	firstInbound.GlobalLimit.globalOnlineIP = first
	secondInbound := &InboundInfo{}
	secondInbound.GlobalLimit.globalOnlineIP = second
	l := New()
	l.InboundInfo.Store("node-tag", firstInbound)
	if old, loaded := l.InboundInfo.Swap("node-tag", secondInbound); loaded {
		closeGlobalIPCache(old.(*InboundInfo).GlobalLimit.globalOnlineIP)
	}
	if got := atomic.LoadInt32(&first.closed); got != 1 {
		t.Fatalf("replaced cache close count = %d, want 1", got)
	}
	if err := l.DeleteInboundLimiter("node-tag"); err != nil {
		t.Fatalf("DeleteInboundLimiter: %v", err)
	}
	if got := atomic.LoadInt32(&second.closed); got != 1 {
		t.Fatalf("deleted cache close count = %d, want 1", got)
	}
	if err := l.DeleteInboundLimiter("node-tag"); err != nil {
		t.Fatalf("second DeleteInboundLimiter: %v", err)
	}
	if got := atomic.LoadInt32(&second.closed); got != 1 {
		t.Fatalf("second delete closed cache %d times, want 1", got)
	}
}

func benchmarkLocalLimiterExistingIP(b *testing.B) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 5}}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		b.Fatal(err)
	}
	email := "node-tag|user@example.com|1"
	if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		b.Fatal("initial IP rejected")
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
				b.Fatal("existing IP rejected")
			}
		}
	})
}

func BenchmarkLocalLimiterExistingIP(b *testing.B) {
	benchmarkLocalLimiterExistingIP(b)
}

func BenchmarkLocalLimiterAtCapacity(b *testing.B) {
	for _, deviceLimit := range []int{1, 5, 100} {
		b.Run(fmt.Sprintf("limit-%d", deviceLimit), func(b *testing.B) {
			l, email := newLocalTestLimiter(b, deviceLimit)
			for i := 0; i < deviceLimit; i++ {
				if _, _, reject := l.GetUserBucket("node-tag", email, fmt.Sprintf("192.0.2.%d", i+1)); reject {
					b.Fatal("fixture IP rejected")
				}
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, reject := l.GetUserBucket("node-tag", email, "198.51.100.1"); !reject {
					b.Fatal("IP accepted above capacity")
				}
			}
		})
	}
}

func BenchmarkGlobalLimiterAtCapacity(b *testing.B) {
	for _, deviceLimit := range []int{1, 5, 100} {
		b.Run(fmt.Sprintf("limit-%d", deviceLimit), func(b *testing.B) {
			inboundInfo := newTestGlobalInbound()
			email := "node-tag|global@example.com|9"
			key := globalTestKey(email, deviceLimit)
			ips := make(map[string]int, deviceLimit)
			for i := 0; i < deviceLimit; i++ {
				ips[fmt.Sprintf("192.0.2.%d", i+1)] = 9
			}
			if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(context.Background(), key, &ips); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if reject := globalLimit(inboundInfo, email, 9, "198.51.100.1", deviceLimit); !reject {
					b.Fatal("global IP accepted above capacity")
				}
			}
		})
	}
}
