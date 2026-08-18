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

func syncMapLen(values *sync.Map) int {
	count := 0
	values.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

func TestDeleteInboundLimiterUsersCleansRuntimeState(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "deleted@example.com", SpeedLimit: 1024, DeviceLimit: 1},
		{UID: 2, Email: "kept@example.com", SpeedLimit: 1024, DeviceLimit: 1},
	}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	deletedEmail := "node-tag|deleted@example.com|1"
	keptEmail := "node-tag|kept@example.com|2"
	deletedBucket, _, reject := l.GetUserBucket("node-tag", deletedEmail, "192.0.2.1")
	if reject || deletedBucket == nil {
		t.Fatal("failed to build deleted user state")
	}
	if _, _, reject := l.GetUserBucket("node-tag", keptEmail, "192.0.2.2"); reject {
		t.Fatal("failed to build kept user state")
	}
	if err := l.DeleteInboundLimiterUsers("node-tag", &[]api.UserInfo{users[0]}); err != nil {
		t.Fatalf("DeleteInboundLimiterUsers: %v", err)
	}

	value, _ := l.InboundInfo.Load("node-tag")
	inboundInfo := value.(*InboundInfo)
	if _, exists := inboundInfo.UserInfo.Load(deletedEmail); exists {
		t.Fatal("deleted UserInfo retained")
	}
	if _, exists := inboundInfo.BucketHub.Load(deletedEmail); exists {
		t.Fatal("deleted BucketHub entry retained")
	}
	if _, exists := inboundInfo.UserOnlineIP.Load(deletedEmail); exists {
		t.Fatal("deleted UserOnlineIP entry retained")
	}
	if _, exists := inboundInfo.UserInfo.Load(keptEmail); !exists {
		t.Fatal("kept UserInfo was removed")
	}
	if deletedBucket.Burst() != 1024 {
		t.Fatal("cleanup mutated a bucket already owned by an active connection")
	}
}

func TestDeleteInboundLimiterUsersConcurrentWithConnections(t *testing.T) {
	l := New()
	user := api.UserInfo{UID: 1, Email: "deleted@example.com", SpeedLimit: 1024, DeviceLimit: 1000}
	users := []api.UserInfo{user}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := formatUserKey("node-tag", user.Email, user.UID)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			l.GetUserBucket("node-tag", email, fmt.Sprintf("198.51.100.%d", i+1))
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if err := l.DeleteInboundLimiterUsers("node-tag", &users); err != nil {
			t.Errorf("DeleteInboundLimiterUsers: %v", err)
		}
	}()
	close(start)
	wg.Wait()

	value, _ := l.InboundInfo.Load("node-tag")
	inboundInfo := value.(*InboundInfo)
	if _, exists := inboundInfo.UserInfo.Load(email); exists {
		t.Fatal("concurrent connection recreated UserInfo")
	}
	if _, exists := inboundInfo.BucketHub.Load(email); exists {
		t.Fatal("concurrent connection recreated BucketHub entry")
	}
	if _, exists := inboundInfo.UserOnlineIP.Load(email); exists {
		t.Fatal("concurrent connection recreated UserOnlineIP entry")
	}
}

func TestDeleteInboundLimiterUsersChurnDoesNotRetainHistory(t *testing.T) {
	const total = 1000
	users := make([]api.UserInfo, total)
	for i := range users {
		users[i] = api.UserInfo{
			UID:         i + 1,
			Email:       fmt.Sprintf("user-%d@example.com", i+1),
			SpeedLimit:  1024,
			DeviceLimit: 1,
		}
	}
	l := New()
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		email := fmt.Sprintf("node-tag|%s|%d", user.Email, user.UID)
		if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
			t.Fatalf("fixture user %d rejected", user.UID)
		}
	}
	deleted := users[:900]
	if err := l.DeleteInboundLimiterUsers("node-tag", &deleted); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("node-tag")
	inboundInfo := value.(*InboundInfo)
	for name, values := range map[string]*sync.Map{
		"UserInfo":     inboundInfo.UserInfo,
		"BucketHub":    inboundInfo.BucketHub,
		"UserOnlineIP": inboundInfo.UserOnlineIP,
	} {
		if got, want := syncMapLen(values), 100; got != want {
			t.Fatalf("%s entries = %d, want %d", name, got, want)
		}
	}
}

func TestLimiterRepeatedUserChurnHasBoundedState(t *testing.T) {
	const (
		activeUsers = 1000
		churnUsers  = 900
		cycles      = 20
	)
	makeUsers := func(firstUID int, count int) []api.UserInfo {
		users := make([]api.UserInfo, count)
		for i := range users {
			uid := firstUID + i
			users[i] = api.UserInfo{
				UID:         uid,
				Email:       fmt.Sprintf("user-%d@example.com", uid),
				SpeedLimit:  1024,
				DeviceLimit: 1,
			}
		}
		return users
	}
	connectUsers := func(t *testing.T, l *Limiter, users []api.UserInfo) {
		t.Helper()
		for _, user := range users {
			email := formatUserKey("node-tag", user.Email, user.UID)
			if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
				t.Fatalf("fixture user %d rejected", user.UID)
			}
		}
	}

	current := makeUsers(1, activeUsers)
	l := New()
	if err := l.AddInboundLimiter("node-tag", 0, &current, nil); err != nil {
		t.Fatal(err)
	}
	connectUsers(t, l, current)
	nextUID := activeUsers + 1
	for cycle := 0; cycle < cycles; cycle++ {
		deleted := current[:churnUsers]
		kept := append([]api.UserInfo(nil), current[churnUsers:]...)
		added := makeUsers(nextUID, churnUsers)
		nextUID += churnUsers
		if err := l.DeleteInboundLimiterUsers("node-tag", &deleted); err != nil {
			t.Fatal(err)
		}
		if err := l.UpdateInboundLimiter("node-tag", &added); err != nil {
			t.Fatal(err)
		}
		connectUsers(t, l, added)
		current = append(kept, added...)

		value, _ := l.InboundInfo.Load("node-tag")
		inboundInfo := value.(*InboundInfo)
		for name, values := range map[string]*sync.Map{
			"UserInfo":     inboundInfo.UserInfo,
			"BucketHub":    inboundInfo.BucketHub,
			"UserOnlineIP": inboundInfo.UserOnlineIP,
		} {
			if got := syncMapLen(values); got != activeUsers {
				t.Fatalf("cycle %d: %s entries = %d, want %d", cycle, name, got, activeUsers)
			}
		}
	}
}

func BenchmarkDeleteInboundLimiterUsers(b *testing.B) {
	for _, size := range []int{1000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("users-%d", size), func(b *testing.B) {
			users := make([]api.UserInfo, size)
			for i := range users {
				users[i] = api.UserInfo{UID: i + 1, Email: fmt.Sprintf("user-%d@example.com", i+1)}
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				l := New()
				if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := l.DeleteInboundLimiterUsers("node-tag", &users); err != nil {
					b.Fatal(err)
				}
			}
		})
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

func BenchmarkLocalLimiterExistingIPWithSpeedLimit(b *testing.B) {
	l := New()
	users := []api.UserInfo{{
		UID:         1,
		Email:       "user@example.com",
		DeviceLimit: 5,
		SpeedLimit:  1024 * 1024,
	}}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		b.Fatal(err)
	}
	email := "node-tag|user@example.com|1"
	if _, speedLimited, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject || !speedLimited {
		b.Fatal("initial speed-limited IP was not accepted")
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, speedLimited, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject || !speedLimited {
				b.Fatal("existing speed-limited IP was not accepted")
			}
		}
	})
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

func TestResetOnlineDeviceClearsWithoutMaterializingUsers(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 5, SpeedLimit: 1024}}
	if err := l.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "node-tag|user@example.com|1"
	if _, _, reject := l.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		t.Fatal("fixture IP rejected")
	}
	if err := l.ResetOnlineDevice("node-tag"); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("node-tag")
	inbound := value.(*InboundInfo)
	if got := syncMapLen(inbound.UserOnlineIP); got != 0 {
		t.Fatalf("online users after reset = %d, want 0", got)
	}
	if got := syncMapLen(inbound.BucketHub); got != 1 {
		t.Fatalf("active bucket after first reset = %d, want 1", got)
	}
	if err := l.ResetOnlineDevice("node-tag"); err != nil {
		t.Fatal(err)
	}
	if got := syncMapLen(inbound.BucketHub); got != 0 {
		t.Fatalf("offline bucket after second reset = %d, want 0", got)
	}
}

func BenchmarkOnlineDeviceReset(b *testing.B) {
	const users = 1000
	userList := make([]api.UserInfo, users)
	for i := range userList {
		userList[i] = api.UserInfo{UID: i + 1, Email: fmt.Sprintf("user-%d@example.com", i+1), DeviceLimit: 5}
	}
	for _, benchmark := range []struct {
		name string
		run  func(*Limiter) error
	}{
		{
			name: "CollectLegacySlice",
			run: func(l *Limiter) error {
				online, err := l.GetOnlineDevice("node-tag")
				if err == nil && len(*online) != users {
					return fmt.Errorf("online users = %d, want %d", len(*online), users)
				}
				return err
			},
		},
		{name: "ResetOnly", run: func(l *Limiter) error { return l.ResetOnlineDevice("node-tag") }},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				l := New()
				if err := l.AddInboundLimiter("node-tag", 0, &userList, nil); err != nil {
					b.Fatal(err)
				}
				for userIndex, user := range userList {
					email := formatUserKey("node-tag", user.Email, user.UID)
					if _, _, reject := l.GetUserBucket("node-tag", email, fmt.Sprintf("192.0.%d.%d", userIndex/250, userIndex%250+1)); reject {
						b.Fatal("fixture IP rejected")
					}
				}
				b.StartTimer()
				if err := benchmark.run(l); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
