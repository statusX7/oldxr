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
	inboundInfo.GlobalLimit.config = &GlobalDeviceLimitConfig{Enable: true, Timeout: 1, Expiry: 60}
	inboundInfo.GlobalLimit.globalOnlineIP = &layeredGlobalIPCache{
		local:       make(map[string]globalIPCacheEntry),
		localExpiry: time.Minute,
	}
	return inboundInfo
}

func TestGlobalDeviceLimitRejectsNewIPAtBoundary(t *testing.T) {
	inboundInfo := newTestGlobalInbound()
	email := "node-tag|user@example.com|1"
	key := "1|user@example.com|1"
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
	var wait sync.WaitGroup
	wait.Add(connections)
	for index := 0; index < connections; index++ {
		go func(index int) {
			defer wait.Done()
			<-start
			if !globalLimit(inboundInfo, email, 2, fmt.Sprintf("198.51.100.%d", index+1), deviceLimit) {
				atomic.AddInt64(&accepted, 1)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	if got := atomic.LoadInt64(&accepted); got != deviceLimit {
		t.Fatalf("accepted %d concurrent IPs, want exactly %d", got, deviceLimit)
	}
}

type testGlobalIPCache struct {
	mu         sync.Mutex
	values     map[interface{}]map[string]int
	getErr     error
	setErr     error
	setStarted chan struct{}
	allowSet   chan struct{}
	closed     int32
	setOnce    sync.Once
}

func (c *testGlobalIPCache) Get(_ context.Context, key interface{}, returnObj interface{}) (interface{}, error) {
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

func (c *testGlobalIPCache) Set(_ context.Context, key, object interface{}, _ ...store.Option) error {
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
		c.values = make(map[interface{}]map[string]int)
	}
	c.values[key] = copyValue
	return nil
}

func (c *testGlobalIPCache) Close() error {
	atomic.AddInt32(&c.closed, 1)
	return nil
}

func TestGlobalDeviceLimitDoesNotDetachSlowSet(t *testing.T) {
	cache := &testGlobalIPCache{setStarted: make(chan struct{}), allowSet: make(chan struct{})}
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
	cache := &testGlobalIPCache{getErr: errors.New("redis unavailable")}
	inboundInfo := newTestGlobalInbound()
	inboundInfo.GlobalLimit.globalOnlineIP = cache
	if reject := globalLimit(inboundInfo, "node-tag|offline@example.com|4", 4, "192.0.2.1", 1); reject {
		t.Fatal("cache failure changed legacy fail-open behavior")
	}
}

func TestGlobalIPCacheClosedOnDeleteAndReplace(t *testing.T) {
	first := new(testGlobalIPCache)
	firstInbound := &InboundInfo{}
	firstInbound.GlobalLimit.globalOnlineIP = first
	manager := New()
	manager.InboundInfo.Store("node-tag", firstInbound)
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	if err := manager.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&first.closed); got != 1 {
		t.Fatalf("replaced cache close count = %d, want 1", got)
	}

	second := new(testGlobalIPCache)
	secondInbound := &InboundInfo{}
	secondInbound.GlobalLimit.globalOnlineIP = second
	manager.InboundInfo.Store("second-tag", secondInbound)
	if err := manager.DeleteInboundLimiter("second-tag"); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteInboundLimiter("second-tag"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&second.closed); got != 1 {
		t.Fatalf("deleted cache close count = %d, want 1", got)
	}
}

func newLocalTestLimiter(t testing.TB, deviceLimit int) (*Limiter, string) {
	t.Helper()
	manager := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: deviceLimit}}
	if err := manager.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}
	return manager, "node-tag|user@example.com|1"
}

func TestLocalDeviceLimitBoundaryAndSameIP(t *testing.T) {
	manager, email := newLocalTestLimiter(t, 1)
	if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		t.Fatal("first IP rejected")
	}
	if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
		t.Fatal("same IP rejected at boundary")
	}
	if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.2"); !reject {
		t.Fatal("second IP accepted with deviceLimit=1")
	}
}

func TestLocalDeviceLimitConcurrentBurstHonorsLimit(t *testing.T) {
	const (
		deviceLimit = 5
		connections = 100
	)
	manager, email := newLocalTestLimiter(t, deviceLimit)
	start := make(chan struct{})
	var accepted int64
	var wait sync.WaitGroup
	wait.Add(connections)
	for index := 0; index < connections; index++ {
		go func(index int) {
			defer wait.Done()
			<-start
			if _, _, reject := manager.GetUserBucket("node-tag", email, fmt.Sprintf("198.51.100.%d", index+1)); !reject {
				atomic.AddInt64(&accepted, 1)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	if got := atomic.LoadInt64(&accepted); got != deviceLimit {
		t.Fatalf("accepted %d concurrent IPs, want exactly %d", got, deviceLimit)
	}
}

func TestUnknownLimiterUserDoesNotCreateRuntimeState(t *testing.T) {
	manager, _ := newLocalTestLimiter(t, 1)
	unknown := "node-tag|unknown@example.com|999"
	if bucket, limited, reject := manager.GetUserBucket("node-tag", unknown, "203.0.113.1"); bucket != nil || limited || reject {
		t.Fatalf("unknown user result = (%v, %v, %v), want nil, false, false", bucket, limited, reject)
	}
	value, ok := manager.InboundInfo.Load("node-tag")
	if !ok {
		t.Fatal("inbound missing")
	}
	if _, exists := value.(*InboundInfo).UserOnlineIP.Load(unknown); exists {
		t.Fatal("unknown user created online-IP state")
	}
}

func syncMapLen(values *sync.Map) int {
	count := 0
	values.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func TestDeleteInboundLimiterUsersCleansRuntimeState(t *testing.T) {
	manager := New()
	users := []api.UserInfo{
		{UID: 1, Email: "deleted@example.com", SpeedLimit: 1024, DeviceLimit: 1},
		{UID: 2, Email: "kept@example.com", SpeedLimit: 1024, DeviceLimit: 1},
	}
	if err := manager.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	deletedEmail := formatUserKey("node-tag", users[0].Email, users[0].UID)
	keptEmail := formatUserKey("node-tag", users[1].Email, users[1].UID)
	deletedBucket, _, reject := manager.GetUserBucket("node-tag", deletedEmail, "192.0.2.1")
	if reject || deletedBucket == nil {
		t.Fatal("failed to create deleted user state")
	}
	if _, _, reject := manager.GetUserBucket("node-tag", keptEmail, "192.0.2.2"); reject {
		t.Fatal("failed to create kept user state")
	}
	deleted := users[:1]
	if err := manager.DeleteInboundLimiterUsers("node-tag", &deleted); err != nil {
		t.Fatalf("DeleteInboundLimiterUsers: %v", err)
	}

	value, _ := manager.InboundInfo.Load("node-tag")
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
	manager := New()
	user := api.UserInfo{UID: 1, Email: "deleted@example.com", SpeedLimit: 1024, DeviceLimit: 1000}
	users := []api.UserInfo{user}
	if err := manager.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := formatUserKey("node-tag", user.Email, user.UID)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			manager.GetUserBucket("node-tag", email, fmt.Sprintf("198.51.100.%d", index+1))
		}(index)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		if err := manager.DeleteInboundLimiterUsers("node-tag", &users); err != nil {
			t.Errorf("DeleteInboundLimiterUsers: %v", err)
		}
	}()
	close(start)
	wait.Wait()

	value, _ := manager.InboundInfo.Load("node-tag")
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

func TestLimiterRepeatedUserChurnHasBoundedState(t *testing.T) {
	const (
		activeUsers = 1000
		churnUsers  = 900
		cycles      = 20
	)
	makeUsers := func(firstUID int, count int) []api.UserInfo {
		users := make([]api.UserInfo, count)
		for index := range users {
			uid := firstUID + index
			users[index] = api.UserInfo{
				UID:         uid,
				Email:       fmt.Sprintf("user-%d@example.com", uid),
				SpeedLimit:  1024,
				DeviceLimit: 1,
			}
		}
		return users
	}
	connectUsers := func(users []api.UserInfo, manager *Limiter) {
		for _, user := range users {
			email := formatUserKey("node-tag", user.Email, user.UID)
			if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
				t.Fatalf("fixture user %d rejected", user.UID)
			}
		}
	}

	current := makeUsers(1, activeUsers)
	manager := New()
	if err := manager.AddInboundLimiter("node-tag", 0, &current, nil); err != nil {
		t.Fatal(err)
	}
	connectUsers(current, manager)
	nextUID := activeUsers + 1
	for cycle := 0; cycle < cycles; cycle++ {
		deleted := current[:churnUsers]
		kept := append([]api.UserInfo(nil), current[churnUsers:]...)
		added := makeUsers(nextUID, churnUsers)
		nextUID += churnUsers
		if err := manager.DeleteInboundLimiterUsers("node-tag", &deleted); err != nil {
			t.Fatal(err)
		}
		if err := manager.UpdateInboundLimiter("node-tag", &added); err != nil {
			t.Fatal(err)
		}
		connectUsers(added, manager)
		current = append(kept, added...)

		value, _ := manager.InboundInfo.Load("node-tag")
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

func BenchmarkLocalLimiterExistingIP(b *testing.B) {
	for _, speedLimit := range []uint64{0, 1024 * 1024} {
		b.Run(fmt.Sprintf("speed-%d", speedLimit), func(b *testing.B) {
			manager := New()
			users := []api.UserInfo{{
				UID:         1,
				Email:       "user@example.com",
				SpeedLimit:  speedLimit,
				DeviceLimit: 5,
			}}
			if err := manager.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
				b.Fatal(err)
			}
			email := formatUserKey("node-tag", users[0].Email, users[0].UID)
			if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
				b.Fatal("initial IP rejected")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, _, reject := manager.GetUserBucket("node-tag", email, "192.0.2.1"); reject {
					b.Fatal("existing IP rejected")
				}
			}
		})
	}
}
