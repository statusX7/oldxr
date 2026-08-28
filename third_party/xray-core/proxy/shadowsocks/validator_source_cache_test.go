package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	stdnet "net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func sourceCacheTestAddress(tb testing.TB, raw string) xraynet.Address {
	tb.Helper()
	ip := stdnet.ParseIP(raw)
	if ip == nil {
		tb.Fatalf("parse source IP %q", raw)
	}
	return xraynet.IPAddress(ip)
}

func authenticateSSUserWithSource(t *testing.T, validator *Validator, user *protocol.MemoryUser, source xraynet.Address, sequence uint64) {
	t.Helper()
	wire := benchmarkSSDeterministicTCPAuthWire(t, user, sequence)
	got, _, _, _, err := validator.GetWithSource(wire, protocol.RequestCommandTCP, source)
	if err != nil || got != user {
		t.Fatalf("authenticate %q from %s: got=%v err=%v", user.Email, source, got, err)
	}
}

func countSSCandidateAttempts(users []*protocol.MemoryUser) (*int, func()) {
	attempts := new(int)
	restore := make([]func(), 0, len(users))
	for _, user := range users {
		aeadCipher := user.Account.(*MemoryAccount).Cipher.(*AEADCipher)
		creator := aeadCipher.AEADAuthCreator
		aeadCipher.AEADAuthCreator = func(key []byte) cipher.AEAD {
			*attempts++
			return creator(key)
		}
		restore = append(restore, func() {
			aeadCipher.AEADAuthCreator = creator
		})
	}
	return attempts, func() {
		for _, restoreCreator := range restore {
			restoreCreator()
		}
	}
}

func TestValidatorSourceCandidatesCGNATAndExactOnce(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 1000, 128)
	validator.sourceCache.Store(newSourceCandidateCache(defaultSourceCacheMaxSources, 4, defaultSourceCacheTTL))
	source := sourceCacheTestAddress(t, "198.51.100.10")
	sourceKey, ok := authSourceKeyFromAddress(source)
	if !ok {
		t.Fatal("source key was not created")
	}

	wrongUser := &protocol.MemoryUser{Account: mustSSBenchmarkAccount(t, "source-cache-wrong")}
	wrongWire := benchmarkSSDeterministicTCPAuthWire(t, wrongUser, 8000)
	if got, _, _, _, err := validator.GetWithSource(wrongWire, protocol.RequestCommandTCP, source); err != ErrNotFound || got != nil {
		t.Fatalf("invalid request unexpectedly matched: got=%v err=%v", got, err)
	}
	if got := validator.sourceCache.Load().lookup(sourceKey, time.Now().UnixNano()).count; got != 0 {
		t.Fatalf("failed authentication populated source cache: count=%d", got)
	}

	for index, userIndex := range []int{600, 700, 800, 900} {
		authenticateSSUserWithSource(t, validator, users[userIndex], source, uint64(8100+index))
	}
	candidates := validator.sourceCache.Load().lookup(sourceKey, time.Now().UnixNano())
	if candidates.count != 4 {
		t.Fatalf("candidate count: got=%d want=4", candidates.count)
	}
	for index, userIndex := range []int{900, 800, 700, 600} {
		if candidates.users[index] != users[userIndex] {
			t.Fatalf("candidate %d: got=%v want=%v", index, candidates.users[index], users[userIndex])
		}
	}

	attempts, restore := countSSCandidateAttempts(users)
	defer restore()
	wire := benchmarkSSDeterministicTCPAuthWire(t, users[800], 8200)
	*attempts = 0
	got, _, _, _, err := validator.GetWithSource(wire, protocol.RequestCommandTCP, source)
	if err != nil || got != users[800] {
		t.Fatalf("cached CGNAT user: got=%v err=%v", got, err)
	}
	if *attempts != 2 {
		t.Fatalf("cached candidate attempts: got=%d want=2", *attempts)
	}

	*attempts = 0
	wrongWire = benchmarkSSDeterministicTCPAuthWire(t, wrongUser, 8201)
	got, _, _, _, err = validator.GetWithSource(wrongWire, protocol.RequestCommandTCP, source)
	if err != ErrNotFound || got != nil {
		t.Fatalf("invalid request unexpectedly matched: got=%v err=%v", got, err)
	}
	if *attempts != len(users) {
		t.Fatalf("invalid request attempts: got=%d want=%d", *attempts, len(users))
	}
}

func TestValidatorSourceCandidatesCredentialGeneration(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	source := sourceCacheTestAddress(t, "2001:db8::10")
	target := users[250]
	oldWire := benchmarkSSDeterministicTCPAuthWire(t, target, 8300)
	authenticateSSUserWithSource(t, validator, target, source, 8301)

	if err := validator.Del(target.Email); err != nil {
		t.Fatal(err)
	}
	if got, _, _, _, err := validator.GetWithSource(oldWire, protocol.RequestCommandTCP, source); err != ErrNotFound || got != nil {
		t.Fatalf("deleted credential remained valid: got=%v err=%v", got, err)
	}

	replacement := &protocol.MemoryUser{
		Email:   target.Email,
		Account: mustSSBenchmarkAccount(t, "source-cache-replacement"),
	}
	if err := validator.Add(replacement); err != nil {
		t.Fatal(err)
	}
	authenticateSSUserWithSource(t, validator, replacement, source, 8302)
	if got, _, _, _, err := validator.GetWithSource(oldWire, protocol.RequestCommandTCP, source); err != ErrNotFound || got != nil {
		t.Fatalf("old credential matched after replacement: got=%v err=%v", got, err)
	}

	key, _ := authSourceKeyFromAddress(source)
	candidates := validator.sourceCache.Load().lookup(key, time.Now().UnixNano())
	if candidates.count == 0 || candidates.users[0] != replacement {
		t.Fatal("replacement credential was not the most recent source candidate")
	}
}

func TestSourceCandidateCacheTTLAddressFamilyAndCapacity(t *testing.T) {
	cache := newSourceCandidateCache(4096, 4, time.Second)
	user := &protocol.MemoryUser{}
	now := time.Now().UnixNano()
	for _, raw := range []string{"192.0.2.20", "2001:db8::20"} {
		key, ok := authSourceKeyFromAddress(sourceCacheTestAddress(t, raw))
		if !ok {
			t.Fatalf("source key for %s was not created", raw)
		}
		cache.recordSuccess(key, user, now)
		if got := cache.lookup(key, now).count; got != 1 {
			t.Fatalf("live entry %s: got=%d want=1", raw, got)
		}
		if got := cache.lookup(key, now+int64(2*time.Second)).count; got != 0 {
			t.Fatalf("expired entry %s: got=%d want=0", raw, got)
		}
	}
	if got, want := len(cache.buckets)*sourceCacheWays, 4096; got != want {
		t.Fatalf("fixed cache capacity: got=%d want=%d", got, want)
	}
	cacheBytes := uintptr(len(cache.buckets))*unsafe.Sizeof(sourceCandidateBucket{}) + unsafe.Sizeof(*cache)
	if tenSiteBytes := cacheBytes * 10; tenSiteBytes > 16<<20 {
		t.Fatalf("ten-site source cache exceeds ideal budget: got=%d bytes", tenSiteBytes)
	}
}

func TestSourceCandidateCacheBypassesHighFanoutWithoutDisablingSmallNAT(t *testing.T) {
	cache := newSourceCandidateCache(64, 8, time.Minute)
	key, ok := authSourceKeyFromAddress(sourceCacheTestAddress(t, "198.51.100.90"))
	if !ok {
		t.Fatal("source key was not created")
	}
	now := time.Now().UnixNano()
	users := make([]*protocol.MemoryUser, 32)
	for index := range users {
		users[index] = &protocol.MemoryUser{Email: fmt.Sprintf("high-fanout-%d@example.invalid", index)}
		cache.recordMissSuccess(key, users[index], now+int64(index))
	}

	bypassed := cache.lookup(key, now+int64(len(users)))
	if bypassed.count != 0 || bypassed.bypassUntil <= now {
		t.Fatalf("high-fanout source was not bypassed: count=%d bypassUntil=%d", bypassed.count, bypassed.bypassUntil)
	}

	smallKey, _ := authSourceKeyFromAddress(sourceCacheTestAddress(t, "198.51.100.91"))
	for index := 0; index < 8; index++ {
		cache.recordMissSuccess(smallKey, users[index], now+int64(index))
	}
	for iteration := 0; iteration < 64; iteration++ {
		cache.recordSuccess(smallKey, users[iteration%8], now+100+int64(iteration))
	}
	small := cache.lookup(smallKey, now+1000)
	if small.count != 8 || small.bypassUntil > now+1000 {
		t.Fatalf("small NAT was incorrectly bypassed: count=%d bypassUntil=%d", small.count, small.bypassUntil)
	}
}

func TestSourceCandidatesTCPAndUDPEntryPoints(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	source := sourceCacheTestAddress(t, "198.51.100.88")
	key, _ := authSourceKeyFromAddress(source)

	tcpWire := benchmarkSSTCPWire(t, users[200])
	request, _, err := readTCPSessionWithSource(validator, bytes.NewReader(tcpWire), source)
	if err != nil || request.User != users[200] {
		t.Fatalf("TCP source-aware authentication: request=%v err=%v", request, err)
	}
	if candidates := validator.sourceCache.Load().lookup(key, time.Now().UnixNano()); candidates.count != 1 || candidates.users[0] != users[200] {
		t.Fatal("TCP entry point did not update source candidates")
	}

	udpPayload := buf.FromBytes(benchmarkSSUDPWire(t, users[201]))
	defer udpPayload.Release()
	request, _, err = decodeUDPPacketWithSource(validator, udpPayload, source)
	if err != nil || request.User != users[201] {
		t.Fatalf("UDP source-aware authentication: request=%v err=%v", request, err)
	}
	if candidates := validator.sourceCache.Load().lookup(key, time.Now().UnixNano()); candidates.count != 2 || candidates.users[0] != users[201] || candidates.users[1] != users[200] {
		t.Fatal("UDP entry point did not update source candidates in MRU order")
	}
}

func TestValidatorSourceCandidatesConcurrentAuthenticationAndUpdate(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	source := sourceCacheTestAddress(t, "203.0.113.40")
	wires := make([][]byte, 4)
	for index := range wires {
		wires[index] = benchmarkSSDeterministicTCPAuthWire(t, users[index], uint64(8400+index))
	}

	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				got, _, _, _, err := validator.GetWithSource(wires[worker], protocol.RequestCommandTCP, source)
				if err != nil || got != users[worker] {
					t.Errorf("worker %d authentication: got=%v err=%v", worker, got, err)
					return
				}
			}
		}()
	}
	for index := 0; index < 20; index++ {
		user := &protocol.MemoryUser{
			Email:   fmt.Sprintf("source-concurrent-%d@example.invalid", index),
			Account: mustSSBenchmarkAccount(t, fmt.Sprintf("source-concurrent-%d", index)),
		}
		if err := validator.Add(user); err != nil {
			t.Fatal(err)
		}
		if err := validator.Del(user.Email); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
}
