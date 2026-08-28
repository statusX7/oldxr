package shadowsocks

import (
	"hash/maphash"
	"sync"
	"time"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const (
	defaultSourceCacheMaxSources          = 4096
	defaultSourceCacheCandidatesPerSource = 8
	defaultSourceCacheTTL                 = 10 * time.Minute
	defaultSourceCacheMissBurst           = 16
	defaultSourceCacheBypassCooldown      = 30 * time.Second
	sourceCacheWays                       = 4
	maxSourceCandidates                   = 8
)

type authSourceKey struct {
	address [16]byte
	family  uint8
}

func authSourceKeyFromAddress(address xraynet.Address) (authSourceKey, bool) {
	if address == nil || !address.Family().IsIP() {
		return authSourceKey{}, false
	}
	ip := address.IP()
	if ipv4 := ip.To4(); ipv4 != nil {
		var key authSourceKey
		key.family = 4
		copy(key.address[:4], ipv4)
		return key, true
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		var key authSourceKey
		key.family = 6
		copy(key.address[:], ipv6)
		return key, true
	}
	return authSourceKey{}, false
}

type sourceCandidateSet struct {
	users        [maxSourceCandidates]*protocol.MemoryUser
	count        int
	blockedUntil int64
	bypassUntil  int64
}

type sourceCandidateEntry struct {
	key          authSourceKey
	users        [maxSourceCandidates]*protocol.MemoryUser
	lastSeen     int64
	blockedUntil int64
	bypassUntil  int64
	count        uint8
	failures     uint8
	misses       uint8
	occupied     bool
}

type sourceCandidateBucket struct {
	sync.RWMutex
	entries [sourceCacheWays]sourceCandidateEntry
}

// sourceCandidateCache is a fixed-size, set-associative hint table. Its user
// entries only change candidate order and never establish identity. A separate
// failed-auth admission decision may defer the cold remainder after the hint
// and active sets miss; every accepted user still passes full verification.
type sourceCandidateCache struct {
	seed                maphash.Seed
	buckets             []sourceCandidateBucket
	bucketMask          uint64
	candidatesPerSource int
	ttlNanos            int64
}

func newSourceCandidateCache(maxSources, candidatesPerSource int, ttl time.Duration) *sourceCandidateCache {
	if maxSources <= 0 || candidatesPerSource <= 0 || ttl <= 0 {
		return nil
	}
	if candidatesPerSource > maxSourceCandidates {
		candidatesPerSource = maxSourceCandidates
	}
	bucketCount := 1
	wantedBuckets := (maxSources + sourceCacheWays - 1) / sourceCacheWays
	for bucketCount < wantedBuckets {
		bucketCount <<= 1
	}
	return &sourceCandidateCache{
		seed:                maphash.MakeSeed(),
		buckets:             make([]sourceCandidateBucket, bucketCount),
		bucketMask:          uint64(bucketCount - 1),
		candidatesPerSource: candidatesPerSource,
		ttlNanos:            int64(ttl),
	}
}

func (c *sourceCandidateCache) bucketFor(key authSourceKey) *sourceCandidateBucket {
	hash := maphash.Bytes(c.seed, key.address[:])
	hash ^= uint64(key.family) * 0x9e3779b97f4a7c15
	return &c.buckets[hash&c.bucketMask]
}

func (c *sourceCandidateCache) lookup(key authSourceKey, now int64) sourceCandidateSet {
	if c == nil {
		return sourceCandidateSet{}
	}
	bucket := c.bucketFor(key)
	bucket.RLock()
	defer bucket.RUnlock()
	for index := range bucket.entries {
		entry := &bucket.entries[index]
		if !entry.occupied || entry.key != key || now-entry.lastSeen > c.ttlNanos {
			continue
		}
		var candidates sourceCandidateSet
		candidates.blockedUntil = entry.blockedUntil
		candidates.bypassUntil = entry.bypassUntil
		if now < entry.bypassUntil {
			return candidates
		}
		candidates.count = int(entry.count)
		copy(candidates.users[:candidates.count], entry.users[:candidates.count])
		return candidates
	}
	return sourceCandidateSet{}
}

func (c *sourceCandidateCache) findOrReplaceEntryLocked(bucket *sourceCandidateBucket, key authSourceKey, now int64) *sourceCandidateEntry {
	entryIndex := -1
	replaceIndex := 0
	oldestSeen := int64(^uint64(0) >> 1)
	for index := range bucket.entries {
		entry := &bucket.entries[index]
		if entry.occupied && entry.key == key && now-entry.lastSeen <= c.ttlNanos {
			entryIndex = index
			break
		}
		if !entry.occupied || now-entry.lastSeen > c.ttlNanos {
			replaceIndex = index
			oldestSeen = -1
			continue
		}
		if oldestSeen >= 0 && entry.lastSeen < oldestSeen {
			oldestSeen = entry.lastSeen
			replaceIndex = index
		}
	}
	if entryIndex < 0 {
		entryIndex = replaceIndex
		bucket.entries[entryIndex] = sourceCandidateEntry{key: key, occupied: true}
	}
	entry := &bucket.entries[entryIndex]
	entry.lastSeen = now
	return entry
}

func (c *sourceCandidateCache) promoteUserLocked(entry *sourceCandidateEntry, user *protocol.MemoryUser) {
	userIndex := -1
	for index := 0; index < int(entry.count); index++ {
		if entry.users[index] == user {
			userIndex = index
			break
		}
	}
	if userIndex == 0 {
		return
	}
	if userIndex > 0 {
		copy(entry.users[1:userIndex+1], entry.users[:userIndex])
		entry.users[0] = user
		return
	}
	limit := c.candidatesPerSource
	if int(entry.count) < limit {
		entry.count++
	}
	copy(entry.users[1:int(entry.count)], entry.users[:int(entry.count)-1])
	entry.users[0] = user
}

func (c *sourceCandidateCache) recordSuccess(key authSourceKey, user *protocol.MemoryUser, now int64) {
	if c == nil || user == nil {
		return
	}
	bucket := c.bucketFor(key)
	bucket.Lock()
	defer bucket.Unlock()
	entry := c.findOrReplaceEntryLocked(bucket, key, now)
	if now < entry.bypassUntil {
		return
	}
	if entry.misses > 0 {
		entry.misses--
	}
	c.promoteUserLocked(entry, user)
}

// recordMissSuccess learns a fully authenticated user after the source hint
// missed. A high-fanout NAT that repeatedly overflows the small candidate set
// is temporarily bypassed so it cannot add several doomed cryptographic
// attempts to every connection. The immutable global/cold fallback remains
// complete and unchanged.
func (c *sourceCandidateCache) recordMissSuccess(key authSourceKey, user *protocol.MemoryUser, now int64) {
	if c == nil || user == nil {
		return
	}
	bucket := c.bucketFor(key)
	bucket.Lock()
	defer bucket.Unlock()
	entry := c.findOrReplaceEntryLocked(bucket, key, now)
	if now < entry.bypassUntil {
		return
	}
	if entry.bypassUntil != 0 {
		entry.bypassUntil = 0
		entry.misses = 0
	}
	if int(entry.count) >= c.candidatesPerSource {
		if entry.misses < defaultSourceCacheMissBurst {
			entry.misses++
		}
		if entry.misses >= defaultSourceCacheMissBurst {
			for index := range entry.users {
				entry.users[index] = nil
			}
			entry.count = 0
			entry.bypassUntil = now + int64(defaultSourceCacheBypassCooldown)
			return
		}
	}
	c.promoteUserLocked(entry, user)
}

func (c *sourceCandidateCache) recordFailure(key authSourceKey, now int64, burst uint8, cooldown time.Duration) {
	if c == nil || burst == 0 || cooldown <= 0 {
		return
	}
	bucket := c.bucketFor(key)
	bucket.Lock()
	defer bucket.Unlock()
	entry := c.findOrReplaceEntryLocked(bucket, key, now)
	if entry.failures < burst {
		entry.failures++
	}
	if entry.failures >= burst {
		entry.blockedUntil = now + int64(cooldown)
	}
}

func (c *sourceCandidateCache) clearFailures(key authSourceKey, now int64) {
	if c == nil {
		return
	}
	bucket := c.bucketFor(key)
	bucket.Lock()
	defer bucket.Unlock()
	for index := range bucket.entries {
		entry := &bucket.entries[index]
		if !entry.occupied || entry.key != key || now-entry.lastSeen > c.ttlNanos {
			continue
		}
		entry.failures = 0
		entry.blockedUntil = 0
		return
	}
}
