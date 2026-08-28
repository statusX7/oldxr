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
	users [maxSourceCandidates]*protocol.MemoryUser
	count int
}

type sourceCandidateEntry struct {
	key      authSourceKey
	users    [maxSourceCandidates]*protocol.MemoryUser
	lastSeen int64
	count    uint8
	occupied bool
}

type sourceCandidateBucket struct {
	sync.RWMutex
	entries [sourceCacheWays]sourceCandidateEntry
}

// sourceCandidateCache is a fixed-size, set-associative hint table. A cache
// miss can only make authentication slower; it never changes the complete
// cryptographic fallback or the set of valid users.
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
		candidates.count = int(entry.count)
		copy(candidates.users[:candidates.count], entry.users[:candidates.count])
		return candidates
	}
	return sourceCandidateSet{}
}

func (c *sourceCandidateCache) recordSuccess(key authSourceKey, user *protocol.MemoryUser, now int64) {
	if c == nil || user == nil {
		return
	}
	bucket := c.bucketFor(key)
	bucket.Lock()
	defer bucket.Unlock()

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
