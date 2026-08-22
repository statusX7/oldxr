package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

const replayShards = 32

type replayKey [16]byte

type replayShard struct {
	mu   sync.Mutex
	seen map[replayKey]struct{}
	ring []replayKey
	next int
	full bool
}

// ReplayFilter is a bounded, engine-wide replay set. The identity is part of
// the key: the same salt is valid for two different credentials or site scopes,
// but a replay for the same site/user is rejected. Sharding keeps authentication locks out
// of the steady-state data path.
type ReplayFilter struct {
	shards [replayShards]replayShard
}

func NewReplayFilter(capacity int) *ReplayFilter {
	if capacity < replayShards {
		capacity = replayShards
	}
	f := &ReplayFilter{}
	perShard := (capacity + replayShards - 1) / replayShards
	for i := range f.shards {
		f.shards[i].seen = make(map[replayKey]struct{}, perShard)
		f.shards[i].ring = make([]replayKey, perShard)
	}
	return f
}

func makeReplayKey(scope uint64, userID int, salt []byte) replayKey {
	var identity [16]byte
	binary.BigEndian.PutUint64(identity[:8], scope)
	binary.BigEndian.PutUint64(identity[8:], uint64(userID))
	h := sha256.New()
	h.Write(identity[:])
	h.Write(salt)
	sum := h.Sum(nil)
	var key replayKey
	copy(key[:], sum[:len(key)])
	return key
}

// CheckAndAdd returns true when key was already present.
func (f *ReplayFilter) CheckAndAdd(scope uint64, userID int, salt []byte) bool {
	key := makeReplayKey(scope, userID, salt)
	shard := &f.shards[int(key[0])%len(f.shards)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if _, exists := shard.seen[key]; exists {
		return true
	}
	if shard.full {
		delete(shard.seen, shard.ring[shard.next])
	}
	shard.ring[shard.next] = key
	shard.seen[key] = struct{}{}
	shard.next++
	if shard.next == len(shard.ring) {
		shard.next = 0
		shard.full = true
	}
	return false
}
