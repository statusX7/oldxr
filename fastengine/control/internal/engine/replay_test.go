package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestReplayFilterIdentityIsolation(t *testing.T) {
	f := NewReplayFilter(128)
	salt := []byte("0123456789abcdef")
	if f.CheckAndAdd(1, 10, salt) {
		t.Fatal("first salt was reported as replay")
	}
	if !f.CheckAndAdd(1, 10, salt) {
		t.Fatal("same user replay was accepted")
	}
	if f.CheckAndAdd(1, 11, salt) {
		t.Fatal("same salt for a different user was rejected")
	}
	if f.CheckAndAdd(2, 10, salt) {
		t.Fatal("same salt for a different site scope was rejected")
	}
}

func TestReplayFilterSamePanelNodeIDUsesDifferentSiteScopes(t *testing.T) {
	f := NewReplayFilter(128)
	salt := []byte("same-node-id-iv!")
	if f.CheckAndAdd(101, 9, salt) {
		t.Fatal("first site insert failed")
	}
	if f.CheckAndAdd(202, 9, salt) {
		t.Fatal("same NodeID/UID/salt in a different site scope was rejected")
	}
	if !f.CheckAndAdd(101, 9, salt) {
		t.Fatal("same site/user replay was accepted")
	}
}

func TestReplayFilterConcurrentDuplicate(t *testing.T) {
	f := NewReplayFilter(128)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !f.CheckAndAdd(1, 1, []byte("concurrent-salt!")) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted duplicates = %d, want 1", got)
	}
}

func TestReplayFilterBoundedEviction(t *testing.T) {
	f := NewReplayFilter(32)
	first := []byte("first-salt-value")
	if f.CheckAndAdd(1, 1, first) {
		t.Fatal("first insert failed")
	}
	for i := 0; i < 4096; i++ {
		salt := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		f.CheckAndAdd(1, 1, salt)
	}
	// Eviction is shard-local, so drive the first key's shard until it leaves.
	for i := 4096; f.CheckAndAdd(1, 1, first); i++ {
		salt := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24), first[0]}
		f.CheckAndAdd(1, 1, salt)
		if i > 100000 {
			t.Fatal("entry did not leave bounded replay set")
		}
	}
}
