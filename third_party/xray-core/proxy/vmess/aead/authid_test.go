package aead

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateAuthID(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)
}

func TestCreateAuthIDAndDecode(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)
}

func TestCreateAuthIDAndDecode2(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test")
	authid2 := CreateAuthID(key2, time.Now().Unix())

	res2, err2 := AuthDecoder.Match(authid2)
	assert.EqualError(t, err2, "user do not exist")
	assert.Nil(t, res2)
}

func TestCreateAuthIDAndDecodeMassive(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	for i := 0; i <= 10000; i++ {
		key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test", strconv.Itoa(i))
		var keyw2 [16]byte
		copy(keyw2[:], key2)
		AuthDecoder.AddUser(keyw2, "Demo User"+strconv.Itoa(i))
	}

	authid3 := CreateAuthID(key, time.Now().Unix())

	res2, err2 := AuthDecoder.Match(authid3)
	assert.Equal(t, "Demo User", res2)
	assert.Nil(t, err2)
}

func TestCreateAuthIDAndDecodeSuperMassive(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	for i := 0; i <= 1000000; i++ {
		key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test", strconv.Itoa(i))
		var keyw2 [16]byte
		copy(keyw2[:], key2)
		AuthDecoder.AddUser(keyw2, "Demo User"+strconv.Itoa(i))
	}

	authid3 := CreateAuthID(key, time.Now().Unix())

	before := time.Now()
	res2, err2 := AuthDecoder.Match(authid3)
	after := time.Now()
	assert.Equal(t, "Demo User", res2)
	assert.Nil(t, err2)

	fmt.Println(after.Sub(before).Seconds())
}

func deterministicAuthID(cmdKey []byte, timestamp int64, random uint32, validChecksum bool) [16]byte {
	var plaintext [16]byte
	binary.BigEndian.PutUint64(plaintext[:8], uint64(timestamp))
	binary.BigEndian.PutUint32(plaintext[8:12], random)
	checksum := crc32.ChecksumIEEE(plaintext[:12])
	if !validChecksum {
		checksum ^= 1
	}
	binary.BigEndian.PutUint32(plaintext[12:], checksum)
	var authID [16]byte
	NewCipherFromKey(cmdKey).Encrypt(authID[:], plaintext[:])
	return authID
}

func authIDTestKey(seed string) [16]byte {
	derived := KDF16([]byte(seed), "AuthID exact replay test")
	var key [16]byte
	copy(key[:], derived)
	return key
}

func TestAuthIDDecoderHolderTracksExactIDs(t *testing.T) {
	key := authIDTestKey("exact IDs")
	holder := NewAuthIDDecoderHolder()
	holder.AddUser(key, "exact user")
	now := time.Now().Unix()
	first := deterministicAuthID(key[:], now, 1, true)
	second := deterministicAuthID(key[:], now, 2, true)

	for index, authID := range [][16]byte{first, second} {
		got, err := holder.Match(authID)
		if err != nil || got != "exact user" {
			t.Fatalf("valid AuthID %d: got=%v err=%v", index, got, err)
		}
	}
	if got, err := holder.Match(first); err != ErrReplay || got != nil {
		t.Fatalf("duplicate AuthID: got=%v err=%v", got, err)
	}
}

func TestAuthIDDecoderHolderConcurrentDuplicate(t *testing.T) {
	key := authIDTestKey("concurrent duplicate")
	holder := NewAuthIDDecoderHolder()
	holder.AddUser(key, "concurrent user")
	authID := deterministicAuthID(key[:], time.Now().Unix(), 1, true)

	const goroutines = 128
	start := make(chan struct{})
	var successes atomic.Int64
	var replays atomic.Int64
	var failures atomic.Int64
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wait.Done()
			<-start
			got, err := holder.Match(authID)
			switch {
			case err == nil && got == "concurrent user":
				successes.Add(1)
			case err == ErrReplay && got == nil:
				replays.Add(1)
			default:
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful matches=%d want=1", got)
	}
	if got := replays.Load(); got != goroutines-1 {
		t.Fatalf("replay matches=%d want=%d", got, goroutines-1)
	}
	if got := failures.Load(); got != 0 {
		t.Fatalf("unexpected results=%d", got)
	}
}

func TestAuthIDDecoderHolderPreservesValidationErrors(t *testing.T) {
	key := authIDTestKey("known user")
	unknownKey := authIDTestKey("unknown user")
	now := time.Now().Unix()

	tests := []struct {
		name   string
		authID [16]byte
	}{
		{name: "invalid CRC", authID: deterministicAuthID(key[:], now, 1, false)},
		{name: "unknown user", authID: deterministicAuthID(unknownKey[:], now, 1, true)},
		{name: "expired", authID: deterministicAuthID(key[:], now-121, 2, true)},
		{name: "future", authID: deterministicAuthID(key[:], now+121, 3, true)},
		{name: "negative time", authID: deterministicAuthID(key[:], -1, 4, true)},
	}
	valid := deterministicAuthID(key[:], now, 5, true)
	var truncated [16]byte
	copy(truncated[:8], valid[:8])
	tests = append(tests, struct {
		name   string
		authID [16]byte
	}{name: "zero-padded truncated block", authID: truncated})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			holder := NewAuthIDDecoderHolder()
			holder.AddUser(key, "known user")
			got, err := holder.Match(test.authID)
			if err != ErrNotFound || got != nil {
				t.Fatalf("got=%v err=%v want nil/%v", got, err, ErrNotFound)
			}
		})
	}

	for _, delta := range []int64{-120, 120} {
		if !validAuthIDTime(now+delta, now) {
			t.Fatalf("boundary timestamp delta=%d was rejected", delta)
		}
	}
	for _, delta := range []int64{-121, 121} {
		if validAuthIDTime(now+delta, now) {
			t.Fatalf("out-of-window timestamp delta=%d was accepted", delta)
		}
	}
}

func TestAuthIDDecoderHolderKeepsReplayHistoryAcrossUserUpdates(t *testing.T) {
	oldKey := authIDTestKey("old credential")
	newKey := authIDTestKey("new credential")
	now := time.Now().Unix()
	holder := NewAuthIDDecoderHolder()
	holder.AddUser(oldKey, "old ticket")
	original := deterministicAuthID(oldKey[:], now, 1, true)
	if got, err := holder.Match(original); err != nil || got != "old ticket" {
		t.Fatalf("initial match: got=%v err=%v", got, err)
	}

	holder.RemoveUser(oldKey)
	if got, err := holder.Match(deterministicAuthID(oldKey[:], now, 2, true)); err != ErrNotFound || got != nil {
		t.Fatalf("removed credential matched: got=%v err=%v", got, err)
	}
	holder.AddUser(oldKey, "re-added ticket")
	if got, err := holder.Match(original); err != ErrReplay || got != nil {
		t.Fatalf("re-add cleared replay history: got=%v err=%v", got, err)
	}

	holder.RemoveUser(oldKey)
	holder.AddUser(newKey, "new ticket")
	if got, err := holder.Match(deterministicAuthID(oldKey[:], now, 3, true)); err != ErrNotFound || got != nil {
		t.Fatalf("old credential matched after replacement: got=%v err=%v", got, err)
	}
	newAuthID := deterministicAuthID(newKey[:], now, 4, true)
	if got, err := holder.Match(newAuthID); err != nil || got != "new ticket" {
		t.Fatalf("replacement credential: got=%v err=%v", got, err)
	}

	recreated := NewAuthIDDecoderHolder()
	recreated.AddUser(newKey, "recreated ticket")
	if got, err := recreated.Match(newAuthID); err != nil || got != "recreated ticket" {
		t.Fatalf("new holder inherited old replay state: got=%v err=%v", got, err)
	}
}

func TestAuthIDReplayDoesNotChangeAEADFailure(t *testing.T) {
	key := authIDTestKey("AEAD failure")
	authID := deterministicAuthID(key[:], time.Now().Unix(), 1, true)
	holder := NewAuthIDDecoderHolder()
	holder.AddUser(key, "AEAD user")
	if got, err := holder.Match(authID); err != nil || got != "AEAD user" {
		t.Fatalf("AuthID match: got=%v err=%v", got, err)
	}
	if _, _, _, err := OpenVMessAEADHeader(key, authID, bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("truncated AEAD header was accepted")
	}
}
