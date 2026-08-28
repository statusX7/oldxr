package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/protocol"
)

const (
	defaultHotUserCapacity        = 128
	defaultHotUserRebuildInterval = 30 * time.Second
	hotUserMinimumPopulation      = 256
	hotUserClockSampleMask        = 63
)

type hotUserCounter struct {
	successes atomic.Uint64
}

type authSnapshot struct {
	ordered  []*protocol.MemoryUser
	counters map[*protocol.MemoryUser]*hotUserCounter
	hotCount int
}

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	authSnapshot atomic.Pointer[authSnapshot]
	hotCounters  map[*protocol.MemoryUser]*hotUserCounter

	hotCapacity        int
	hotRebuildInterval time.Duration
	hotSuccessEvents   atomic.Uint64
	hotNextRebuild     atomic.Int64
	hotRebuildPending  atomic.Bool

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = newError("Not Found")

func (v *Validator) effectiveHotCapacity() int {
	if v.hotCapacity < 0 {
		return 0
	}
	if v.hotCapacity > 0 {
		return v.hotCapacity
	}
	return defaultHotUserCapacity
}

func (v *Validator) effectiveHotRebuildInterval() time.Duration {
	if v.hotRebuildInterval > 0 {
		return v.hotRebuildInterval
	}
	return defaultHotUserRebuildInterval
}

func hotUserEligible(user *protocol.MemoryUser) bool {
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return false
	}
	cipher, ok := account.Cipher.(*AEADCipher)
	return ok && cipher.KeySize() == 16 && cipher.IVSize() == 16
}

func (v *Validator) initializeHotRebuildDeadline() {
	if v.hotNextRebuild.Load() != 0 {
		return
	}
	next := time.Now().Add(v.effectiveHotRebuildInterval()).UnixNano()
	v.hotNextRebuild.CompareAndSwap(0, next)
}

func (v *Validator) updateBehaviorSeed(account *MemoryAccount) {
	if v.behaviorFused {
		return
	}
	hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
	hashkdf.Write(account.Key)
	v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
}

func (v *Validator) publishUsersLocked() {
	if len(v.users) < hotUserMinimumPopulation || v.effectiveHotCapacity() == 0 {
		v.hotCounters = nil
		v.authSnapshot.Store(nil)
		return
	}

	if v.hotCounters == nil {
		v.hotCounters = make(map[*protocol.MemoryUser]*hotUserCounter, len(v.users))
	}
	for _, user := range v.users {
		if hotUserEligible(user) {
			if _, found := v.hotCounters[user]; !found {
				v.hotCounters[user] = new(hotUserCounter)
			}
		}
	}

	immutableCounters := make(map[*protocol.MemoryUser]*hotUserCounter, len(v.hotCounters))
	for user, counter := range v.hotCounters {
		immutableCounters[user] = counter
	}

	ordered := make([]*protocol.MemoryUser, 0, len(v.users))
	hotCount := 0
	seen := make(map[*protocol.MemoryUser]struct{}, len(v.users))
	presentUsers := make(map[*protocol.MemoryUser]struct{}, len(v.users))
	for _, user := range v.users {
		presentUsers[user] = struct{}{}
	}
	if previous := v.authSnapshot.Load(); previous != nil {
		for index, user := range previous.ordered {
			if _, found := immutableCounters[user]; !found && hotUserEligible(user) {
				continue
			}
			if _, present := presentUsers[user]; !present {
				continue
			}
			ordered = append(ordered, user)
			seen[user] = struct{}{}
			if index < previous.hotCount {
				hotCount++
			}
		}
	}
	for _, user := range v.users {
		if _, found := seen[user]; found {
			continue
		}
		ordered = append(ordered, user)
	}
	v.authSnapshot.Store(&authSnapshot{
		ordered:  ordered,
		counters: immutableCounters,
		hotCount: hotCount,
	})
	v.initializeHotRebuildDeadline()
}

func (v *Validator) addUsers(users []*protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	simulatedLength := len(v.users)
	for _, user := range users {
		account := user.Account.(*MemoryAccount)
		if !account.Cipher.IsAEAD() && simulatedLength > 0 {
			return newError("The cipher is not support Single-port Multi-user")
		}
		simulatedLength++
	}
	for _, user := range users {
		v.users = append(v.users, user)
		v.updateBehaviorSeed(user.Account.(*MemoryAccount))
	}
	v.publishUsersLocked()
	return nil
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	return v.addUsers([]*protocol.MemoryUser{u})
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return newError("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return newError("User ", email, " not found.")
	}
	ulen := len(v.users)
	removed := v.users[idx]

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]
	if v.hotCounters != nil {
		delete(v.hotCounters, removed)
	}
	v.publishUsersLocked()

	return nil
}

func (v *Validator) recordHotSuccess(counter *hotUserCounter) {
	if counter == nil {
		return
	}
	counter.successes.Add(1)
	if v.hotSuccessEvents.Add(1)&hotUserClockSampleMask != 0 {
		return
	}
	now := time.Now()
	if now.UnixNano() < v.hotNextRebuild.Load() {
		return
	}
	if !v.hotRebuildPending.CompareAndSwap(false, true) {
		return
	}
	go v.rebuildHotSnapshot(now)
}

func (v *Validator) rebuildHotSnapshot(now time.Time) {
	defer v.hotRebuildPending.Store(false)

	v.Lock()
	defer v.Unlock()
	v.hotNextRebuild.Store(now.Add(v.effectiveHotRebuildInterval()).UnixNano())
	current := v.authSnapshot.Load()
	capacity := v.effectiveHotCapacity()
	if current == nil || capacity == 0 || len(v.users) < hotUserMinimumPopulation {
		return
	}

	type scoredUser struct {
		user      *protocol.MemoryUser
		score     uint64
		baseIndex int
	}
	scored := make([]scoredUser, 0, len(v.hotCounters))
	for baseIndex, user := range v.users {
		if counter := v.hotCounters[user]; counter != nil {
			if score := counter.successes.Swap(0); score > 0 {
				scored = append(scored, scoredUser{user: user, score: score, baseIndex: baseIndex})
			}
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].baseIndex < scored[j].baseIndex
	})
	if len(scored) > capacity {
		scored = scored[:capacity]
	}

	hot := make(map[*protocol.MemoryUser]struct{}, len(scored))
	ordered := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, candidate := range scored {
		hot[candidate.user] = struct{}{}
		ordered = append(ordered, candidate.user)
	}
	for _, user := range v.users {
		if _, found := hot[user]; !found {
			ordered = append(ordered, user)
		}
	}
	v.authSnapshot.Store(&authSnapshot{
		ordered:  ordered,
		counters: current.counters,
		hotCount: len(scored),
	})
}

func getShadowsocksUser(users []*protocol.MemoryUser, bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	var subkey []byte
	var data []byte
	for _, user := range users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			if int32(cap(subkey)) < aeadCipher.KeyBytes {
				subkey = make([]byte, aeadCipher.KeyBytes)
			} else {
				subkey = subkey[:aeadCipher.KeyBytes]
			}
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				dataLen := 4 + aead.NonceSize()
				if cap(data) < dataLen {
					data = make([]byte, dataLen)
				} else {
					data = data[:dataLen]
				}
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				if cap(data) < 8192 {
					data = make([]byte, 8192)
				} else {
					data = data[:8192]
				}
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				err = account.CheckIV(iv)
				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			return
		}
	}

	return nil, nil, nil, 0, ErrNotFound
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	if snapshot := v.authSnapshot.Load(); snapshot != nil {
		u, aead, ret, ivLen, err = getShadowsocksUser(snapshot.ordered, bs, command)
		if err == nil && u != nil {
			v.recordHotSuccess(snapshot.counters[u])
		}
		return
	}

	v.RLock()
	defer v.RUnlock()
	return getShadowsocksUser(v.users, bs, command)
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
