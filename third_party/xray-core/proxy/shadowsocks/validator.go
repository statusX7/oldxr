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
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const (
	defaultHotUserCapacity        = 1024
	defaultHotUserRebuildInterval = 15 * time.Second
	hotUserMinimumPopulation      = 256
	hotUserClockSampleMask        = 63
)

type hotUserCounter struct {
	successes atomic.Uint64
}

type authSnapshot struct {
	ordered  []*protocol.MemoryUser
	counters map[*protocol.MemoryUser]*hotUserCounter
	ranks    map[*protocol.MemoryUser]uint32
	hotCount int
}

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	authSnapshot atomic.Pointer[authSnapshot]
	hotCounters  map[*protocol.MemoryUser]*hotUserCounter

	hotCapacity           int
	hotRebuildInterval    time.Duration
	hotSuccessEvents      atomic.Uint64
	hotNextRebuild        atomic.Int64
	hotRebuildPending     atomic.Bool
	sourceCache           atomic.Pointer[sourceCandidateCache]
	sourceMaxSources      int
	sourceCandidates      int
	sourceTTL             time.Duration
	failedAuthDisabled    bool
	sourceFailureBurst    int
	sourceFailureCooldown time.Duration
	authMetrics           validatorAuthMetrics

	behaviorSeed  uint64
	behaviorFused bool
}

func newAuthSnapshot(ordered []*protocol.MemoryUser, counters map[*protocol.MemoryUser]*hotUserCounter, hotCount int) *authSnapshot {
	ranks := make(map[*protocol.MemoryUser]uint32, len(ordered))
	for index, user := range ordered {
		ranks[user] = uint32(index + 1)
	}
	return &authSnapshot{
		ordered:  ordered,
		counters: counters,
		ranks:    ranks,
		hotCount: hotCount,
	}
}

func (v *Validator) effectiveSourceMaxSources() int {
	if v.sourceMaxSources < 0 {
		return 0
	}
	if v.sourceMaxSources > 0 {
		return v.sourceMaxSources
	}
	return defaultSourceCacheMaxSources
}

func (v *Validator) effectiveSourceCandidates() int {
	if v.sourceCandidates < 0 {
		return 0
	}
	if v.sourceCandidates > 0 {
		return v.sourceCandidates
	}
	return defaultSourceCacheCandidatesPerSource
}

func (v *Validator) effectiveSourceTTL() time.Duration {
	if v.sourceTTL > 0 {
		return v.sourceTTL
	}
	return defaultSourceCacheTTL
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
		v.sourceCache.Store(nil)
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
	v.authSnapshot.Store(newAuthSnapshot(ordered, immutableCounters, hotCount))
	if v.sourceCache.Load() == nil {
		v.sourceCache.Store(newSourceCandidateCache(v.effectiveSourceMaxSources(), v.effectiveSourceCandidates(), v.effectiveSourceTTL()))
	}
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
	v.authSnapshot.Store(newAuthSnapshot(ordered, current.counters, len(scored)))
}

type shadowsocksUserMatcher struct {
	bs      []byte
	command protocol.RequestCommand
	subkey  []byte
	data    []byte
}

func (m *shadowsocksUserMatcher) try(user *protocol.MemoryUser) (aead cipher.AEAD, ret []byte, ivLen int32, matched bool, err error) {
	account := user.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() {
		return nil, nil, account.Cipher.IVSize(), true, nil
	}

	aeadCipher := account.Cipher.(*AEADCipher)
	ivLen = aeadCipher.IVSize()
	iv := m.bs[:ivLen]
	if int32(cap(m.subkey)) < aeadCipher.KeyBytes {
		m.subkey = make([]byte, aeadCipher.KeyBytes)
	} else {
		m.subkey = m.subkey[:aeadCipher.KeyBytes]
	}
	hkdfSHA1(account.Key, iv, m.subkey)
	aead = aeadCipher.AEADAuthCreator(m.subkey)

	var matchErr error
	switch m.command {
	case protocol.RequestCommandTCP:
		dataLen := 4 + aead.NonceSize()
		if cap(m.data) < dataLen {
			m.data = make([]byte, dataLen)
		} else {
			m.data = m.data[:dataLen]
		}
		ret, matchErr = aead.Open(m.data[:0], m.data[4:], m.bs[ivLen:ivLen+18], nil)
	case protocol.RequestCommandUDP:
		if cap(m.data) < 8192 {
			m.data = make([]byte, 8192)
		} else {
			m.data = m.data[:8192]
		}
		ret, matchErr = aead.Open(m.data[:0], m.data[8192-aead.NonceSize():8192], m.bs[ivLen:], nil)
	}
	if matchErr != nil {
		return nil, nil, 0, false, nil
	}
	return aead, ret, ivLen, true, account.CheckIV(iv)
}

func getShadowsocksUser(users []*protocol.MemoryUser, bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	matcher := shadowsocksUserMatcher{bs: bs, command: command}
	for _, user := range users {
		candidateAEAD, candidateRet, candidateIVLen, matched, matchErr := matcher.try(user)
		if matched {
			return user, candidateAEAD, candidateRet, candidateIVLen, matchErr
		}
	}
	return nil, nil, nil, 0, ErrNotFound
}

func getShadowsocksUserLayered(snapshot *authSnapshot, candidates sourceCandidateSet, bs []byte, command protocol.RequestCommand, sourceColdAllowed bool, budget *coldScanBudget) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, layer authMatchLayer, attempts uint32, coldScanned bool, err error) {
	matcher := shadowsocksUserMatcher{bs: bs, command: command}
	var attemptedRanks [maxSourceCandidates]uint32
	attemptedCount := 0
	for index := 0; index < candidates.count; index++ {
		user := candidates.users[index]
		rank, present := snapshot.ranks[user]
		if !present {
			continue
		}
		duplicate := false
		for attemptedIndex := 0; attemptedIndex < attemptedCount; attemptedIndex++ {
			if attemptedRanks[attemptedIndex] == rank {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		attemptedRanks[attemptedCount] = rank
		attemptedCount++
		attempts++
		candidateAEAD, candidateRet, candidateIVLen, matched, matchErr := matcher.try(user)
		if matched {
			return user, candidateAEAD, candidateRet, candidateIVLen, authMatchSource, attempts, false, matchErr
		}
	}

	hotCount := snapshot.hotCount
	if hotCount > len(snapshot.ordered) {
		hotCount = len(snapshot.ordered)
	}
	for index, user := range snapshot.ordered[:hotCount] {
		rank := uint32(index + 1)
		skip := false
		for attemptedIndex := 0; attemptedIndex < attemptedCount; attemptedIndex++ {
			if attemptedRanks[attemptedIndex] == rank {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		attempts++
		candidateAEAD, candidateRet, candidateIVLen, matched, matchErr := matcher.try(user)
		if matched {
			return user, candidateAEAD, candidateRet, candidateIVLen, authMatchGlobal, attempts, false, matchErr
		}
	}

	if !sourceColdAllowed || budget != nil && !budget.acquire() {
		return nil, nil, nil, 0, authMatchNone, attempts, false, ErrNotFound
	}
	if budget != nil {
		defer budget.release()
	}
	for index := hotCount; index < len(snapshot.ordered); index++ {
		user := snapshot.ordered[index]
		rank := uint32(index + 1)
		skip := false
		for attemptedIndex := 0; attemptedIndex < attemptedCount; attemptedIndex++ {
			if attemptedRanks[attemptedIndex] == rank {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		attempts++
		candidateAEAD, candidateRet, candidateIVLen, matched, matchErr := matcher.try(user)
		if matched {
			return user, candidateAEAD, candidateRet, candidateIVLen, authMatchCold, attempts, true, matchErr
		}
	}
	return nil, nil, nil, 0, authMatchNone, attempts, true, ErrNotFound
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	return v.get(bs, command, authSourceKey{}, false)
}

// GetWithSource uses a source address only as an ordered authentication hint.
// Every accepted user is still selected by complete cryptographic verification.
// After source and active candidates miss, failed-auth admission may defer the
// expensive cold remainder for a bounded cooldown; it never accepts a user.
func (v *Validator) GetWithSource(bs []byte, command protocol.RequestCommand, source xraynet.Address) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	sourceKey, hasSource := authSourceKeyFromAddress(source)
	return v.get(bs, command, sourceKey, hasSource)
}

func (v *Validator) get(bs []byte, command protocol.RequestCommand, sourceKey authSourceKey, hasSource bool) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	if snapshot := v.authSnapshot.Load(); snapshot != nil {
		cache := v.sourceCache.Load()
		var candidates sourceCandidateSet
		now := int64(0)
		if hasSource && cache != nil {
			now = time.Now().UnixNano()
			candidates = cache.lookup(sourceKey, now)
		}
		protectionEnabled := hasSource && !v.failedAuthDisabled
		sourceColdAllowed := !protectionEnabled || candidates.blockedUntil <= now
		var budget *coldScanBudget
		if protectionEnabled {
			budget = processColdScanBudget
		}
		var layer authMatchLayer
		var attempts uint32
		var coldScanned bool
		u, aead, ret, ivLen, layer, attempts, coldScanned, err = getShadowsocksUserLayered(snapshot, candidates, bs, command, sourceColdAllowed, budget)
		v.authMetrics.candidateAttempts.Add(uint64(attempts))
		if coldScanned {
			v.authMetrics.coldScans.Add(1)
		}
		if err == nil && u != nil {
			switch layer {
			case authMatchSource:
				v.authMetrics.sourceHits.Add(1)
			case authMatchGlobal:
				v.authMetrics.globalHits.Add(1)
			case authMatchCold:
				v.authMetrics.coldHits.Add(1)
			}
			v.recordHotSuccess(snapshot.counters[u])
			if hasSource && cache != nil {
				eventNow := time.Now().UnixNano()
				if candidates.bypassUntil <= eventNow {
					if layer == authMatchSource {
						cache.recordSuccess(sourceKey, u, eventNow)
					} else {
						cache.recordMissSuccess(sourceKey, u, eventNow)
					}
				}
				if layer == authMatchCold {
					cache.clearFailures(sourceKey, eventNow)
				}
			}
		} else if protectionEnabled && err == ErrNotFound {
			if coldScanned {
				eventNow := time.Now().UnixNano()
				if cache != nil {
					cache.recordFailure(sourceKey, eventNow, v.effectiveSourceFailureBurst(), v.effectiveSourceFailureCooldown())
				}
				processColdScanBudget.recordFailure(eventNow)
			} else {
				v.authMetrics.admissionRejects.Add(1)
			}
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
