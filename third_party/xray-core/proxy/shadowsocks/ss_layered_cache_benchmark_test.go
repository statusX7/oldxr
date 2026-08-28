package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	benchmarkSSLayeredSeed         = int64(0x51ca4e)
	benchmarkSSLayeredUsers        = 10000
	benchmarkSSLayeredActive       = 1000
	benchmarkSSLayeredRequests     = 2000
	benchmarkSSLayeredChangedUsers = 200
)

type benchmarkSSLayeredModel uint8

const (
	benchmarkSSLayeredBalanced benchmarkSSLayeredModel = iota
	benchmarkSSLayeredRealistic
	benchmarkSSLayeredInvalidHeavy
	benchmarkSSLayeredAttackSingle
	benchmarkSSLayeredAttackRotating
)

type benchmarkSSLayeredSource [16]byte

type benchmarkSSLayeredRequest struct {
	source   benchmarkSSLayeredSource
	wire     []byte
	want     *protocol.MemoryUser
	attempts int
}

func benchmarkSSLayeredSourceID(id uint32) benchmarkSSLayeredSource {
	var source benchmarkSSLayeredSource
	source[10] = 0xff
	source[11] = 0xff
	binary.BigEndian.PutUint32(source[12:], id)
	return source
}

func benchmarkSSLayeredBaseSource(activeIndex int) benchmarkSSLayeredSource {
	switch {
	case activeIndex < 600:
		return benchmarkSSLayeredSourceID(uint32(activeIndex + 1))
	case activeIndex < 900:
		return benchmarkSSLayeredSourceID(uint32(601 + (activeIndex-600)/5))
	default:
		return benchmarkSSLayeredSourceID(uint32(661 + (activeIndex-900)/50))
	}
}

func benchmarkSSLayeredModelName(model benchmarkSSLayeredModel) string {
	switch model {
	case benchmarkSSLayeredBalanced:
		return "balanced"
	case benchmarkSSLayeredRealistic:
		return "realistic"
	case benchmarkSSLayeredInvalidHeavy:
		return "invalid_heavy"
	case benchmarkSSLayeredAttackSingle:
		return "attack_single"
	case benchmarkSSLayeredAttackRotating:
		return "attack_rotating_1000"
	default:
		panic("unknown layered model")
	}
}

func benchmarkSSLayeredRequestClasses(model benchmarkSSLayeredModel, rng *rand.Rand) []byte {
	classes := make([]byte, 0, benchmarkSSLayeredRequests)
	appendClass := func(class byte, count int) {
		for i := 0; i < count; i++ {
			classes = append(classes, class)
		}
	}
	switch model {
	case benchmarkSSLayeredBalanced:
		appendClass(0, 1900)
		appendClass(2, 100)
	case benchmarkSSLayeredRealistic:
		appendClass(0, 1400)
		appendClass(1, 500)
		appendClass(2, 100)
	case benchmarkSSLayeredInvalidHeavy:
		appendClass(0, 1000)
		appendClass(2, 1000)
	case benchmarkSSLayeredAttackSingle, benchmarkSSLayeredAttackRotating:
		appendClass(2, benchmarkSSLayeredRequests)
	}
	rng.Shuffle(len(classes), func(i, j int) {
		classes[i], classes[j] = classes[j], classes[i]
	})
	return classes
}

func benchmarkSSLayeredRequestsForModel(tb testing.TB, model benchmarkSSLayeredModel, hotCapacity int) (*Validator, []benchmarkSSLayeredRequest) {
	tb.Helper()
	validator, users := benchmarkSSUsersWithHotCapacity(tb, benchmarkSSLayeredUsers, hotCapacity)
	rng := rand.New(rand.NewSource(benchmarkSSLayeredSeed + int64(model)))
	activeIndexes := rng.Perm(len(users))[:benchmarkSSLayeredActive]
	changed := make([]bool, benchmarkSSLayeredActive)
	for _, index := range rng.Perm(benchmarkSSLayeredActive)[:benchmarkSSLayeredChangedUsers] {
		changed[index] = true
	}
	classes := benchmarkSSLayeredRequestClasses(model, rng)

	wrongAccount, err := (&Account{
		Password:   fmt.Sprintf("layered-invalid-%d", model),
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		tb.Fatal(err)
	}
	wrongUser := &protocol.MemoryUser{Account: wrongAccount}

	requests := make([]benchmarkSSLayeredRequest, len(classes))
	balancedCursor := 0
	frequentCursor := 0
	remainderCursor := 0
	invalidCursor := 0
	for i, class := range classes {
		sequence := uint64(model)<<60 | uint64(i+1)
		if class == 2 {
			source := benchmarkSSLayeredSourceID(1)
			switch model {
			case benchmarkSSLayeredBalanced, benchmarkSSLayeredRealistic:
				source = benchmarkSSLayeredBaseSource(invalidCursor % benchmarkSSLayeredActive)
			case benchmarkSSLayeredInvalidHeavy:
				if invalidCursor&1 == 0 {
					source = benchmarkSSLayeredBaseSource(invalidCursor % benchmarkSSLayeredActive)
				} else {
					source = benchmarkSSLayeredSourceID(uint32(20001 + invalidCursor%1000))
				}
			case benchmarkSSLayeredAttackRotating:
				source = benchmarkSSLayeredSourceID(uint32(20001 + invalidCursor%1000))
			}
			requests[i] = benchmarkSSLayeredRequest{
				source:   source,
				wire:     benchmarkSSDeterministicTCPAuthWire(tb, wrongUser, sequence),
				attempts: len(users),
			}
			invalidCursor++
			continue
		}

		activeIndex := 0
		if model == benchmarkSSLayeredRealistic {
			if class == 0 {
				activeIndex = frequentCursor % 200
				frequentCursor++
			} else {
				activeIndex = 200 + remainderCursor%800
				remainderCursor++
			}
		} else {
			activeIndex = balancedCursor % benchmarkSSLayeredActive
			balancedCursor++
		}
		userIndex := activeIndexes[activeIndex]
		source := benchmarkSSLayeredBaseSource(activeIndex)
		if changed[activeIndex] && i >= len(classes)/2 {
			source = benchmarkSSLayeredSourceID(uint32(10001 + activeIndex))
		}
		requests[i] = benchmarkSSLayeredRequest{
			source:   source,
			wire:     benchmarkSSDeterministicTCPAuthWire(tb, users[userIndex], sequence),
			want:     users[userIndex],
			attempts: userIndex + 1,
		}
	}
	return validator, requests
}

func benchmarkSSWarmLayeredGlobal(tb testing.TB, validator *Validator, requests []benchmarkSSLayeredRequest) {
	tb.Helper()
	snapshot := validator.authSnapshot.Load()
	if snapshot == nil {
		tb.Fatal("global authentication snapshot is disabled")
	}
	for _, request := range requests {
		if request.want != nil {
			snapshot.counters[request.want].successes.Add(1)
		}
	}
	validator.rebuildHotSnapshot(time.Now())
	snapshot = validator.authSnapshot.Load()
	rank := make(map[*protocol.MemoryUser]int, len(snapshot.ordered))
	for index, user := range snapshot.ordered {
		rank[user] = index + 1
	}
	for index := range requests {
		if requests[index].want == nil {
			requests[index].attempts = len(snapshot.ordered)
		} else {
			requests[index].attempts = rank[requests[index].want]
		}
	}
}

func benchmarkSSLayeredParentStream(b *testing.B, validator *Validator, requests []benchmarkSSLayeredRequest) {
	totalAttempts := 0
	valid := 0
	for _, request := range requests {
		totalAttempts += request.attempts
		if request.want != nil {
			valid++
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := &requests[i%len(requests)]
		user, _, _, _, err := validator.Get(request.wire, protocol.RequestCommandTCP)
		if request.want == nil {
			if err != ErrNotFound || user != nil {
				b.Fatalf("invalid request unexpectedly matched: user=%v err=%v", user, err)
			}
		} else if err != nil || user != request.want {
			b.Fatalf("valid request mismatch: got=%v want=%v err=%v", user, request.want, err)
		}
		benchmarkSSUser = user
		benchmarkSSErr = err
	}
	b.ReportMetric(float64(totalAttempts)/float64(len(requests)), "attempts/op")
	b.ReportMetric(float64(valid)*100/float64(len(requests)), "valid_pct")
}

func BenchmarkSSLayeredAuthParent(b *testing.B) {
	models := []benchmarkSSLayeredModel{
		benchmarkSSLayeredBalanced,
		benchmarkSSLayeredRealistic,
		benchmarkSSLayeredInvalidHeavy,
		benchmarkSSLayeredAttackSingle,
		benchmarkSSLayeredAttackRotating,
	}
	for _, model := range models {
		model := model
		b.Run(benchmarkSSLayeredModelName(model), func(b *testing.B) {
			validator, requests := benchmarkSSLayeredRequestsForModel(b, model, defaultHotUserCapacity)
			benchmarkSSWarmLayeredGlobal(b, validator, requests)
			benchmarkSSLayeredParentStream(b, validator, requests)
		})
	}
}

func TestSSLayeredSourceDistribution(t *testing.T) {
	baseSources := make(map[benchmarkSSLayeredSource]struct{})
	for activeIndex := 0; activeIndex < benchmarkSSLayeredActive; activeIndex++ {
		baseSources[benchmarkSSLayeredBaseSource(activeIndex)] = struct{}{}
	}
	if got := len(baseSources); got != 662 {
		t.Fatalf("base source count: got=%d want=662", got)
	}

	validator, requests := benchmarkSSLayeredRequestsForModel(t, benchmarkSSLayeredBalanced, defaultHotUserCapacity)
	if validator == nil || len(requests) != benchmarkSSLayeredRequests {
		t.Fatal("layered fixture construction failed")
	}
	valid := 0
	invalid := 0
	for _, request := range requests {
		if request.want == nil {
			invalid++
		} else {
			valid++
		}
	}
	if valid != 1900 || invalid != 100 {
		t.Fatalf("balanced distribution: valid=%d invalid=%d", valid, invalid)
	}
}
