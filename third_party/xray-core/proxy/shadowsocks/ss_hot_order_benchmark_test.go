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
	benchmarkSSAirportSeed         = int64(0x51aead)
	benchmarkSSAirportRequestCount = 2000
	benchmarkSSAirportActiveUsers  = 300
	benchmarkSSAirportFrequent     = 100
)

type benchmarkSSAirportRequest struct {
	wire     []byte
	want     *protocol.MemoryUser
	attempts int
}

// benchmarkSSDeterministicTCPAuthWire builds the exact salt and first
// encrypted length record consumed by Validator.Get. It keeps the request
// stream identical between implementations without changing the wire format.
func benchmarkSSDeterministicTCPAuthWire(tb testing.TB, user *protocol.MemoryUser, sequence uint64) []byte {
	tb.Helper()
	account := user.Account.(*MemoryAccount)
	aeadCipher := account.Cipher.(*AEADCipher)
	salt := make([]byte, aeadCipher.IVSize())
	binary.LittleEndian.PutUint64(salt[:8], sequence+1)
	binary.LittleEndian.PutUint64(salt[8:16], sequence*0x9e3779b97f4a7c15+0x6a09e667f3bcc909)
	subkey := make([]byte, aeadCipher.KeySize())
	hkdfSHA1(account.Key, salt, subkey)
	aead := aeadCipher.AEADAuthCreator(subkey)
	wire := append([]byte(nil), salt...)
	wire = aead.Seal(wire, make([]byte, aead.NonceSize()), []byte{0, 32}, nil)
	return wire
}

func benchmarkSSAirportRequests(tb testing.TB, userCount int) (*Validator, []benchmarkSSAirportRequest) {
	return benchmarkSSAirportRequestsWithHotCapacity(tb, userCount, 0)
}

func benchmarkSSAirportRequestsWithHotCapacity(tb testing.TB, userCount, hotCapacity int) (*Validator, []benchmarkSSAirportRequest) {
	tb.Helper()
	if userCount < benchmarkSSAirportActiveUsers {
		tb.Fatalf("user count %d is smaller than active population", userCount)
	}
	validator, users := benchmarkSSUsersWithHotCapacity(tb, userCount, hotCapacity)
	rng := rand.New(rand.NewSource(benchmarkSSAirportSeed + int64(userCount)))
	activeIndexes := rng.Perm(userCount)[:benchmarkSSAirportActiveUsers]

	requestClasses := make([]byte, 0, benchmarkSSAirportRequestCount)
	for i := 0; i < benchmarkSSAirportRequestCount*80/100; i++ {
		requestClasses = append(requestClasses, 0)
	}
	for i := 0; i < benchmarkSSAirportRequestCount*15/100; i++ {
		requestClasses = append(requestClasses, 1)
	}
	for len(requestClasses) < benchmarkSSAirportRequestCount {
		requestClasses = append(requestClasses, 2)
	}
	rng.Shuffle(len(requestClasses), func(i, j int) {
		requestClasses[i], requestClasses[j] = requestClasses[j], requestClasses[i]
	})

	wrongAccount, err := (&Account{
		Password:   fmt.Sprintf("airport-invalid-%d", userCount),
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		tb.Fatal(err)
	}
	wrongUser := &protocol.MemoryUser{Account: wrongAccount}

	requests := make([]benchmarkSSAirportRequest, len(requestClasses))
	frequentCursor := 0
	coldCursor := 0
	for i, class := range requestClasses {
		sequence := uint64(userCount)<<32 | uint64(i)
		switch class {
		case 0:
			index := activeIndexes[frequentCursor%benchmarkSSAirportFrequent]
			frequentCursor++
			requests[i] = benchmarkSSAirportRequest{
				wire:     benchmarkSSDeterministicTCPAuthWire(tb, users[index], sequence),
				want:     users[index],
				attempts: index + 1,
			}
		case 1:
			index := activeIndexes[benchmarkSSAirportFrequent+coldCursor%(benchmarkSSAirportActiveUsers-benchmarkSSAirportFrequent)]
			coldCursor++
			requests[i] = benchmarkSSAirportRequest{
				wire:     benchmarkSSDeterministicTCPAuthWire(tb, users[index], sequence),
				want:     users[index],
				attempts: index + 1,
			}
		default:
			requests[i] = benchmarkSSAirportRequest{
				wire:     benchmarkSSDeterministicTCPAuthWire(tb, wrongUser, sequence),
				attempts: userCount,
			}
		}
	}
	return validator, requests
}

func benchmarkSSWarmAirportSnapshot(tb testing.TB, validator *Validator, requests []benchmarkSSAirportRequest) {
	tb.Helper()
	snapshot := validator.authSnapshot.Load()
	if snapshot == nil {
		tb.Fatal("hot snapshot is disabled")
	}
	for _, request := range requests {
		if request.want == nil {
			continue
		}
		counter := snapshot.counters[request.want]
		if counter == nil {
			tb.Fatalf("missing hot counter for %s", request.want.Email)
		}
		counter.successes.Add(1)
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

func benchmarkSSAirportRequestStream(b *testing.B, validator *Validator, requests []benchmarkSSAirportRequest) {
	totalAttempts := 0
	for _, request := range requests {
		totalAttempts += request.attempts
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
	b.ReportMetric(5, "invalid_pct")
}

func benchmarkSSRealAirportCold(b *testing.B, userCount int) {
	validator, requests := benchmarkSSAirportRequests(b, userCount)
	benchmarkSSAirportRequestStream(b, validator, requests)
}

func BenchmarkSSRealAirportCold(b *testing.B) {
	for _, userCount := range []int{1000, 5000, 10000} {
		b.Run(fmt.Sprintf("users_%05d", userCount), func(b *testing.B) {
			benchmarkSSRealAirportCold(b, userCount)
		})
	}
}

func BenchmarkSSRealAirportWarm(b *testing.B) {
	for _, hotCapacity := range []int{32, 64, 128} {
		for _, userCount := range []int{1000, 5000, 10000} {
			b.Run(fmt.Sprintf("hot_%03d/users_%05d", hotCapacity, userCount), func(b *testing.B) {
				validator, requests := benchmarkSSAirportRequestsWithHotCapacity(b, userCount, hotCapacity)
				benchmarkSSWarmAirportSnapshot(b, validator, requests)
				benchmarkSSAirportRequestStream(b, validator, requests)
			})
		}
	}
}

func BenchmarkSSHotSnapshotRebuild(b *testing.B) {
	for _, hotCapacity := range []int{32, 64, 128} {
		b.Run(fmt.Sprintf("hot_%03d/users_10000", hotCapacity), func(b *testing.B) {
			validator, requests := benchmarkSSAirportRequestsWithHotCapacity(b, 10000, hotCapacity)
			snapshot := validator.authSnapshot.Load()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, request := range requests {
					if request.want != nil {
						snapshot.counters[request.want].successes.Add(1)
					}
				}
				validator.rebuildHotSnapshot(time.Now())
				snapshot = validator.authSnapshot.Load()
			}
		})
	}
}

func TestSSRealAirportDistribution(t *testing.T) {
	_, requests := benchmarkSSAirportRequests(t, 10000)
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
		t.Fatalf("unexpected distribution: valid=%d invalid=%d", valid, invalid)
	}
}
