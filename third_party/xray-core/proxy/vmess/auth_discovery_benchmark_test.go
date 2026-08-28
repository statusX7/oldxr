package vmess

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	vmessaead "github.com/xtls/xray-core/proxy/vmess/aead"
)

var (
	benchmarkVMessUser  *protocol.MemoryUser
	benchmarkVMessFound bool
	benchmarkVMessErr   error
)

func benchmarkVMessID(index int) *protocol.ID {
	var raw uuid.UUID
	binary.BigEndian.PutUint64(raw[:8], uint64(index)+0x1020304050607080)
	binary.BigEndian.PutUint64(raw[8:], uint64(index)+0x8090a0b0c0d0e0f0)
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return protocol.NewID(raw)
}

func benchmarkVMessValidator(tb testing.TB, userCount int) (*TimedUserValidator, []*protocol.MemoryUser) {
	tb.Helper()
	validator := NewAEADUserValidator(protocol.DefaultIDHash)
	users := make([]*protocol.MemoryUser, userCount)
	for i := range users {
		user := &protocol.MemoryUser{
			Email: fmt.Sprintf("auth-benchmark-%d@example.invalid", i),
			Account: &MemoryAccount{
				ID: benchmarkVMessID(i),
			},
		}
		if err := validator.Add(user); err != nil {
			tb.Fatalf("add user %d: %v", i, err)
		}
		users[i] = user
	}
	return validator, users
}

func BenchmarkVMessAEADTimedUserValidator(b *testing.B) {
	for _, userCount := range []int{1, 100, 1000, 5000, 10000} {
		userCount := userCount
		b.Run(fmt.Sprintf("users_%05d/valid", userCount), func(b *testing.B) {
			validator, users := benchmarkVMessValidator(b, userCount)
			defer common.Close(validator)
			target := users[userCount/2]
			key := target.Account.(*MemoryAccount).ID.CmdKey()
			authIDs := make([][16]byte, b.N)
			now := time.Now().Unix()
			for i := range authIDs {
				authIDs[i] = vmessaead.CreateAuthID(key, now)
			}
			b.ReportAllocs()
			b.ReportMetric(float64(userCount), "users")
			b.ResetTimer()
			for i := range authIDs {
				user, found, err := validator.GetAEAD(authIDs[i][:])
				if err != nil || !found || user != target {
					b.Fatalf("valid AuthID mismatch: got=%v want=%v found=%v err=%v", user, target, found, err)
				}
				benchmarkVMessUser = user
				benchmarkVMessFound = found
				benchmarkVMessErr = err
			}
		})

		b.Run(fmt.Sprintf("users_%05d/invalid", userCount), func(b *testing.B) {
			validator, _ := benchmarkVMessValidator(b, userCount)
			defer common.Close(validator)
			var authID [16]byte
			binary.BigEndian.PutUint64(authID[:8], 0xdeadbeefcafebabe)
			binary.BigEndian.PutUint64(authID[8:], 0x0123456789abcdef)
			b.ReportAllocs()
			b.ReportMetric(float64(userCount), "users")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				user, found, err := validator.GetAEAD(authID[:])
				if err != vmessaead.ErrNotFound || found || user != nil {
					b.Fatalf("invalid AuthID unexpectedly matched: user=%v found=%v err=%v", user, found, err)
				}
				benchmarkVMessUser = user
				benchmarkVMessFound = found
				benchmarkVMessErr = err
			}
		})
	}
}
