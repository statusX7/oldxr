package aead

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

type benchmarkCountingBlock struct {
	cipher.Block
	attempts *uint64
}

func (b benchmarkCountingBlock) Decrypt(dst, src []byte) {
	*b.attempts++
	b.Block.Decrypt(dst, src)
}

func benchmarkAuthKey(index int) [16]byte {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], uint64(index)+1)
	sum := sha256.Sum256(input[:])
	var key [16]byte
	copy(key[:], sum[:16])
	return key
}

func benchmarkAuthHolder(userCount int, attempts *uint64) (*AuthIDDecoderHolder, [16]byte, interface{}) {
	holder := NewAuthIDDecoderHolder()
	var target [16]byte
	var ticket interface{}
	for i := 0; i < userCount; i++ {
		key := benchmarkAuthKey(i)
		value := i + 1
		holder.AddUser(key, value)
		if i == userCount/2 {
			target = key
			ticket = value
		}
	}
	if attempts != nil {
		for _, item := range holder.decoders {
			item.dec.s = benchmarkCountingBlock{Block: item.dec.s, attempts: attempts}
		}
	}
	return holder, target, ticket
}

func benchmarkAuthAttempts(tb testing.TB, userCount int, valid bool) float64 {
	tb.Helper()
	var attempts uint64
	holder, target, ticket := benchmarkAuthHolder(userCount, &attempts)
	const samples = 128
	if valid {
		for i := 0; i < samples; i++ {
			authID := CreateAuthID(target[:], time.Now().Unix())
			got, err := holder.Match(authID)
			if err != nil || got != ticket {
				tb.Fatalf("count valid AuthID: got=%v want=%v err=%v", got, ticket, err)
			}
		}
	} else {
		var authID [16]byte
		binary.BigEndian.PutUint64(authID[:8], 0xdeadbeefcafebabe)
		binary.BigEndian.PutUint64(authID[8:], 0x0123456789abcdef)
		for i := 0; i < samples; i++ {
			got, err := holder.Match(authID)
			if err != ErrNotFound || got != nil {
				tb.Fatalf("count invalid AuthID: got=%v err=%v", got, err)
			}
		}
	}
	return float64(attempts) / samples
}

func BenchmarkVMessAEADAuthIDHolder(b *testing.B) {
	for _, userCount := range []int{1, 100, 1000, 5000, 10000} {
		userCount := userCount
		b.Run(fmt.Sprintf("users_%05d/valid", userCount), func(b *testing.B) {
			holder, target, ticket := benchmarkAuthHolder(userCount, nil)
			attempts := benchmarkAuthAttempts(b, userCount, true)
			authIDs := make([][16]byte, b.N)
			now := time.Now().Unix()
			for i := range authIDs {
				authIDs[i] = CreateAuthID(target[:], now)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range authIDs {
				got, err := holder.Match(authIDs[i])
				if err != nil || got != ticket {
					b.Fatalf("valid AuthID mismatch: got=%v want=%v err=%v", got, ticket, err)
				}
			}
			b.ReportMetric(attempts, "attempts/op")
		})

		b.Run(fmt.Sprintf("users_%05d/invalid", userCount), func(b *testing.B) {
			holder, _, _ := benchmarkAuthHolder(userCount, nil)
			attempts := benchmarkAuthAttempts(b, userCount, false)
			var authID [16]byte
			binary.BigEndian.PutUint64(authID[:8], 0xdeadbeefcafebabe)
			binary.BigEndian.PutUint64(authID[8:], 0x0123456789abcdef)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := holder.Match(authID)
				if err != ErrNotFound || got != nil {
					b.Fatalf("invalid AuthID unexpectedly matched: got=%v err=%v", got, err)
				}
			}
			b.ReportMetric(attempts, "attempts/op")
		})
	}
}
