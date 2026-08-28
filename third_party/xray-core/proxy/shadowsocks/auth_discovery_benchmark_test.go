package shadowsocks

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

var (
	benchmarkSSUser *protocol.MemoryUser
	benchmarkSSErr  error
)

func benchmarkSSUsers(tb testing.TB, count int) (*Validator, []*protocol.MemoryUser) {
	return benchmarkSSUsersWithHotCapacity(tb, count, 0)
}

func benchmarkSSUsersWithHotCapacity(tb testing.TB, count, hotCapacity int) (*Validator, []*protocol.MemoryUser) {
	tb.Helper()
	validator := &Validator{hotCapacity: hotCapacity}
	users := make([]*protocol.MemoryUser, count)
	for i := range users {
		account, err := (&Account{
			Password:   fmt.Sprintf("auth-benchmark-password-%d", i),
			CipherType: CipherType_AES_128_GCM,
		}).AsAccount()
		if err != nil {
			tb.Fatalf("create account %d: %v", i, err)
		}
		user := &protocol.MemoryUser{
			Email:   fmt.Sprintf("auth-benchmark-%d@example.invalid", i),
			Account: account,
		}
		users[i] = user
	}
	if err := validator.addUsers(users); err != nil {
		tb.Fatalf("add users: %v", err)
	}
	return validator, users
}

func benchmarkSSTCPWire(tb testing.TB, user *protocol.MemoryUser) []byte {
	tb.Helper()
	wire := buf.New()
	defer wire.Release()
	request := &protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandTCP,
		Address: net.IPAddress([]byte{192, 0, 2, 1}),
		Port:    8080,
		User:    user,
	}
	writer, err := WriteTCPRequest(request, wire)
	if err != nil {
		tb.Fatalf("create TCP request: %v", err)
	}
	payload := buf.New()
	common.Must2(payload.WriteString("auth-discovery"))
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		tb.Fatalf("write TCP request: %v", err)
	}
	return append([]byte(nil), wire.Bytes()...)
}

func benchmarkSSUDPWire(tb testing.TB, user *protocol.MemoryUser) []byte {
	tb.Helper()
	request := &protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandUDP,
		Address: net.IPAddress([]byte{192, 0, 2, 1}),
		Port:    8080,
		User:    user,
	}
	wire, err := EncodeUDPPacket(request, []byte("auth-discovery"))
	if err != nil {
		tb.Fatalf("create UDP request: %v", err)
	}
	defer wire.Release()
	return append([]byte(nil), wire.Bytes()...)
}

func benchmarkSSValidatorCase(b *testing.B, validator *Validator, wire []byte, command protocol.RequestCommand, want *protocol.MemoryUser, attempts int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user, _, _, _, err := validator.Get(wire, command)
		if want == nil {
			if err != ErrNotFound || user != nil {
				b.Fatalf("invalid request unexpectedly matched: user=%v err=%v", user, err)
			}
		} else if err != nil || user != want {
			b.Fatalf("valid request mismatch: got=%v want=%v err=%v", user, want, err)
		}
		benchmarkSSUser = user
		benchmarkSSErr = err
	}
	b.ReportMetric(float64(attempts), "attempts/op")
}

func benchmarkSSValidator(b *testing.B, command protocol.RequestCommand) {
	for _, userCount := range []int{1, 100, 1000, 5000, 10000} {
		validator, users := benchmarkSSUsers(b, userCount)
		positions := []struct {
			name  string
			index int
		}{
			{name: "first", index: 0},
		}
		if userCount > 1 {
			positions = append(positions,
				struct {
					name  string
					index int
				}{name: "middle", index: userCount / 2},
				struct {
					name  string
					index int
				}{name: "last", index: userCount - 1},
			)
		}

		for _, position := range positions {
			position := position
			var wire []byte
			if command == protocol.RequestCommandTCP {
				wire = benchmarkSSTCPWire(b, users[position.index])
			} else {
				wire = benchmarkSSUDPWire(b, users[position.index])
			}
			b.Run(fmt.Sprintf("users_%05d/valid_%s", userCount, position.name), func(b *testing.B) {
				benchmarkSSValidatorCase(b, validator, wire, command, users[position.index], position.index+1)
			})
		}

		invalidWireSize := 50
		if command == protocol.RequestCommandUDP {
			invalidWireSize = 64
		}
		invalidWire := make([]byte, invalidWireSize)
		b.Run(fmt.Sprintf("users_%05d/invalid", userCount), func(b *testing.B) {
			benchmarkSSValidatorCase(b, validator, invalidWire, command, nil, userCount)
		})
	}
}

func BenchmarkSSAEADValidatorTCP(b *testing.B) {
	benchmarkSSValidator(b, protocol.RequestCommandTCP)
}

func BenchmarkSSAEADValidatorUDP(b *testing.B) {
	benchmarkSSValidator(b, protocol.RequestCommandUDP)
}
