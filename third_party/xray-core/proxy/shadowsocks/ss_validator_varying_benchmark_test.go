package shadowsocks

import (
	"crypto/cipher"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

const benchmarkSSInvalidWireCount = 256

func benchmarkSSInvalidWires(tb testing.TB, command protocol.RequestCommand) [][]byte {
	tb.Helper()
	wires := make([][]byte, benchmarkSSInvalidWireCount)
	for i := range wires {
		account, err := (&Account{
			Password:   fmt.Sprintf("auth-invalid-password-%d", i),
			CipherType: CipherType_AES_128_GCM,
		}).AsAccount()
		if err != nil {
			tb.Fatal(err)
		}
		user := &protocol.MemoryUser{Account: account}
		if command == protocol.RequestCommandTCP {
			wires[i] = benchmarkSSTCPWire(tb, user)
		} else {
			wires[i] = benchmarkSSUDPWire(tb, user)
		}
	}
	return wires
}

func benchmarkSSValidatorVaryingInvalid(b *testing.B, command protocol.RequestCommand) {
	for _, userCount := range []int{1, 100, 1000, 5000, 10000} {
		validator, _ := benchmarkSSUsers(b, userCount)
		wires := benchmarkSSInvalidWires(b, command)
		b.Run(fmt.Sprintf("users_%05d/invalid_varying", userCount), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				user, _, _, _, err := validator.Get(wires[i%len(wires)], command)
				if err != ErrNotFound || user != nil {
					b.Fatalf("invalid request unexpectedly matched: user=%v err=%v", user, err)
				}
				benchmarkSSUser = user
				benchmarkSSErr = err
			}
			b.ReportMetric(float64(userCount), "attempts/op")
		})
	}
}

func BenchmarkSSAEADValidatorTCPVaryingInvalid(b *testing.B) {
	benchmarkSSValidatorVaryingInvalid(b, protocol.RequestCommandTCP)
}

func BenchmarkSSAEADValidatorUDPVaryingInvalid(b *testing.B) {
	benchmarkSSValidatorVaryingInvalid(b, protocol.RequestCommandUDP)
}

func TestSSAEADValidatorAttemptCount(t *testing.T) {
	for _, test := range []struct {
		name         string
		users        int
		validIndex   int
		wantAttempts int
		invalid      bool
	}{
		{name: "valid_first", users: 100, validIndex: 0, wantAttempts: 1},
		{name: "valid_middle", users: 100, validIndex: 50, wantAttempts: 51},
		{name: "valid_last", users: 100, validIndex: 99, wantAttempts: 100},
		{name: "invalid", users: 100, wantAttempts: 100, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			validator, users := benchmarkSSUsers(t, test.users)
			attempts := 0
			for _, user := range users {
				account := user.Account.(*MemoryAccount)
				aeadCipher := account.Cipher.(*AEADCipher)
				creator := aeadCipher.AEADAuthCreator
				aeadCipher.AEADAuthCreator = func(key []byte) cipher.AEAD {
					attempts++
					return creator(key)
				}
			}

			var wire []byte
			var want *protocol.MemoryUser
			if test.invalid {
				wire = benchmarkSSInvalidWires(t, protocol.RequestCommandTCP)[0]
			} else {
				want = users[test.validIndex]
				wire = benchmarkSSTCPWire(t, want)
			}
			attempts = 0
			got, _, _, _, err := validator.Get(wire, protocol.RequestCommandTCP)
			if test.invalid {
				if err != ErrNotFound || got != nil {
					t.Fatalf("invalid request unexpectedly matched: user=%v err=%v", got, err)
				}
			} else if err != nil || got != want {
				t.Fatalf("valid request mismatch: got=%v want=%v err=%v", got, want, err)
			}
			if attempts != test.wantAttempts {
				t.Fatalf("attempt count mismatch: got=%d want=%d", attempts, test.wantAttempts)
			}
		})
	}
}
