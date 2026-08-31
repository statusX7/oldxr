package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

const benchmarkSSCandidateMaterialCount = 256

var (
	benchmarkSSCandidateBlock cipher.Block
	benchmarkSSCandidateAEAD  cipher.AEAD
	benchmarkSSCandidateBytes []byte
)

type benchmarkSSCandidateMaterial struct {
	masterKey   [16]byte
	salt        [16]byte
	subkey      [16]byte
	validWire   []byte
	invalidWire []byte
}

func benchmarkSSCandidateMaterials(tb testing.TB) []benchmarkSSCandidateMaterial {
	tb.Helper()
	materials := make([]benchmarkSSCandidateMaterial, benchmarkSSCandidateMaterialCount)
	for i := range materials {
		for j := range materials[i].masterKey {
			materials[i].masterKey[j] = byte(i*17 + j*29 + 1)
			materials[i].salt[j] = byte(i*31 + j*13 + 7)
		}
		hkdfSHA1(materials[i].masterKey[:], materials[i].salt[:], materials[i].subkey[:])
	}
	return materials
}

func BenchmarkSSCandidateHKDF(b *testing.B) {
	materials := benchmarkSSCandidateMaterials(b)
	var out [16]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		material := &materials[i%len(materials)]
		hkdfSHA1(material.masterKey[:], material.salt[:], out[:])
	}
	benchmarkSSCandidateBytes = out[:]
}

func BenchmarkSSCandidateAESNewCipher(b *testing.B) {
	materials := benchmarkSSCandidateMaterials(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		material := &materials[i%len(materials)]
		block, err := aes.NewCipher(material.subkey[:])
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSSCandidateBlock = block
	}
}

func BenchmarkSSCandidateNewGCM(b *testing.B) {
	materials := benchmarkSSCandidateMaterials(b)
	blocks := make([]cipher.Block, len(materials))
	for i := range materials {
		block, err := aes.NewCipher(materials[i].subkey[:])
		if err != nil {
			b.Fatal(err)
		}
		blocks[i] = block
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead, err := cipher.NewGCM(blocks[i%len(blocks)])
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSSCandidateAEAD = aead
	}
}

func benchmarkSSCandidateOpenMaterials(tb testing.TB) ([]cipher.AEAD, [][]byte, [][]byte) {
	tb.Helper()
	materials := benchmarkSSCandidateMaterials(tb)
	aeads := make([]cipher.AEAD, len(materials))
	valid := make([][]byte, len(materials))
	invalid := make([][]byte, len(materials))
	nonce := make([]byte, 12)
	for i := range materials {
		block, err := aes.NewCipher(materials[i].subkey[:])
		if err != nil {
			tb.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			tb.Fatal(err)
		}
		aeads[i] = aead
		valid[i] = aead.Seal(nil, nonce, []byte{0, 32}, nil)
		invalid[i] = append([]byte(nil), valid[i]...)
		invalid[i][len(invalid[i])-1] ^= 0x80
	}
	return aeads, valid, invalid
}

func benchmarkSSCandidateOpen(b *testing.B, invalid bool) {
	aeads, validWires, invalidWires := benchmarkSSCandidateOpenMaterials(b)
	wires := validWires
	if invalid {
		wires = invalidWires
	}
	var scratch [16]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % len(aeads)
		plaintext, err := aeads[index].Open(scratch[:0], scratch[4:], wires[index], nil)
		if invalid {
			if err == nil {
				b.Fatal("invalid tag unexpectedly authenticated")
			}
		} else if err != nil {
			b.Fatal(err)
		}
		benchmarkSSCandidateBytes = plaintext
	}
}

func BenchmarkSSCandidateOpenInvalid(b *testing.B) {
	benchmarkSSCandidateOpen(b, true)
}

func BenchmarkSSCandidateOpenValid(b *testing.B) {
	benchmarkSSCandidateOpen(b, false)
}

func benchmarkSSCandidateVerifyWires(tb testing.TB) (*Validator, *protocol.MemoryUser, [][]byte, [][]byte) {
	tb.Helper()
	validator, users := benchmarkSSUsers(tb, 1)
	valid := make([][]byte, benchmarkSSCandidateMaterialCount)
	invalid := make([][]byte, benchmarkSSCandidateMaterialCount)
	for i := range valid {
		valid[i] = benchmarkSSTCPWire(tb, users[0])
		wrongAccount, err := (&Account{
			Password:   "candidate-invalid-password-" + strconv.Itoa(i),
			CipherType: CipherType_AES_128_GCM,
		}).AsAccount()
		if err != nil {
			tb.Fatal(err)
		}
		wrongUser := &protocol.MemoryUser{Account: wrongAccount}
		invalid[i] = benchmarkSSTCPWire(tb, wrongUser)
	}
	return validator, users[0], valid, invalid
}

func benchmarkSSCandidateVerify(b *testing.B, invalid bool) {
	validator, want, validWires, invalidWires := benchmarkSSCandidateVerifyWires(b)
	wires := validWires
	if invalid {
		wires = invalidWires
		want = nil
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user, _, _, _, err := validator.Get(wires[i%len(wires)], protocol.RequestCommandTCP)
		if invalid {
			if err != ErrNotFound || user != nil {
				b.Fatalf("invalid candidate unexpectedly matched: user=%v err=%v", user, err)
			}
		} else if err != nil || user != want {
			b.Fatalf("valid candidate mismatch: got=%v want=%v err=%v", user, want, err)
		}
		benchmarkSSUser = user
		benchmarkSSErr = err
	}
}

func BenchmarkSSCandidateVerifyInvalid(b *testing.B) {
	benchmarkSSCandidateVerify(b, true)
}

func BenchmarkSSCandidateVerifyValid(b *testing.B) {
	benchmarkSSCandidateVerify(b, false)
}
