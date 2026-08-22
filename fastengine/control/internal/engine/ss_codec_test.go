package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	ss "github.com/xtls/xray-core/proxy/shadowsocks"
)

func testAESAccount(t *testing.T) *ss.MemoryAccount {
	t.Helper()
	account, err := (&ss.Account{Password: "phase7-codec-secret", CipherType: ss.CipherType_AES_128_GCM}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return account.(*ss.MemoryAccount)
}

func TestAES128GCMSessionAndRecordSequence(t *testing.T) {
	account := testAESAccount(t)
	salt := make([]byte, ssSaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	encryptor, err := newAES128GCMSession(account, salt)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := newAES128GCMSession(account, salt)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("phase7-record-"), 900)
	var encryptNonce [12]byte
	wire := sealSSRecords(encryptor, encryptNonce[:], nil, payload)
	var decryptNonce [12]byte
	var decoded []byte
	for len(wire) > 0 {
		if len(wire) < ssLengthWireSize {
			t.Fatal("truncated encrypted length")
		}
		lengthBytes, err := decryptor.Open(nil, decryptNonce[:], wire[:ssLengthWireSize], nil)
		if err != nil {
			t.Fatal(err)
		}
		incrementNonce(decryptNonce[:])
		length := int(binary.BigEndian.Uint16(lengthBytes))
		wire = wire[ssLengthWireSize:]
		if len(wire) < length+ssTagSize {
			t.Fatal("truncated encrypted payload")
		}
		plain, err := decryptor.Open(nil, decryptNonce[:], wire[:length+ssTagSize], nil)
		if err != nil {
			t.Fatal(err)
		}
		incrementNonce(decryptNonce[:])
		decoded = append(decoded, plain...)
		wire = wire[length+ssTagSize:]
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("decoded payload mismatch")
	}
}

func TestParseSSTarget(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
		want string
	}{
		{"ipv4", []byte{1, 127, 0, 0, 1, 0x1f, 0x90}, "127.0.0.1:8080"},
		{"domain", append(append([]byte{3, 11}, []byte("example.com")...), 0x01, 0xbb), "example.com:443"},
		{"ipv6", append(append([]byte{4}, net.ParseIP("2001:db8::1").To16()...), 0x00, 0x35), "[2001:db8::1]:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, consumed, err := parseSSTarget(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || consumed != len(tc.wire) {
				t.Fatalf("target=%q consumed=%d, want %q/%d", got, consumed, tc.want, len(tc.wire))
			}
		})
	}
}
