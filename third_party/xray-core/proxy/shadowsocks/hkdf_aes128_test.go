package shadowsocks

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"math/rand"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func standardHKDFSHA1AES128(tb testing.TB, secret, salt []byte) [16]byte {
	tb.Helper()
	var out [16]byte
	if _, err := io.ReadFull(hkdf.New(sha1.New, secret, salt, []byte("ss-subkey")), out[:]); err != nil {
		tb.Fatal(err)
	}
	return out
}

func TestHKDFSHA1AES128KnownAnswer(t *testing.T) {
	var secret [16]byte
	var salt [16]byte
	for i := range secret {
		secret[i] = byte(i)
		salt[i] = byte(i + 16)
	}
	want, err := hex.DecodeString("6e1fe8a4522b2b31df56f720d9241521")
	if err != nil {
		t.Fatal(err)
	}
	var got [16]byte
	hkdfSHA1AES128(&secret, &salt, &got)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("HKDF-SHA1 mismatch: got %x want %x", got, want)
	}
}

func TestHKDFSHA1AES128Differential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x535341454144))
	for i := 0; i < 4096; i++ {
		var secret [16]byte
		var salt [16]byte
		if _, err := rng.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rng.Read(salt[:]); err != nil {
			t.Fatal(err)
		}
		want := standardHKDFSHA1AES128(t, secret[:], salt[:])
		var got [16]byte
		hkdfSHA1AES128(&secret, &salt, &got)
		if got != want {
			t.Fatalf("case %d mismatch: got %x want %x", i, got, want)
		}
	}
}

func FuzzHKDFSHA1AES128Differential(f *testing.F) {
	f.Add([]byte("oldxr-hkdf-aes128-differential-seed"))
	f.Fuzz(func(t *testing.T, material []byte) {
		var secret [16]byte
		var salt [16]byte
		for i, value := range material {
			if i&1 == 0 {
				secret[(i/2)%len(secret)] ^= value
			} else {
				salt[(i/2)%len(salt)] ^= value
			}
		}
		want := standardHKDFSHA1AES128(t, secret[:], salt[:])
		var got [16]byte
		hkdfSHA1AES128(&secret, &salt, &got)
		if got != want {
			t.Fatalf("mismatch: got %x want %x", got, want)
		}
	})
}
