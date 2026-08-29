package encoding

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/sha3"
)

type legacyShakeSizeParser struct {
	shake  sha3.ShakeHash
	buffer [2]byte
}

func newLegacyShakeSizeParser(nonce []byte) *legacyShakeSizeParser {
	shake := sha3.NewShake128()
	if _, err := shake.Write(nonce); err != nil {
		panic(err)
	}
	return &legacyShakeSizeParser{shake: shake}
}

func (s *legacyShakeSizeParser) next() uint16 {
	if _, err := s.shake.Read(s.buffer[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint16(s.buffer[:])
}

func TestShakeSizeParserBatchMatchesLegacyStream(t *testing.T) {
	testCases := [][]byte{
		nil,
		{0},
		{0, 1, 2, 3, 4, 5, 6, 7},
		{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0},
	}
	for caseIndex, nonce := range testCases {
		legacy := newLegacyShakeSizeParser(nonce)
		batched := NewShakeSizeParser(nonce)
		// Cross several 168-byte refill boundaries. Each next call consumes two
		// bytes, so 1,000 values cover eleven complete boundaries and a tail.
		for index := 0; index < 1000; index++ {
			want := legacy.next()
			if got := batched.next(); got != want {
				t.Fatalf("case %d value %d = %04x; want %04x", caseIndex, index, got, want)
			}
		}
	}
}

func TestShakeSizeParserBatchPreservesEncodeDecodeSequence(t *testing.T) {
	nonce := []byte("oldxr-vmess-shake-batch")
	encoder := NewShakeSizeParser(nonce)
	decoder := newLegacyShakeSizeParser(nonce)
	var wire [2]byte
	for index := 0; index < 1000; index++ {
		size := uint16(index*61 + 17)
		encoded := encoder.Encode(size, wire[:])
		if got := binary.BigEndian.Uint16(encoded) ^ decoder.next(); got != size {
			t.Fatalf("size %d decoded as %d", size, got)
		}
		if got, want := encoder.NextPaddingLen(), decoder.next()%64; got != want {
			t.Fatalf("padding value %d = %d; want %d", index, got, want)
		}
	}
}

var shakeSizeParserBenchmarkSink uint16

func BenchmarkShakeSizeParserLegacyTwoByteRead(b *testing.B) {
	parser := newLegacyShakeSizeParser([]byte("oldxr-vmess-shake-benchmark"))
	b.ReportAllocs()
	b.ResetTimer()
	var result uint16
	for index := 0; index < b.N; index++ {
		result ^= parser.next()
	}
	shakeSizeParserBenchmarkSink = result
}

func BenchmarkShakeSizeParserBatchedRead(b *testing.B) {
	parser := NewShakeSizeParser([]byte("oldxr-vmess-shake-benchmark"))
	b.ReportAllocs()
	b.ResetTimer()
	var result uint16
	for index := 0; index < b.N; index++ {
		result ^= parser.next()
	}
	shakeSizeParserBenchmarkSink = result
}
