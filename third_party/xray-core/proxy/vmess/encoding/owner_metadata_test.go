package encoding

import (
	"bytes"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
)

var ownerMetadataBenchmarkSink int

func newOwnerMetadataTestCodec() *OwnerBodyCodec {
	key := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10}
	requestIV := [16]byte{0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f}
	responseIV := [16]byte{0x3f, 0x2e, 0x1d, 0x0c, 0xfb, 0xea, 0xd9, 0xc8, 0xb7, 0xa6, 0x95, 0x84, 0x73, 0x62, 0x51, 0x40}

	requestAEAD := crypto.NewAesGcm(key[:])
	requestAuth := &crypto.AEADAuthenticator{
		AEAD:                    requestAEAD,
		NonceGenerator:          GenerateChunkNonce(requestIV[:], uint32(requestAEAD.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	requestSize := NewShakeSizeParser(requestIV[:])

	responseAEAD := crypto.NewAesGcm(key[:])
	responseAuth := &crypto.AEADAuthenticator{
		AEAD:                    responseAEAD,
		NonceGenerator:          GenerateChunkNonce(responseIV[:], uint32(responseAEAD.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	responseSize := NewShakeSizeParser(responseIV[:])

	return &OwnerBodyCodec{
		requestAuth:        requestAuth,
		requestSize:        requestSize,
		requestOverhead:    requestAuth.Overhead(),
		requestSizeBytes:   int(requestSize.SizeBytes()),
		responseAuth:       responseAuth,
		responseSize:       responseSize,
		responseOverhead:   responseAuth.Overhead(),
		responseSizeBytes:  int(responseSize.SizeBytes()),
		responseMaxPayload: buf.Size - responseAuth.Overhead() - int(responseSize.SizeBytes()),
		responseEnd:        true,
	}
}

func decodeRequestSizeLegacyMetadata(c *OwnerBodyCodec, sizeBytes []byte) (wireSize int, padding int, done bool, err error) {
	if len(sizeBytes) != int(c.requestSize.SizeBytes()) {
		return 0, 0, false, io.ErrUnexpectedEOF
	}
	size, err := c.requestSize.Decode(sizeBytes)
	if err != nil {
		return 0, 0, false, err
	}
	if int(size) == c.requestAuth.Overhead() {
		return int(size), 0, true, nil
	}
	if int(size) <= c.requestAuth.Overhead() || int(size) > buf.Size {
		return 0, 0, false, io.ErrUnexpectedEOF
	}
	return int(size), 0, false, nil
}

func sealResponseRecordLegacyMetadata(c *OwnerBodyCodec, dst, plaintext []byte) ([]byte, error) {
	maxPayload := buf.Size - c.responseAuth.Overhead() - int(c.responseSize.SizeBytes())
	if len(plaintext) == 0 || maxPayload <= 0 || len(plaintext) > maxPayload {
		return nil, io.ErrShortBuffer
	}
	wireSize := len(plaintext) + c.responseAuth.Overhead()
	prefix := c.responsePrefix[:c.responseSize.SizeBytes()]
	c.responseSize.Encode(uint16(wireSize), prefix)
	dst = append(dst, prefix...)
	return c.responseAuth.Seal(dst, plaintext)
}

func sealResponseEndLegacyMetadata(c *OwnerBodyCodec, dst []byte) ([]byte, error) {
	wireSize := c.responseAuth.Overhead()
	var prefixBuffer [18]byte
	prefix := prefixBuffer[:c.responseSize.SizeBytes()]
	c.responseSize.Encode(uint16(wireSize), prefix)
	dst = append(dst, prefix...)
	return c.responseAuth.Seal(dst, nil)
}

func TestOwnerBodyCodecCachedMetadataMatchesLegacyWire(t *testing.T) {
	cachedRequest := newOwnerMetadataTestCodec()
	legacyRequest := newOwnerMetadataTestCodec()
	requestEncoder := NewShakeSizeParser([]byte{0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f})
	for i := 0; i < 1024; i++ {
		var prefix [2]byte
		requestEncoder.Encode(uint16(4096+cachedRequest.requestOverhead), prefix[:])
		cachedSize, cachedPadding, cachedDone, cachedErr := cachedRequest.DecodeRequestSize(prefix[:])
		legacySize, legacyPadding, legacyDone, legacyErr := decodeRequestSizeLegacyMetadata(legacyRequest, prefix[:])
		if cachedSize != legacySize || cachedPadding != legacyPadding || cachedDone != legacyDone || cachedErr != legacyErr {
			t.Fatalf("request record %d mismatch: cached=(%d,%d,%v,%v) legacy=(%d,%d,%v,%v)", i, cachedSize, cachedPadding, cachedDone, cachedErr, legacySize, legacyPadding, legacyDone, legacyErr)
		}
	}

	cachedResponse := newOwnerMetadataTestCodec()
	legacyResponse := newOwnerMetadataTestCodec()
	for i := 0; i < 1024; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1+(i%4096))
		cachedWire, cachedErr := cachedResponse.SealResponseRecord(nil, payload)
		legacyWire, legacyErr := sealResponseRecordLegacyMetadata(legacyResponse, nil, payload)
		if cachedErr != nil || legacyErr != nil {
			t.Fatalf("response record %d errors: cached=%v legacy=%v", i, cachedErr, legacyErr)
		}
		if !bytes.Equal(cachedWire, legacyWire) {
			t.Fatalf("response record %d wire mismatch", i)
		}
	}
	cachedEnd, cachedErr := cachedResponse.SealResponseEnd(nil)
	legacyEnd, legacyErr := sealResponseEndLegacyMetadata(legacyResponse, nil)
	if cachedErr != nil || legacyErr != nil {
		t.Fatalf("response end errors: cached=%v legacy=%v", cachedErr, legacyErr)
	}
	if !bytes.Equal(cachedEnd, legacyEnd) {
		t.Fatal("response end wire mismatch")
	}
}

func TestOwnerBodyCodecCachedMetadataRejectsInvalidRecords(t *testing.T) {
	codec := newOwnerMetadataTestCodec()
	if _, _, _, err := codec.DecodeRequestSize([]byte{0}); err != io.ErrUnexpectedEOF {
		t.Fatalf("short size prefix error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if _, err := codec.OpenRequest(make([]byte, codec.requestOverhead), 0); err != io.ErrUnexpectedEOF {
		t.Fatalf("short authenticated record error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if _, err := codec.OpenRequest(make([]byte, codec.requestOverhead+1), 0); err == nil {
		t.Fatal("invalid authenticated record was accepted")
	}
	if _, err := codec.SealResponseRecord(nil, make([]byte, codec.responseMaxPayload+1)); err != io.ErrShortBuffer {
		t.Fatalf("oversized response record error = %v, want %v", err, io.ErrShortBuffer)
	}
}

func BenchmarkOwnerBodyCodecRequestRecordMetadata(b *testing.B) {
	for _, benchmark := range []struct {
		name   string
		decode func(*OwnerBodyCodec, []byte) (int, int, bool, error)
	}{
		{name: "legacy", decode: decodeRequestSizeLegacyMetadata},
		{name: "cached", decode: func(c *OwnerBodyCodec, prefix []byte) (int, int, bool, error) {
			return c.DecodeRequestSize(prefix)
		}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			codec := newOwnerMetadataTestCodec()
			encoder := NewShakeSizeParser([]byte{0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f})
			var prefix [2]byte
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(uint16(4096+codec.requestOverhead), prefix[:])
				size, _, _, err := benchmark.decode(codec, prefix[:])
				if err != nil {
					b.Fatal(err)
				}
				ownerMetadataBenchmarkSink = size
			}
		})
	}
}

func BenchmarkOwnerBodyCodecSealResponseRecordMetadata(b *testing.B) {
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	for _, benchmark := range []struct {
		name string
		seal func(*OwnerBodyCodec, []byte, []byte) ([]byte, error)
	}{
		{name: "legacy", seal: sealResponseRecordLegacyMetadata},
		{name: "cached", seal: func(c *OwnerBodyCodec, dst, plaintext []byte) ([]byte, error) {
			return c.SealResponseRecord(dst, plaintext)
		}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			codec := newOwnerMetadataTestCodec()
			dst := make([]byte, 0, len(payload)+32)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire, err := benchmark.seal(codec, dst[:0], payload)
				if err != nil {
					b.Fatal(err)
				}
				ownerMetadataBenchmarkSink = len(wire)
			}
		})
	}
}
