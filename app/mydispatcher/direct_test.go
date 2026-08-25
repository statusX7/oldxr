package mydispatcher

import (
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type sequenceReader struct {
	payloads [][]byte
}

func (r *sequenceReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.payloads) == 0 {
		return nil, io.EOF
	}
	payload := r.payloads[0]
	r.payloads = r.payloads[1:]
	return buf.MergeBytes(nil, payload), nil
}

func multiBufferBytes(t *testing.T, mb buf.MultiBuffer) []byte {
	t.Helper()
	payload := make([]byte, mb.Len())
	remainder, n := buf.SplitBytes(mb, payload)
	buf.ReleaseMulti(remainder)
	if n != len(payload) {
		t.Fatalf("unexpected payload length: got %d, want %d", n, len(payload))
	}
	return payload
}

func TestCachedReaderReplayReader(t *testing.T) {
	underlying := &sequenceReader{payloads: [][]byte{[]byte("sniffed"), []byte("steady")}}
	cached := &cachedReader{reader: underlying}
	payload := buf.New()
	defer payload.Release()

	cached.Cache(payload)
	if got := string(payload.Bytes()); got != "sniffed" {
		t.Fatalf("unexpected sniff payload: got %q", got)
	}

	replay := cached.ReplayReader()
	first, err := replay.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(multiBufferBytes(t, first)); got != "sniffed" {
		t.Fatalf("unexpected replay payload: got %q", got)
	}

	second, err := replay.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(multiBufferBytes(t, second)); got != "steady" {
		t.Fatalf("unexpected steady payload: got %q", got)
	}
}

func TestCachedReaderReplayReaderWithoutCache(t *testing.T) {
	underlying := &sequenceReader{}
	cached := &cachedReader{reader: underlying}
	if replay := cached.ReplayReader(); replay != underlying {
		t.Fatal("empty cache should return the original reader")
	}
}
