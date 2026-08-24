package limiter

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type testBufferWriter struct {
	calls int32
	bytes int64
}

func TestRateWriterHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	underlying := new(testBufferWriter)
	bucket := rate.NewLimiter(100, 4)
	writer := New().RateWriterContext(ctx, underlying, bucket)
	mb := buf.MultiBuffer{buf.FromBytes(make([]byte, 8))}
	if err := writer.WriteMultiBuffer(mb); err == nil {
		buf.ReleaseMulti(mb)
		t.Fatal("WriteMultiBuffer succeeded with canceled context")
	}
	buf.ReleaseMulti(mb)
	if got := atomic.LoadInt32(&underlying.calls); got != 0 {
		t.Fatalf("underlying calls = %d, want 0", got)
	}
}

func (w *testBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	atomic.AddInt32(&w.calls, 1)
	atomic.AddInt64(&w.bytes, int64(mb.Len()))
	buf.ReleaseMulti(mb)
	return nil
}

func TestRateWriterDoesNotBypassWritesLargerThanBurst(t *testing.T) {
	underlying := new(testBufferWriter)
	bucket := rate.NewLimiter(100, 4)
	writer := New().RateWriter(underlying, bucket)
	mb := buf.MultiBuffer{buf.FromBytes(make([]byte, 8))}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}
	if got := atomic.LoadInt32(&underlying.calls); got != 1 {
		t.Fatalf("underlying calls = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&underlying.bytes); got != 8 {
		t.Fatalf("underlying bytes = %d, want 8", got)
	}
	if tokens := bucket.Tokens(); tokens >= 1 {
		t.Fatalf("large write bypassed limiter: tokens after write = %.2f", tokens)
	}
}
