package mydispatcher

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/XrayR-project/XrayR/common/limiter"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type tailBufferWriter struct {
	calls atomic.Int32
	bytes atomic.Int64
}

func (w *tailBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls.Add(1)
	w.bytes.Add(int64(mb.Len()))
	buf.ReleaseMulti(mb)
	return nil
}

func TestUserWriterDrainsTailAfterConnectionContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	underlying := new(tailBufferWriter)
	dispatcher := &DefaultDispatcher{Limiter: limiter.New()}
	bucket := rate.NewLimiter(1_000_000, 4)
	writer := dispatcher.wrapUserWriter(ctx, underlying, bucket, true, nil)
	payload := buf.MultiBuffer{buf.FromBytes(make([]byte, 8))}

	if err := writer.WriteMultiBuffer(payload); err != nil {
		buf.ReleaseMulti(payload)
		t.Fatalf("tail write failed after connection context cancellation: %v", err)
	}
	if got := underlying.calls.Load(); got != 1 {
		t.Fatalf("underlying calls = %d, want 1", got)
	}
	if got := underlying.bytes.Load(); got != 8 {
		t.Fatalf("underlying bytes = %d, want 8", got)
	}
}
