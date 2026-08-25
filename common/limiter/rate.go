package limiter

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return l.RateWriterContext(context.Background(), writer, limiter)
}

func (l *Limiter) RateWriterContext(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
	}
}

func (l *Limiter) RateReaderContext(ctx context.Context, reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Reader{
		reader:  reader,
		limiter: limiter,
		ctx:     ctx,
	}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if mb.IsEmpty() {
		return mb, err
	}
	if waitErr := waitRateLimit(r.ctx, r.limiter, int(mb.Len())); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, waitErr
	}
	return mb, err
}

func (r *Reader) Interrupt() {
	common.Interrupt(r.reader)
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitRateLimit(w.ctx, w.limiter, int(mb.Len())); err != nil {
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func waitRateLimit(ctx context.Context, limiter *rate.Limiter, bytes int) error {
	if bytes <= 0 {
		return nil
	}
	burst := limiter.Burst()
	if burst <= 0 {
		return fmt.Errorf("rate limiter burst must be positive")
	}
	for bytes > 0 {
		chunk := bytes
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		bytes -= chunk
	}
	return nil
}
