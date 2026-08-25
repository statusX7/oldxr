package mydispatcher

import (
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type userConnectionLifecycle struct {
	remaining atomic.Int32
	flow      *userIO
}

func newUserConnectionLifecycle(flow *userIO, owners int32) *userConnectionLifecycle {
	lifecycle := &userConnectionLifecycle{flow: flow}
	lifecycle.remaining.Store(owners)
	return lifecycle
}

func (l *userConnectionLifecycle) release() {
	if l == nil || l.flow == nil {
		return
	}
	if l.remaining.Add(-1) == 0 {
		l.flow.Release()
	}
}

type lifecycleWriter struct {
	Writer    buf.Writer
	lifecycle *userConnectionLifecycle
	once      sync.Once
}

func (w *lifecycleWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *lifecycleWriter) Close() error {
	err := common.Close(w.Writer)
	w.once.Do(w.lifecycle.release)
	return err
}

func (w *lifecycleWriter) Interrupt() {
	common.Interrupt(w.Writer)
	w.once.Do(w.lifecycle.release)
}

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

type SizeStatReader struct {
	Counter stats.Counter
	Reader  buf.Reader
}

func (r *SizeStatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.Counter.Add(int64(mb.Len()))
	}
	return mb, err
}

func (r *SizeStatReader) Interrupt() {
	common.Interrupt(r.Reader)
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
