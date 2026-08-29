package quic

import (
	"context"
	"fmt"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/xtls/xray-core/common/log"
)

func newQlogTracer(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	trace := qlogwriter.NewConnectionFileSeq(
		&QlogWriter{connID: append([]byte(nil), connID.Bytes()...)},
		isClient,
		connID,
		[]string{qlog.EventSchema},
	)
	go trace.Run()
	return trace
}

type QlogWriter struct {
	connID []byte
}

func (w *QlogWriter) Write(b []byte) (int, error) {
	if len(b) > 1 { // skip line separator "0a" in qlog
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("[%x] %s", w.connID, b),
		})
	}
	return len(b), nil
}

func (w *QlogWriter) Close() error {
	// Noop
	return nil
}
