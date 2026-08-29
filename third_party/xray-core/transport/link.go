package transport

import (
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// Link is a utility for connecting between an inbound and an outbound proxy handler.
type Link struct {
	Reader buf.Reader
	Writer buf.Writer
}

// DirectLink owns a directly dialed outbound connection. It is optional and
// used only when a dispatcher and an outbound handler both support bypassing
// the generic in-memory transport pipes.
type DirectLink struct {
	Reader        buf.Reader
	Writer        buf.Writer
	Connection    *net.TCPConn
	ReadCounters  []stats.Counter
	WriteCounters []stats.Counter
	closeFunc     func() error
	stateMu       sync.Mutex
	flow          DirectFlow
	closeOnce     sync.Once
	closeErr      error
}

// DirectFlow binds per-user rate and traffic state before a socket is handed
// to the owner reactor. Acquire reserves bytes without blocking an event loop.
type DirectFlow interface {
	OwnerEligible() bool
	Acquire(bytes int) (time.Duration, bool)
	AddUplink(bytes int64)
	AddDownlink(bytes int64)
	Release()
}

// NewDirectLink creates a direct link with explicit connection ownership.
func NewDirectLink(reader buf.Reader, writer buf.Writer, closeFunc func() error) *DirectLink {
	return &DirectLink{
		Reader:    reader,
		Writer:    writer,
		closeFunc: closeFunc,
	}
}

// SetConnection exposes an unwrapped TCP connection and its wire counters to
// a supported socket-owner path. Generic callers continue to use Reader and
// Writer and are unaffected.
func (l *DirectLink) SetConnection(conn *net.TCPConn, readCounters, writeCounters []stats.Counter) {
	l.Connection = conn
	l.ReadCounters = readCounters
	l.WriteCounters = writeCounters
}

// CloseWrite forwards a completed logical upload to the direct target while
// preserving the reverse TCP stream. Generic pipe outbounds already receive
// this half-close when their request writer completes; direct sockets must do
// the same explicitly.
func (l *DirectLink) CloseWrite() error {
	if l == nil || l.Connection == nil {
		return nil
	}
	return l.Connection.CloseWrite()
}

// SetFlow transfers one connection-lifetime flow reference to the link. The
// reference is released by Close unless TakeFlow transfers it to a socket
// owner first.
func (l *DirectLink) SetFlow(flow DirectFlow) {
	if l == nil {
		if flow != nil {
			flow.Release()
		}
		return
	}
	l.stateMu.Lock()
	previous := l.flow
	l.flow = flow
	l.stateMu.Unlock()
	if previous != nil {
		previous.Release()
	}
}

// Flow returns the current flow without transferring ownership.
func (l *DirectLink) Flow() DirectFlow {
	if l == nil {
		return nil
	}
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	return l.flow
}

// TakeFlow transfers the connection-lifetime reference from the link to its
// caller. A subsequent Close still releases the socket but not the flow.
func (l *DirectLink) TakeFlow() DirectFlow {
	if l == nil {
		return nil
	}
	l.stateMu.Lock()
	flow := l.flow
	l.flow = nil
	l.stateMu.Unlock()
	return flow
}

// Close releases the directly owned outbound connection.
func (l *DirectLink) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		if l.closeFunc != nil {
			l.closeErr = l.closeFunc()
		}
		if flow := l.TakeFlow(); flow != nil {
			flow.Release()
		}
	})
	return l.closeErr
}
