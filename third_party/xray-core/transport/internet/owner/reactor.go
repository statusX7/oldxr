//go:build linux

// Package owner transfers established TCP sockets to a small number of
// process-wide event loops. Protocol packages keep their own framing and
// cryptographic state; this package only owns socket readiness and lifecycle.
package owner

import (
	"context"
	"errors"
	"expvar"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/panjf2000/gnet/v2"
)

// Role identifies one endpoint of an owned relay pair.
type Role uint8

const (
	Inbound Role = iota + 1
	Outbound
)

// Action and Conn intentionally expose only gnet's event callback contract to
// protocol-local incremental state machines.
type Action = gnet.Action

// Conn is the minimal event-loop connection surface used by protocol-local
// owner sessions. Keeping it narrow makes lifecycle and partial-I/O behavior
// testable without exposing the rest of gnet's API.
type Conn interface {
	Write([]byte) (int, error)
	TryWrite([]byte) (int, error)
	// Next returns callback-scoped storage. Sessions must copy bytes that
	// remain live after the current Session callback returns.
	Next(int) ([]byte, error)
	Discard(int) (int, error)
	// InboundBuffered returns the bounded processing window exposed to the
	// current callback, which can be smaller than data retained by the owner.
	InboundBuffered() int
	SuspendRead() error
	ResumeRead() error
	ArmWrite() error
	DisarmWrite() error
	Wake(gnet.AsyncCallback) error
	Close() error
}

var protocolPendingWakeCallback gnet.AsyncCallback = func(gnet.Conn, error) error { return nil }

// WakeProtocolPending forces a traffic callback for work buffered by a
// protocol state machine rather than by the socket owner itself. ResumeRead
// may have no owner-buffered bytes while a protocol retains encrypted input in
// connection-local storage.
func WakeProtocolPending(conn Conn) error {
	if conn == nil {
		return net.ErrClosed
	}
	return conn.Wake(protocolPendingWakeCallback)
}

const (
	None  = gnet.None
	Close = gnet.Close
)

// Session is single-owner state. Both endpoints are enrolled on the same event
// loop, so these callbacks are serialized for one session.
type Session interface {
	OnOpen(Role, Conn)
	OnTraffic(Role, Conn) Action
	OnWritable(Role, Conn) Action
	OnReadClosed(Role, Conn) Action
	OnClose(Role, Conn, error)
}

type endpoint struct {
	role    Role
	session Session
}

type eventHandler struct {
	gnet.BuiltinEventEngine
}

func (eventHandler) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	owned, ok := conn.(Conn)
	if !ok {
		return nil, gnet.Close
	}
	endpoint, ok := conn.Context().(*endpoint)
	if !ok || endpoint.session == nil {
		return nil, gnet.Close
	}
	endpoint.session.OnOpen(endpoint.role, owned)
	return nil, gnet.None
}

func (eventHandler) OnTraffic(conn gnet.Conn) gnet.Action {
	owned, ok := conn.(Conn)
	if !ok {
		return gnet.Close
	}
	endpoint, ok := conn.Context().(*endpoint)
	if !ok || endpoint.session == nil {
		return gnet.Close
	}
	return endpoint.session.OnTraffic(endpoint.role, owned)
}

func (eventHandler) OnReadClosed(conn gnet.Conn) gnet.Action {
	owned, ok := conn.(Conn)
	if !ok {
		return gnet.Close
	}
	endpoint, ok := conn.Context().(*endpoint)
	if !ok || endpoint.session == nil {
		return gnet.Close
	}
	return endpoint.session.OnReadClosed(endpoint.role, owned)
}

func (eventHandler) OnWritable(conn gnet.Conn) gnet.Action {
	owned, ok := conn.(Conn)
	if !ok {
		return gnet.Close
	}
	endpoint, ok := conn.Context().(*endpoint)
	if !ok || endpoint.session == nil {
		return gnet.Close
	}
	return endpoint.session.OnWritable(endpoint.role, owned)
}

func (eventHandler) OnClose(conn gnet.Conn, err error) gnet.Action {
	owned, ownedOK := conn.(Conn)
	endpoint, ok := conn.Context().(*endpoint)
	if ownedOK && ok && endpoint.session != nil {
		endpoint.session.OnClose(endpoint.role, owned, err)
	}
	return gnet.None
}

var defaultClient struct {
	once   sync.Once
	client *gnet.Client
	err    error
}

var hybridClient struct {
	once   sync.Once
	client *gnet.Client
	err    error
}

var (
	hybridOwnerSequence atomic.Uint64
	hybridAdvanced      = expvar.NewInt("xray_socket_owner_hybrid_advanced")
	hybridGnet          = expvar.NewInt("xray_socket_owner_hybrid_gnet")
	hybridFallbacks     = expvar.NewMap("xray_socket_owner_hybrid_fallbacks")
)

const hybridOwnerStride = 5

func newGnetOwnerClient(eventLoops int) (*gnet.Client, error) {
	client, err := gnet.NewClient(
		&eventHandler{},
		gnet.WithNumEventLoop(eventLoops),
		gnet.WithEdgeTriggeredIO(false),
		gnet.WithReadBufferCap(16*1024),
		gnet.WithWriteBufferCap(64*1024),
		gnet.WithTCPNoDelay(gnet.TCPNoDelay),
	)
	if err != nil {
		return nil, err
	}
	if err := client.Start(); err != nil {
		_ = client.Stop()
		return nil, err
	}
	return client, nil
}

func client() (*gnet.Client, error) {
	defaultClient.once.Do(func() {
		defaultClient.client, defaultClient.err = newGnetOwnerClient(3)
	})
	return defaultClient.client, defaultClient.err
}

func spilloverClient() (*gnet.Client, error) {
	hybridClient.once.Do(func() {
		hybridClient.client, hybridClient.err = newGnetOwnerClient(1)
	})
	return hybridClient.client, hybridClient.err
}

// AdoptPair enrolls both sockets on one event loop. The outbound endpoint is
// enrolled first so inbound traffic cannot outrun target readiness and build an
// unbounded userspace queue during transfer. On success gnet owns the supplied
// net.TCPConn values and the caller may return from its connection goroutine.
func adoptGnetPair(inbound, outbound *net.TCPConn, session Session) error {
	if inbound == nil || outbound == nil || session == nil {
		return errors.New("owner: invalid relay pair")
	}
	client, err := client()
	if err != nil {
		return err
	}
	return adoptGnetPairWith(client, inbound, outbound, session)
}

func adoptGnetPairWith(client *gnet.Client, inbound, outbound *net.TCPConn, session Session) error {
	if client == nil || inbound == nil || outbound == nil || session == nil {
		return errors.New("owner: invalid gnet relay pair")
	}
	outboundConn, err := client.EnrollContext(outbound, &endpoint{role: Outbound, session: session})
	if err != nil {
		return err
	}
	registered, err := outboundConn.EventLoop().Enroll(
		gnet.NewContext(context.Background(), &endpoint{role: Inbound, session: session}),
		inbound,
	)
	if err != nil {
		_ = outboundConn.Close()
		return err
	}
	result := <-registered
	if result.Err != nil {
		_ = outboundConn.Close()
		return result.Err
	}
	return nil
}

func hybridUsesGnet(sequence uint64) bool {
	return sequence%hybridOwnerStride == 0
}

func adoptHybridPair(inbound, outbound *net.TCPConn, session Session) error {
	advanced, err := advancedUringOwnerClient()
	if err != nil {
		hybridFallbacks.Add("advanced-unavailable", 1)
		return adoptGnetPair(inbound, outbound, session)
	}
	sequence := hybridOwnerSequence.Add(1) - 1
	if hybridUsesGnet(sequence) {
		spillover, spilloverErr := spilloverClient()
		if spilloverErr == nil {
			hybridGnet.Add(1)
			return adoptGnetPairWith(spillover, inbound, outbound, session)
		}
		hybridFallbacks.Add("gnet-unavailable", 1)
	}
	hybridAdvanced.Add(1)
	return adoptAdvancedUringPairWith(advanced, inbound, outbound, session)
}

// AdoptPair selects the socket executor once per connection. Auto mode starts
// the advanced backend only when all required io_uring features initialize;
// older or restricted kernels retain the same protocol session on gnet.
func AdoptPair(inbound, outbound *net.TCPConn, session Session) error {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XRAYR_SOCKET_OWNER_REACTOR"))) {
	case "uring", "uring-advanced":
		return adoptAdvancedUringPair(inbound, outbound, session)
	case "hybrid", "uring-gnet-hybrid":
		return adoptHybridPair(inbound, outbound, session)
	case "gnet", "epoll":
		return adoptGnetPair(inbound, outbound, session)
	case "", "auto":
		reactor, err := advancedUringOwnerClient()
		if err != nil {
			advancedUringOwnerFallbacks.Add(err.Error(), 1)
			return adoptGnetPair(inbound, outbound, session)
		}
		return adoptAdvancedUringPairWith(reactor, inbound, outbound, session)
	default:
		advancedUringOwnerFallbacks.Add("invalid-reactor-mode", 1)
		return adoptGnetPair(inbound, outbound, session)
	}
}
