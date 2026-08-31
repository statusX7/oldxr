package mydispatcher

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type ownershipTestReader struct {
	interrupted atomic.Bool
}

func (*ownershipTestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, io.EOF
}

func (r *ownershipTestReader) Interrupt() {
	r.interrupted.Store(true)
}

type ownershipTestWriter struct {
	closed atomic.Bool
}

func (*ownershipTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (w *ownershipTestWriter) Close() error {
	w.closed.Store(true)
	return nil
}

type ownershipTestHandler struct {
	dispatched chan *transport.Link
}

func (*ownershipTestHandler) Start() error { return nil }
func (*ownershipTestHandler) Close() error { return nil }
func (*ownershipTestHandler) Tag() string  { return "test" }

func (h *ownershipTestHandler) Dispatch(_ context.Context, link *transport.Link) {
	h.dispatched <- link
}

type ownershipTestManager struct {
	defaultHandler outbound.Handler
}

func (*ownershipTestManager) Type() interface{} { return outbound.ManagerType() }
func (*ownershipTestManager) Start() error      { return nil }
func (*ownershipTestManager) Close() error      { return nil }
func (*ownershipTestManager) GetHandler(string) outbound.Handler {
	return nil
}
func (m *ownershipTestManager) GetDefaultHandler() outbound.Handler {
	return m.defaultHandler
}
func (*ownershipTestManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (*ownershipTestManager) RemoveHandler(context.Context, string) error        { return nil }

func newOwnershipTestContext(destination net.Destination) context.Context {
	return session.ContextWithOutbound(context.Background(), &session.Outbound{Target: destination})
}

func TestRoutedDispatchTransfersLinkOwnershipToHandler(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.test"), 443)
	handler := &ownershipTestHandler{dispatched: make(chan *transport.Link, 1)}
	dispatcher := &DefaultDispatcher{ohm: &ownershipTestManager{defaultHandler: handler}}
	reader := new(ownershipTestReader)
	writer := new(ownershipTestWriter)
	link := &transport.Link{Reader: reader, Writer: writer}

	dispatcher.routedDispatch(newOwnershipTestContext(destination), link, destination)

	if got := <-handler.dispatched; got != link {
		t.Fatal("outbound handler received a different link")
	}
	if writer.closed.Load() {
		t.Fatal("dispatcher closed a link after transferring ownership to the outbound handler")
	}
	if reader.interrupted.Load() {
		t.Fatal("dispatcher interrupted a link after transferring ownership to the outbound handler")
	}
}

func TestRoutedDispatchClosesLinkWhenSelectionFails(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.test"), 443)
	dispatcher := &DefaultDispatcher{ohm: &ownershipTestManager{}}
	reader := new(ownershipTestReader)
	writer := new(ownershipTestWriter)

	dispatcher.routedDispatch(newOwnershipTestContext(destination), &transport.Link{
		Reader: reader,
		Writer: writer,
	}, destination)

	if !writer.closed.Load() {
		t.Fatal("dispatcher did not close the writer after outbound selection failed")
	}
	if !reader.interrupted.Load() {
		t.Fatal("dispatcher did not interrupt the reader after outbound selection failed")
	}
}
