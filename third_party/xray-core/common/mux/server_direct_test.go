package mux

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

type directTestDispatcher struct {
	called bool
	link   *transport.DirectLink
}

func (*directTestDispatcher) Type() interface{} { return nil }
func (*directTestDispatcher) Start() error      { return nil }
func (*directTestDispatcher) Close() error      { return nil }

func (*directTestDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (*directTestDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (d *directTestDispatcher) DispatchDirect(_ context.Context, _ net.Destination, input buf.Reader) (*transport.DirectLink, buf.Reader, error) {
	d.called = true
	return d.link, input, nil
}

func TestServerForwardsDirectDispatch(t *testing.T) {
	link := &transport.DirectLink{}
	dispatcher := &directTestDispatcher{link: link}
	server := &Server{dispatcher: dispatcher}

	got, replay, err := server.DispatchDirect(context.Background(), net.TCPDestination(net.LocalHostIP, 443), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatcher.called {
		t.Fatal("direct dispatcher was not called")
	}
	if got != link {
		t.Fatalf("unexpected direct link: got %p, want %p", got, link)
	}
	if replay != nil {
		t.Fatal("unexpected replay reader")
	}
}
