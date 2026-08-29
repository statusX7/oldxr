package transport

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type directLinkTestFlow struct {
	releases atomic.Int32
}

func (*directLinkTestFlow) OwnerEligible() bool               { return true }
func (*directLinkTestFlow) Acquire(int) (time.Duration, bool) { return 0, true }
func (*directLinkTestFlow) AddUplink(int64)                   {}
func (*directLinkTestFlow) AddDownlink(int64)                 {}
func (f *directLinkTestFlow) Release()                        { f.releases.Add(1) }

func TestDirectLinkCloseReleasesFlowExactlyOnce(t *testing.T) {
	flow := new(directLinkTestFlow)
	var closes atomic.Int32
	link := NewDirectLink(nil, nil, func() error {
		closes.Add(1)
		return nil
	})
	link.SetFlow(flow)
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("socket closes = %d, want 1", got)
	}
	if got := flow.releases.Load(); got != 1 {
		t.Fatalf("flow releases = %d, want 1", got)
	}
}

func TestDirectLinkTakeFlowTransfersRelease(t *testing.T) {
	flow := new(directLinkTestFlow)
	link := NewDirectLink(nil, nil, nil)
	link.SetFlow(flow)
	taken := link.TakeFlow()
	if taken != flow {
		t.Fatal("TakeFlow did not return the owned flow")
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if got := flow.releases.Load(); got != 0 {
		t.Fatalf("link released transferred flow %d times", got)
	}
	taken.Release()
	if got := flow.releases.Load(); got != 1 {
		t.Fatalf("transferred flow releases = %d, want 1", got)
	}
}

func TestDirectLinkCloseWritePreservesReverseTraffic(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	direct, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()

	link := NewDirectLink(nil, nil, direct.Close)
	link.SetConnection(direct, nil, nil)
	if err := link.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if n, err := peer.Read(buffer); n != 0 || err != io.EOF {
		t.Fatalf("peer read after direct half-close = (%d, %v), want (0, EOF)", n, err)
	}

	response := []byte("reverse-remains-open")
	if _, err := peer.Write(response); err != nil {
		t.Fatal(err)
	}
	_ = direct.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(response))
	if _, err := io.ReadFull(direct, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(response) {
		t.Fatalf("reverse payload = %q, want %q", received, response)
	}
}
