package transport

import (
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
