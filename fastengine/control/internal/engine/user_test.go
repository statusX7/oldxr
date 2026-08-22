package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type failingBufferWriter struct{}

func (failingBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return errors.New("injected write failure")
}

func TestDeviceAdmissionCountsDistinctIPs(t *testing.T) {
	u := newUserRuntime(1, "secret", 0, 2)
	if !u.admit("192.0.2.1", true) || !u.admit("192.0.2.1", true) || !u.admit("192.0.2.2", true) {
		t.Fatal("valid device admission rejected")
	}
	if u.admit("192.0.2.3", true) {
		t.Fatal("third distinct IP accepted")
	}
	u.release("192.0.2.1", true)
	if u.admit("192.0.2.3", true) {
		t.Fatal("IP was released while a second connection remained")
	}
	u.release("192.0.2.1", true)
	if !u.admit("192.0.2.3", true) {
		t.Fatal("new IP rejected after last connection released")
	}
}

func TestTrafficSnapshotRestore(t *testing.T) {
	u := newUserRuntime(1, "secret", 0, 0)
	u.upload.Add(10)
	u.download.Add(20)
	up, down := u.snapshotTraffic()
	if up != 10 || down != 20 {
		t.Fatalf("snapshot = (%d,%d), want (10,20)", up, down)
	}
	u.restoreTraffic(up, down)
	up, down = u.snapshotTraffic()
	if up != 10 || down != 20 {
		t.Fatalf("restored = (%d,%d), want (10,20)", up, down)
	}
}

func TestFeatureWriterDoesNotBillFailedBuffer(t *testing.T) {
	u := newUserRuntime(1, "secret", 0, 0)
	w := &featureWriter{inner: failingBufferWriter{}, user: u, ctx: context.Background(), features: Features{Traffic: true}}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("not-written"))}); err == nil {
		t.Fatal("injected write failure was lost")
	}
	if up, down := u.snapshotTraffic(); up != 0 || down != 0 {
		t.Fatalf("failed buffer was billed: upload=%d download=%d", up, down)
	}
}
