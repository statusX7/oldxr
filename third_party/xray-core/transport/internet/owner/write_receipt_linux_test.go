//go:build linux

package owner

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"golang.org/x/sys/unix"
)

var ownerWriteReceiptBenchmarkSink byte

type advancedUringOwnerReceiptRelaySession struct {
	conn      [2]Conn
	receipt   [2]WriteReceipt
	readEOF   [2]bool
	opened    chan struct{}
	closed    chan struct{}
	openOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

func newAdvancedUringOwnerReceiptRelaySession() *advancedUringOwnerReceiptRelaySession {
	return &advancedUringOwnerReceiptRelaySession{
		opened: make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (session *advancedUringOwnerReceiptRelaySession) OnOpen(role Role, conn Conn) {
	session.conn[int(role)-1] = conn
	if session.conn[0] != nil && session.conn[1] != nil {
		session.openOnce.Do(func() { close(session.opened) })
	}
}

func (session *advancedUringOwnerReceiptRelaySession) pause(source, destination int) Action {
	if err := session.conn[destination].ArmWrite(); err != nil {
		return Close
	}
	if err := session.conn[source].SuspendRead(); err != nil {
		return Close
	}
	return None
}

func (session *advancedUringOwnerReceiptRelaySession) resume(source, destination int) Action {
	if err := session.conn[destination].DisarmWrite(); err != nil {
		return Close
	}
	if err := session.conn[source].ResumeRead(); err != nil {
		return Close
	}
	_ = session.conn[source].Wake(nil)
	return None
}

func (session *advancedUringOwnerReceiptRelaySession) flush(destination int) Action {
	receipt := session.receipt[destination]
	if !receipt.Valid() {
		return None
	}
	writer, ok := session.conn[destination].(OwnedWriteConn)
	if !ok {
		return Close
	}
	_, done, err := writer.CompleteOwnedWrite(receipt)
	if err != nil {
		return Close
	}
	source := 1 - destination
	if !done {
		return session.pause(source, destination)
	}
	session.receipt[destination] = WriteReceipt{}
	return session.resume(source, destination)
}

func (session *advancedUringOwnerReceiptRelaySession) OnTraffic(role Role, conn Conn) Action {
	source := int(role) - 1
	destination := 1 - source
	if action := session.flush(destination); action == Close {
		return action
	}
	if session.receipt[destination].Valid() {
		return None
	}
	buffered := conn.InboundBuffered()
	if buffered == 0 {
		return None
	}
	payload, err := conn.Next(buffered)
	if err != nil {
		return Close
	}
	writer, ok := session.conn[destination].(OwnedWriteConn)
	if !ok {
		return Close
	}
	written, receipt, err := writer.BeginOwnedWrite(payload)
	if err != nil {
		return Close
	}
	if !receipt.Valid() {
		if written != len(payload) {
			return Close
		}
		return None
	}
	session.receipt[destination] = receipt
	return session.pause(source, destination)
}

func (session *advancedUringOwnerReceiptRelaySession) OnWritable(role Role, _ Conn) Action {
	return session.flush(int(role) - 1)
}

func (session *advancedUringOwnerReceiptRelaySession) OnReadClosed(role Role, _ Conn) Action {
	session.readEOF[int(role)-1] = true
	if session.readEOF[0] && session.readEOF[1] {
		return Close
	}
	return None
}

func (session *advancedUringOwnerReceiptRelaySession) OnClose(_ Role, _ Conn, err error) {
	session.closeOnce.Do(func() {
		session.closeErr = err
		close(session.closed)
	})
}

func socketPairForOwnedWrite(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return fds[0], fds[1]
}

func readOwnedWritePeer(t *testing.T, fd int, expected []byte) {
	t.Helper()
	actual := make([]byte, len(expected))
	for offset := 0; offset < len(actual); {
		n, err := unix.Read(fd, actual[offset:])
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal(io.ErrUnexpectedEOF)
		}
		offset += n
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("peer payload = %x; want %x", actual, expected)
	}
}

func TestAdvancedUringOwnerOwnedWriteDeferredLifecycle(t *testing.T) {
	loop := &advancedUringOwnerLoop{sessions: make([]*advancedUringOwnerSession, 3)}
	handler := &advancedUringOwnerDeferredSession{}
	session, conn := newAdvancedUringOwnerDeferredFixture(loop, 1, 0, handler)
	ownedFD, peerFD := socketPairForOwnedWrite(t)
	session.fds[0] = ownedFD

	payload := bytes.Repeat([]byte{0x5a}, 4096)
	written, receipt, err := conn.BeginOwnedWrite(payload)
	if err != nil || written != 0 || !receipt.Valid() {
		t.Fatalf("begin = (%d, valid=%v, %v); want (0, true, nil)", written, receipt.Valid(), err)
	}
	readOwnedWritePeer(t, peerFD, payload)
	if _, err := conn.TryWrite(payload); err == nil {
		t.Fatal("generic TryWrite accepted an active owned receipt")
	}
	if n, done, err := conn.CompleteOwnedWrite(receipt); err != nil || n != 0 || done {
		t.Fatalf("early completion = (%d, %v, %v); want (0, false, nil)", n, done, err)
	}

	loop.completeDeferredSends()
	if len(handler.writable) != 1 || handler.writable[0] != Inbound {
		t.Fatalf("writable callbacks = %v; want [%v]", handler.writable, Inbound)
	}
	if n, done, err := conn.CompleteOwnedWrite(receipt); err != nil || n != len(payload) || !done {
		t.Fatalf("completion = (%d, %v, %v); want (%d, true, nil)", n, done, err, len(payload))
	}
	if receipt.Valid() == false {
		t.Fatal("caller receipt unexpectedly mutated")
	}
	if _, _, err := conn.CompleteOwnedWrite(receipt); err == nil {
		t.Fatal("duplicate receipt completion succeeded")
	}
	if endpoint := conn.state(); endpoint.sendOwned || endpoint.sendPending || endpoint.sendCompletion || len(endpoint.sendBuffer) != 0 {
		t.Fatalf("completed endpoint retained state: %+v", endpoint)
	}

	secondPayload := []byte("second-generation")
	_, secondReceipt, err := conn.BeginOwnedWrite(secondPayload)
	if err != nil || !secondReceipt.Valid() || secondReceipt.generation == receipt.generation {
		t.Fatalf("second receipt = %+v, err=%v", secondReceipt, err)
	}
	readOwnedWritePeer(t, peerFD, secondPayload)
	if _, _, err := conn.CompleteOwnedWrite(receipt); err == nil {
		t.Fatal("stale receipt completed a newer generation")
	}

	otherHandler := &advancedUringOwnerDeferredSession{}
	_, otherConn := newAdvancedUringOwnerDeferredFixture(loop, 2, 0, otherHandler)
	if _, _, err := otherConn.CompleteOwnedWrite(secondReceipt); err == nil {
		t.Fatal("receipt completed on the wrong connection")
	}
	loop.completeDeferredSends()
	if n, done, err := conn.CompleteOwnedWrite(secondReceipt); err != nil || n != len(secondPayload) || !done {
		t.Fatalf("second completion = (%d, %v, %v)", n, done, err)
	}
}

func TestAdvancedUringOwnerOwnedWritePartialCompletions(t *testing.T) {
	endpoint := &advancedUringOwnerEndpoint{
		sendBuffer:     append([]byte(nil), "abcdefgh"...),
		sendCompletion: true,
		sendN:          3,
		sendOwned:      true,
		sendGeneration: 1,
		sendRemaining:  8,
	}
	resubmits := 0
	resubmit := func() error {
		resubmits++
		endpoint.sendPending = true
		return nil
	}

	n, done, err := completeAdvancedUringOwnedWrite(endpoint, resubmit)
	if err != nil || done || n != 3 || string(endpoint.sendBuffer) != "defgh" || resubmits != 1 {
		t.Fatalf("first partial = (%d, %v, %v), tail=%q resubmits=%d", n, done, err, endpoint.sendBuffer, resubmits)
	}
	endpoint.sendPending = false
	endpoint.sendCompletion = true
	endpoint.sendN = 2
	n, done, err = completeAdvancedUringOwnedWrite(endpoint, resubmit)
	if err != nil || done || n != 2 || string(endpoint.sendBuffer) != "fgh" || resubmits != 2 {
		t.Fatalf("second partial = (%d, %v, %v), tail=%q resubmits=%d", n, done, err, endpoint.sendBuffer, resubmits)
	}
	endpoint.sendPending = false
	endpoint.sendCompletion = true
	endpoint.sendN = 3
	n, done, err = completeAdvancedUringOwnedWrite(endpoint, resubmit)
	if err != nil || !done || n != 3 || endpoint.sendOwned || len(endpoint.sendBuffer) != 0 || resubmits != 2 {
		t.Fatalf("final completion = (%d, %v, %v), state=%+v resubmits=%d", n, done, err, endpoint, resubmits)
	}
}

func TestAdvancedUringOwnerOwnedWriteCompletionErrors(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *advancedUringOwnerEndpoint
		resubmit func() error
	}{
		{
			name: "hard-error",
			endpoint: &advancedUringOwnerEndpoint{
				sendBuffer:     []byte("abc"),
				sendCompletion: true,
				sendErr:        io.ErrClosedPipe,
				sendOwned:      true,
				sendGeneration: 1,
				sendRemaining:  3,
			},
		},
		{
			name: "oversized-completion",
			endpoint: &advancedUringOwnerEndpoint{
				sendBuffer:     []byte("abc"),
				sendCompletion: true,
				sendN:          4,
				sendOwned:      true,
				sendGeneration: 1,
				sendRemaining:  3,
			},
		},
		{
			name: "resubmit-error",
			endpoint: &advancedUringOwnerEndpoint{
				sendBuffer:     []byte("abc"),
				sendCompletion: true,
				sendN:          1,
				sendOwned:      true,
				sendGeneration: 1,
				sendRemaining:  3,
			},
			resubmit: func() error { return io.ErrClosedPipe },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resubmit := test.resubmit
			if resubmit == nil {
				resubmit = func() error { return nil }
			}
			_, done, err := completeAdvancedUringOwnedWrite(test.endpoint, resubmit)
			if err == nil || !done {
				t.Fatalf("completion = (done=%v, err=%v); want terminal error", done, err)
			}
			if test.endpoint.sendOwned || test.endpoint.sendPending || test.endpoint.sendCompletion || len(test.endpoint.sendBuffer) != 0 {
				t.Fatalf("terminal error retained state: %+v", test.endpoint)
			}
		})
	}
}

func TestAdvancedUringOwnerOwnedWriteCloseBeforeCompletion(t *testing.T) {
	loop := &advancedUringOwnerLoop{sessions: make([]*advancedUringOwnerSession, 2)}
	handler := &advancedUringOwnerDeferredSession{}
	session, conn := newAdvancedUringOwnerDeferredFixture(loop, 1, 0, handler)
	ownedFD, peerFD := socketPairForOwnedWrite(t)
	session.fds[0] = ownedFD

	payload := []byte("close-before-completion")
	_, receipt, err := conn.BeginOwnedWrite(payload)
	if err != nil {
		t.Fatal(err)
	}
	readOwnedWritePeer(t, peerFD, payload)
	session.endpoint[1].readArmed = true
	session.closing = true
	loop.completeDeferredSends()
	if endpoint := conn.state(); endpoint.sendOwned || endpoint.sendPending || endpoint.sendCompletion || len(endpoint.sendBuffer) != 0 {
		t.Fatalf("closing endpoint retained state: %+v", endpoint)
	}
	if _, _, err := conn.CompleteOwnedWrite(receipt); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("completion after close = %v; want net.ErrClosed", err)
	}
}

func TestAdvancedUringOwnerOwnedWriteHardSendError(t *testing.T) {
	loop := &advancedUringOwnerLoop{sessions: make([]*advancedUringOwnerSession, 2)}
	handler := &advancedUringOwnerDeferredSession{}
	_, conn := newAdvancedUringOwnerDeferredFixture(loop, 1, 0, handler)
	conn.session.fds[0] = -1
	written, receipt, err := conn.BeginOwnedWrite([]byte("payload"))
	if err == nil || written != 0 || receipt.Valid() {
		t.Fatalf("hard send = (%d, valid=%v, %v); want (0, false, error)", written, receipt.Valid(), err)
	}
}

func TestAdvancedUringOwnerOwnedWriteRetryErrors(t *testing.T) {
	if !retryAdvancedUringOwnerSend(unix.EAGAIN) || !retryAdvancedUringOwnerSend(unix.EINTR) {
		t.Fatal("EAGAIN/EINTR must retain and retry the owner-owned tail")
	}
	if retryAdvancedUringOwnerSend(unix.EBADF) {
		t.Fatal("hard send error classified as retryable")
	}
}

func TestAdvancedUringOwnerOwnedWriteRepeatedRoundTrips(t *testing.T) {
	const roundTrips = 100
	reactor, err := newAdvancedUringOwnerReactorSized(1, advancedUringOwnerTestEntries)
	if advancedUringOwnerUnavailable(err) {
		t.Skipf("advanced io_uring unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer reactor.close()

	inboundListener := listenAdvancedUringOwnerTCP(t)
	defer inboundListener.Close()
	targetListener := listenAdvancedUringOwnerTCP(t)
	defer targetListener.Close()
	client, err := net.DialTCP("tcp", nil, inboundListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inbound, err := inboundListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := net.DialTCP("tcp", nil, targetListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	target, err := targetListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() { _, _ = io.Copy(target, target) }()

	session := newAdvancedUringOwnerReceiptRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.opened:
	case <-time.After(3 * time.Second):
		t.Fatal("owner receipt session did not open")
	}
	payload := bytes.Repeat([]byte("owner-receipt-round-trip-"), 164)
	received := make([]byte, len(payload))
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	for iteration := 0; iteration < roundTrips; iteration++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", iteration, err)
		}
		if _, err := io.ReadFull(client, received); err != nil {
			t.Fatalf("read %d: %v", iteration, err)
		}
		if !bytes.Equal(received, payload) {
			t.Fatalf("round trip %d mismatch", iteration)
		}
	}
	type stateSnapshot struct {
		clean bool
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshots := make(chan stateSnapshot, 1)
		if err := session.conn[0].Wake(func(_ gnet.Conn, _ error) error {
			clean := true
			for side, ownedConn := range session.conn {
				endpoint := ownedConn.(*advancedUringOwnerConn).state()
				if session.receipt[side].Valid() || endpoint.sendOwned || endpoint.sendPending || endpoint.sendCompletion || len(endpoint.sendBuffer) != 0 {
					clean = false
				}
			}
			snapshots <- stateSnapshot{clean: clean}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if snapshot := <-snapshots; snapshot.clean {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owner receipt state did not drain")
		}
		time.Sleep(time.Millisecond)
	}
}

func BenchmarkAdvancedUringOwnerUploadStaging(b *testing.B) {
	payload := bytes.Repeat([]byte{0x6b}, 4096)
	b.Run("legacy-copy", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		pending := make([]byte, 0, len(payload))
		for i := 0; i < b.N; i++ {
			pending = append(pending[:0], payload...)
			ownerWriteReceiptBenchmarkSink ^= pending[i&(len(payload)-1)]
		}
	})
	b.Run("owner-receipt", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		loop := &advancedUringOwnerLoop{}
		session := &advancedUringOwnerSession{}
		conn := &advancedUringOwnerConn{loop: loop, session: session}
		var pending WriteReceipt
		for i := 0; i < b.N; i++ {
			pending = conn.startOwnedWriteReceipt(len(payload))
			if !pending.Valid() {
				b.Fatal("invalid receipt")
			}
			ownerWriteReceiptBenchmarkSink ^= payload[i&(len(payload)-1)] ^ byte(conn.state().sendRemaining)
		}
	})
}
