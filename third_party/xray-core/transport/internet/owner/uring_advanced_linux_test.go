//go:build linux

package owner

import (
	"bytes"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const advancedUringOwnerTestEntries = 1024

func TestAdvancedUringOwnerProtocolPendingWakeBypassesResumeNoop(t *testing.T) {
	wakeFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wakeFD)

	loop := &advancedUringOwnerLoop{
		wakeFD: wakeFD,
		tasks:  make(chan advancedUringOwnerTask, 1),
		done:   make(chan struct{}),
	}
	session := &advancedUringOwnerSession{id: 1}
	conn := &advancedUringOwnerConn{loop: loop, session: session, side: 0}
	session.endpoint[0].conn = conn
	session.endpoint[0].resumeWakeNoop.Store(true)

	if err := conn.Wake(nil); err != nil {
		t.Fatal(err)
	}
	if len(loop.tasks) != 0 {
		t.Fatal("ordinary resume wake was not skipped")
	}

	session.endpoint[0].resumeWakeNoop.Store(true)
	if err := WakeProtocolPending(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case task := <-loop.tasks:
		if task.callback == nil {
			t.Fatal("protocol-pending wake lost its forcing callback")
		}
	default:
		t.Fatal("protocol-pending wake was incorrectly skipped")
	}
	if session.endpoint[0].resumeWakeNoop.Load() {
		t.Fatal("protocol-pending wake left a stale resume skip token")
	}
}

type advancedUringOwnerRelaySession struct {
	conn      [2]Conn
	pending   [2][]byte
	readEOF   [2]bool
	opened    chan struct{}
	closed    chan struct{}
	openOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

type advancedUringOwnerHoldingSession struct {
	conn         [2]Conn
	expected     int64
	hold         atomic.Bool
	received     atomic.Int64
	opened       chan struct{}
	held         chan struct{}
	complete     chan struct{}
	closed       chan struct{}
	openOnce     sync.Once
	holdOnce     sync.Once
	completeOnce sync.Once
	closeOnce    sync.Once
	closeErr     error
}

func newAdvancedUringOwnerHoldingSession(expected int64) *advancedUringOwnerHoldingSession {
	session := &advancedUringOwnerHoldingSession{
		expected: expected,
		opened:   make(chan struct{}),
		held:     make(chan struct{}),
		complete: make(chan struct{}),
		closed:   make(chan struct{}),
	}
	session.hold.Store(true)
	return session
}

func (session *advancedUringOwnerHoldingSession) OnOpen(role Role, conn Conn) {
	session.conn[int(role)-1] = conn
	if session.conn[0] != nil && session.conn[1] != nil {
		session.openOnce.Do(func() { close(session.opened) })
	}
}

func (session *advancedUringOwnerHoldingSession) OnTraffic(role Role, conn Conn) Action {
	if role != Inbound {
		_, _ = conn.Discard(-1)
		return None
	}
	if session.hold.Load() {
		if err := conn.SuspendRead(); err != nil {
			return Close
		}
		session.holdOnce.Do(func() { close(session.held) })
		return None
	}
	buffered := conn.InboundBuffered()
	if buffered > 0 {
		discarded, err := conn.Discard(-1)
		if err != nil {
			return Close
		}
		if session.received.Add(int64(discarded)) >= session.expected {
			session.completeOnce.Do(func() { close(session.complete) })
		}
	}
	if err := conn.ResumeRead(); err != nil {
		return Close
	}
	return None
}

func (session *advancedUringOwnerHoldingSession) OnWritable(Role, Conn) Action {
	return None
}

func (session *advancedUringOwnerHoldingSession) OnReadClosed(Role, Conn) Action {
	return None
}

func (session *advancedUringOwnerHoldingSession) OnClose(_ Role, _ Conn, err error) {
	session.closeOnce.Do(func() {
		session.closeErr = err
		close(session.closed)
	})
}

func newAdvancedUringOwnerRelaySession() *advancedUringOwnerRelaySession {
	return &advancedUringOwnerRelaySession{
		opened: make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (session *advancedUringOwnerRelaySession) OnOpen(role Role, conn Conn) {
	side := int(role) - 1
	session.conn[side] = conn
	if session.conn[0] != nil && session.conn[1] != nil {
		session.openOnce.Do(func() { close(session.opened) })
	}
}

func (session *advancedUringOwnerRelaySession) flush(destination int) Action {
	if len(session.pending[destination]) == 0 {
		return None
	}
	written, err := session.conn[destination].TryWrite(session.pending[destination])
	if written > 0 {
		session.pending[destination] = session.pending[destination][written:]
	}
	if err != nil {
		return Close
	}
	source := 1 - destination
	if len(session.pending[destination]) > 0 {
		if err := session.conn[destination].ArmWrite(); err != nil {
			return Close
		}
		if err := session.conn[source].SuspendRead(); err != nil {
			return Close
		}
		return None
	}
	if err := session.conn[destination].DisarmWrite(); err != nil {
		return Close
	}
	if err := session.conn[source].ResumeRead(); err != nil {
		return Close
	}
	_ = session.conn[source].Wake(nil)
	return None
}

func (session *advancedUringOwnerRelaySession) OnTraffic(role Role, conn Conn) Action {
	source := int(role) - 1
	destination := 1 - source
	if action := session.flush(destination); action == Close {
		return action
	}
	if len(session.pending[destination]) > 0 {
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
	session.pending[destination] = append(session.pending[destination], payload...)
	return session.flush(destination)
}

func (session *advancedUringOwnerRelaySession) OnWritable(role Role, _ Conn) Action {
	return session.flush(int(role) - 1)
}

func (session *advancedUringOwnerRelaySession) OnReadClosed(role Role, _ Conn) Action {
	session.readEOF[int(role)-1] = true
	if session.readEOF[0] && session.readEOF[1] {
		return Close
	}
	return None
}

func (session *advancedUringOwnerRelaySession) OnClose(_ Role, _ Conn, err error) {
	session.closeOnce.Do(func() {
		session.closeErr = err
		close(session.closed)
	})
}

func listenAdvancedUringOwnerTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func advancedUringOwnerUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL)
}

func TestAdvancedUringOwnerRejectsPartialInitialRecvSetup(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorSized(1, 1)
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
	defer inbound.Close()
	outbound, err := net.DialTCP("tcp", nil, targetListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	target, err := targetListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	session := newAdvancedUringOwnerRelaySession()
	err = reactor.adoptPair(inbound, outbound, session)
	if err == nil || !strings.Contains(err.Error(), "insufficient submission queue space") {
		t.Fatalf("adopt error = %v, want atomic two-recv capacity rejection", err)
	}
	loop := reactor.loops[0]
	if loop.nextID != 0 || len(loop.freeIDs) != 0 {
		t.Fatalf("failed setup changed session IDs: next=%d free=%v", loop.nextID, loop.freeIDs)
	}
	for id, installed := range loop.sessions {
		if installed != nil {
			t.Fatalf("failed setup retained session %d", id)
		}
	}

	// Adoption duplicates descriptors and closes the originals only after a
	// complete setup. A capacity failure must therefore leave generic fallback
	// able to use both original sockets.
	payload := []byte("generic-fallback-remains-open")
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = inbound.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(inbound, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("inbound fallback payload mismatch")
	}
}

func TestAdvancedUringOwnerRelayHalfClose(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorSized(2, advancedUringOwnerTestEntries)
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

	clientRaw, err := net.DialTCP("tcp", nil, inboundListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
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

	session := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.opened:
	case <-time.After(3 * time.Second):
		t.Fatal("owner session did not open")
	}

	request := bytes.Repeat([]byte("advanced-owner-request-"), 1024)
	response := bytes.Repeat([]byte("advanced-owner-response-"), 1024)
	_ = clientRaw.SetDeadline(time.Now().Add(5 * time.Second))
	_ = target.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientRaw.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := clientRaw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, request) {
		t.Fatalf("request mismatch: got=%d want=%d", len(received), len(request))
	}
	if _, err := target.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received, err = io.ReadAll(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, response) {
		t.Fatalf("response mismatch: got=%d want=%d", len(received), len(response))
	}
	select {
	case <-session.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("owner session did not close")
	}
}

func TestAdvancedUringOwnerHalfCloseDrainsBackpressuredUploadAndPreservesReverseTraffic(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorSized(2, advancedUringOwnerTestEntries)
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

	session := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.opened:
	case <-time.After(3 * time.Second):
		t.Fatal("owner session did not open")
	}

	request := bytes.Repeat([]byte("owner-backpressured-half-close-request-"), (64*1024*1024)/len("owner-backpressured-half-close-request-"))
	responseChunk := bytes.Repeat([]byte("owner-reverse-stream-after-forward-eof-"), 256)
	const responseChunks = 64
	response := bytes.Repeat(responseChunk, responseChunks)

	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	_ = target.SetDeadline(time.Now().Add(30 * time.Second))
	uploadDone := make(chan error, 1)
	go func() {
		if _, writeErr := io.Copy(client, bytes.NewReader(request)); writeErr != nil {
			uploadDone <- writeErr
			return
		}
		uploadDone <- client.CloseWrite()
	}()

	// Keep the target from reading long enough for the owner's outbound socket
	// to become write-blocked. The client upload must still be pending here;
	// otherwise this test did not exercise the intended state transition.
	time.Sleep(250 * time.Millisecond)
	select {
	case writeErr := <-uploadDone:
		if writeErr != nil {
			t.Fatalf("upload failed before backpressure was released: %v", writeErr)
		}
		t.Fatal("upload completed before target released backpressure")
	default:
	}

	targetDone := make(chan error, 1)
	var targetStage atomic.Int32
	var targetBytes atomic.Int64
	go func() {
		received := make([]byte, len(request))
		for offset := 0; offset < len(received); {
			readN, readErr := target.Read(received[offset:])
			if readN > 0 {
				offset += readN
				targetBytes.Add(int64(readN))
			}
			if readErr != nil {
				targetDone <- fmt.Errorf("read request at %d/%d: %w", offset, len(received), readErr)
				return
			}
		}
		if !bytes.Equal(received, request) {
			targetDone <- fmt.Errorf("request mismatch: got=%d want=%d", len(received), len(request))
			return
		}
		targetStage.Store(1)
		var trailing [1]byte
		if trailingN, trailingErr := target.Read(trailing[:]); trailingN != 0 || !errors.Is(trailingErr, io.EOF) {
			targetDone <- fmt.Errorf("forward half-close: n=%d err=%v", trailingN, trailingErr)
			return
		}
		targetStage.Store(2)
		for chunk := 0; chunk < responseChunks; chunk++ {
			if _, writeErr := target.Write(responseChunk); writeErr != nil {
				targetDone <- fmt.Errorf("write response chunk %d: %w", chunk, writeErr)
				return
			}
			if chunk%8 == 7 {
				time.Sleep(5 * time.Millisecond)
			}
		}
		targetStage.Store(3)
		targetDone <- target.CloseWrite()
	}()

	received, err := io.ReadAll(client)
	if err != nil {
		uploadState := "pending"
		select {
		case uploadErr := <-uploadDone:
			uploadState = fmt.Sprintf("complete err=%v", uploadErr)
		default:
		}
		targetState := "pending"
		select {
		case targetErr := <-targetDone:
			targetState = fmt.Sprintf("complete err=%v", targetErr)
		default:
		}
		t.Fatalf(
			"read reverse stream: %v; target_stage=%d target_bytes=%d/%d upload=%s target=%s owner_close=%v closes=%s recvs=%d sends=%d cancels=%d starvations=%d recoveries=%d inbound={armed:%t paused:%t cancel:%t eof:%t notified:%t buffered:%d send_pending:%t send_completion:%t pending_to_outbound:%d} outbound={armed:%t paused:%t cancel:%t eof:%t notified:%t buffered:%d send_pending:%t send_completion:%t pending_to_inbound:%d}",
			err,
			targetStage.Load(),
			targetBytes.Load(),
			len(request),
			uploadState,
			targetState,
			session.closeErr,
			advancedUringOwnerCloses.String(),
			advancedUringOwnerRecvs.Value(),
			advancedUringOwnerSends.Value(),
			advancedUringOwnerCancels.Value(),
			advancedUringOwnerStarvations.Value(),
			advancedUringOwnerRecoveries.Value(),
			session.conn[0].(*advancedUringOwnerConn).state().readArmed,
			session.conn[0].(*advancedUringOwnerConn).state().readPaused,
			session.conn[0].(*advancedUringOwnerConn).state().cancelPending,
			session.conn[0].(*advancedUringOwnerConn).state().readEOF,
			session.conn[0].(*advancedUringOwnerConn).state().readNotified,
			session.conn[0].(*advancedUringOwnerConn).state().readBuffered,
			session.conn[0].(*advancedUringOwnerConn).state().sendPending,
			session.conn[0].(*advancedUringOwnerConn).state().sendCompletion,
			len(session.pending[1]),
			session.conn[1].(*advancedUringOwnerConn).state().readArmed,
			session.conn[1].(*advancedUringOwnerConn).state().readPaused,
			session.conn[1].(*advancedUringOwnerConn).state().cancelPending,
			session.conn[1].(*advancedUringOwnerConn).state().readEOF,
			session.conn[1].(*advancedUringOwnerConn).state().readNotified,
			session.conn[1].(*advancedUringOwnerConn).state().readBuffered,
			session.conn[1].(*advancedUringOwnerConn).state().sendPending,
			session.conn[1].(*advancedUringOwnerConn).state().sendCompletion,
			len(session.pending[0]),
		)
	}
	if !bytes.Equal(received, response) {
		t.Fatalf("reverse stream mismatch: got=%d want=%d", len(received), len(response))
	}
	if err := <-uploadDone; err != nil {
		t.Fatal(err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("owner session did not close after both directions drained")
	}
}

func TestAdvancedUringOwnerRepeatedRoundTrips(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorSized(2, advancedUringOwnerTestEntries)
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

	session := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	<-session.opened
	payload := bytes.Repeat([]byte("round-trip-"), 372)
	received := make([]byte, len(payload))
	for iteration := 0; iteration < 100; iteration++ {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", iteration, err)
		}
		if _, err := io.ReadFull(client, received); err != nil {
			inboundState := session.conn[0].(*advancedUringOwnerConn).state()
			outboundState := session.conn[1].(*advancedUringOwnerConn).state()
			t.Fatalf("read %d: %v; inbound={armed:%v cancel:%v paused:%v buffered:%d send:%v completion:%v} outbound={armed:%v cancel:%v paused:%v buffered:%d send:%v completion:%v}",
				iteration, err,
				inboundState.readArmed, inboundState.cancelPending, inboundState.readPaused, inboundState.readBuffered, inboundState.sendPending, inboundState.sendCompletion,
				outboundState.readArmed, outboundState.cancelPending, outboundState.readPaused, outboundState.readBuffered, outboundState.sendPending, outboundState.sendCompletion)
		}
		if !bytes.Equal(received, payload) {
			t.Fatalf("round trip %d mismatch", iteration)
		}
	}
}

func TestAdvancedUringOwnerConcurrentRoundTrips(t *testing.T) {
	const (
		connections = 500
		roundTrips  = 16
	)

	reactor, err := newAdvancedUringOwnerReactorSized(2, advancedUringOwnerTestEntries)
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

	clients := make([]*net.TCPConn, 0, connections)
	for index := 0; index < connections; index++ {
		client, dialErr := net.DialTCP("tcp", nil, inboundListener.Addr().(*net.TCPAddr))
		if dialErr != nil {
			t.Fatalf("dial client %d: %v", index, dialErr)
		}
		inbound, acceptErr := inboundListener.AcceptTCP()
		if acceptErr != nil {
			client.Close()
			t.Fatalf("accept inbound %d: %v", index, acceptErr)
		}
		outbound, dialErr := net.DialTCP("tcp", nil, targetListener.Addr().(*net.TCPAddr))
		if dialErr != nil {
			client.Close()
			inbound.Close()
			t.Fatalf("dial target %d: %v", index, dialErr)
		}
		target, acceptErr := targetListener.AcceptTCP()
		if acceptErr != nil {
			client.Close()
			inbound.Close()
			outbound.Close()
			t.Fatalf("accept target %d: %v", index, acceptErr)
		}
		go func() {
			_, _ = io.Copy(target, target)
			_ = target.Close()
		}()
		session := newAdvancedUringOwnerRelaySession()
		if adoptErr := reactor.adoptPair(inbound, outbound, session); adoptErr != nil {
			client.Close()
			t.Fatalf("adopt pair %d: %v", index, adoptErr)
		}
		select {
		case <-session.opened:
		case <-time.After(3 * time.Second):
			client.Close()
			t.Fatalf("owner session %d did not open", index)
		}
		clients = append(clients, client)
	}
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()

	start := make(chan struct{})
	errorsByConnection := make(chan error, connections)
	var workers sync.WaitGroup
	for index, client := range clients {
		workers.Add(1)
		go func(connection int, socket *net.TCPConn) {
			defer workers.Done()
			<-start
			payload := bytes.Repeat([]byte{byte(connection), byte(connection >> 8), 0xa5, 0x5a}, 1024)
			received := make([]byte, len(payload))
			_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
			for iteration := 0; iteration < roundTrips; iteration++ {
				if _, writeErr := socket.Write(payload); writeErr != nil {
					errorsByConnection <- fmt.Errorf("connection %d write %d: %w", connection, iteration, writeErr)
					return
				}
				if _, readErr := io.ReadFull(socket, received); readErr != nil {
					errorsByConnection <- fmt.Errorf("connection %d read %d: %w", connection, iteration, readErr)
					return
				}
				if !bytes.Equal(received, payload) {
					errorsByConnection <- fmt.Errorf("connection %d round trip %d mismatch", connection, iteration)
					return
				}
			}
		}(index, client)
	}
	close(start)
	workers.Wait()
	close(errorsByConnection)
	for workerErr := range errorsByConnection {
		t.Error(workerErr)
	}
}

func TestAdvancedUringOwnerSlowConsumerBackpressure(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorSized(2, advancedUringOwnerTestEntries)
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

	session := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	<-session.opened
	payload := bytes.Repeat([]byte("bounded-slow-consumer-"), (8*1024*1024)/len("bounded-slow-consumer-"))
	received := make([]byte, len(payload))
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	_ = target.SetDeadline(time.Now().Add(15 * time.Second))
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(client, bytes.NewReader(payload))
		writeResult <- writeErr
	}()

	time.Sleep(250 * time.Millisecond)
	if _, err := io.ReadFull(target, received); err != nil {
		var closeErr error
		select {
		case <-session.closed:
			closeErr = session.closeErr
		default:
		}
		t.Fatalf("slow-consumer read: %v; owner close: %v; closes=%s starvations=%d recoveries=%d", err, closeErr, advancedUringOwnerCloses.String(), advancedUringOwnerStarvations.Value(), advancedUringOwnerRecoveries.Value())
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("slow-consumer payload mismatch")
	}
}

func TestAdvancedUringOwnerMultishotRecoversProvidedBufferStarvation(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorConfigured(1, advancedUringOwnerTestEntries, 1)
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

	payload := bytes.Repeat([]byte("recover-buffer-starvation-"), (1024*1024)/len("recover-buffer-starvation-"))
	session := newAdvancedUringOwnerHoldingSession(int64(len(payload)))
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	<-session.opened
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	starvationsBefore := advancedUringOwnerStarvations.Value()
	recoveriesBefore := advancedUringOwnerRecoveries.Value()
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(client, bytes.NewReader(payload))
		writeResult <- writeErr
	}()

	select {
	case <-session.held:
	case <-time.After(3 * time.Second):
		t.Fatal("owner session did not enter read hold")
	}
	deadline := time.Now().Add(3 * time.Second)
	for advancedUringOwnerStarvations.Value() == starvationsBefore && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if advancedUringOwnerStarvations.Value() == starvationsBefore {
		t.Fatal("small provided-buffer ring did not report starvation")
	}
	stableStarvations := advancedUringOwnerStarvations.Value()
	time.Sleep(50 * time.Millisecond)
	if got := advancedUringOwnerStarvations.Value(); got != stableStarvations {
		t.Fatalf("buffer starvation rearmed without recycled buffers: before=%d after=%d", stableStarvations, got)
	}
	select {
	case <-session.closed:
		t.Fatalf("provided-buffer starvation closed a valid session: %v", session.closeErr)
	default:
	}

	session.hold.Store(false)
	if err := session.conn[0].Wake(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.complete:
	case <-session.closed:
		t.Fatalf("owner session closed before consuming payload: %v", session.closeErr)
	case <-time.After(10 * time.Second):
		t.Fatalf("starved receive did not recover; consumed=%d want=%d", session.received.Load(), len(payload))
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if got := session.received.Load(); got != int64(len(payload)) {
		t.Fatalf("recovered byte count = %d; want %d", got, len(payload))
	}
	if advancedUringOwnerRecoveries.Value() == recoveriesBefore {
		t.Fatal("provided-buffer starvation recovered without a recorded rearm")
	}
}

func TestAdvancedUringOwnerRejectsInvalidBufferCounts(t *testing.T) {
	for _, count := range []int{0, 3, 1<<15 + 1, 1 << 16} {
		if _, err := newAdvancedUringOwnerReactorConfigured(1, advancedUringOwnerTestEntries, count); err == nil {
			t.Fatalf("buffer count %d unexpectedly accepted", count)
		}
	}
}

func TestAdvancedUringOwnerMultishotStarvationFairness(t *testing.T) {
	reactor, err := newAdvancedUringOwnerReactorConfigured(1, advancedUringOwnerTestEntries, 4)
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
	type heldPair struct {
		client  *net.TCPConn
		target  *net.TCPConn
		session *advancedUringOwnerHoldingSession
		payload []byte
		written chan error
	}
	adopt := func(marker byte) *heldPair {
		client, err := net.DialTCP("tcp", nil, inboundListener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		inbound, err := inboundListener.AcceptTCP()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		outbound, err := net.DialTCP("tcp", nil, targetListener.Addr().(*net.TCPAddr))
		if err != nil {
			client.Close()
			inbound.Close()
			t.Fatal(err)
		}
		target, err := targetListener.AcceptTCP()
		if err != nil {
			client.Close()
			inbound.Close()
			outbound.Close()
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{marker}, 512*1024)
		session := newAdvancedUringOwnerHoldingSession(int64(len(payload)))
		if err := reactor.adoptPair(inbound, outbound, session); err != nil {
			client.Close()
			target.Close()
			t.Fatal(err)
		}
		<-session.opened
		_ = client.SetDeadline(time.Now().Add(15 * time.Second))
		return &heldPair{client: client, target: target, session: session, payload: payload, written: make(chan error, 1)}
	}

	pairs := []*heldPair{adopt('a'), adopt('b')}
	defer func() {
		for _, pair := range pairs {
			pair.client.Close()
			pair.target.Close()
		}
	}()
	starvationsBefore := advancedUringOwnerStarvations.Value()
	for _, pair := range pairs {
		go func(pair *heldPair) {
			_, writeErr := io.Copy(pair.client, bytes.NewReader(pair.payload))
			pair.written <- writeErr
		}(pair)
	}
	deadline := time.Now().Add(3 * time.Second)
	for advancedUringOwnerStarvations.Value() == starvationsBefore && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if advancedUringOwnerStarvations.Value() == starvationsBefore {
		t.Fatal("two held sessions did not exhaust the shared provided-buffer ring")
	}

	for _, pair := range pairs {
		pair.session.hold.Store(false)
		if err := pair.session.conn[0].Wake(nil); err != nil {
			t.Fatal(err)
		}
	}
	for index, pair := range pairs {
		select {
		case <-pair.session.complete:
		case <-pair.session.closed:
			t.Fatalf("session %d closed before starvation recovery: %v", index, pair.session.closeErr)
		case <-time.After(10 * time.Second):
			t.Fatalf("session %d starved; consumed=%d want=%d starvations=%d recoveries=%d", index, pair.session.received.Load(), len(pair.payload), advancedUringOwnerStarvations.Value(), advancedUringOwnerRecoveries.Value())
		}
		if err := <-pair.written; err != nil {
			t.Fatalf("session %d write: %v", index, err)
		}
		if got := pair.session.received.Load(); got != int64(len(pair.payload)) {
			t.Fatalf("session %d consumed=%d want=%d", index, got, len(pair.payload))
		}
	}
}

func TestAdvancedUringOwnerAbruptCloseKeepsLoopUsable(t *testing.T) {
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
	session := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	<-session.opened
	_ = target.SetLinger(0)
	_ = target.Close()
	_, _ = client.Write([]byte("force-reset"))
	select {
	case <-session.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("abrupt peer close did not close owner session")
	}
	select {
	case <-reactor.loops[0].done:
		t.Fatalf("abrupt peer close stopped owner loop: %v", reactor.loops[0].failure())
	default:
	}

	secondClient, err := net.DialTCP("tcp", nil, inboundListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	secondInbound, err := inboundListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	secondOutbound, err := net.DialTCP("tcp", nil, targetListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	secondTarget, err := targetListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer secondTarget.Close()
	go func() { _, _ = io.Copy(secondTarget, secondTarget) }()
	secondSession := newAdvancedUringOwnerRelaySession()
	if err := reactor.adoptPair(secondInbound, secondOutbound, secondSession); err != nil {
		t.Fatal(err)
	}
	<-secondSession.opened
	payload := bytes.Repeat([]byte("after-abrupt-close-"), 256)
	received := make([]byte, len(payload))
	_ = secondClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := secondClient.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(secondClient, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("post-abrupt-close payload mismatch")
	}
}

func TestOwnerAutoReactorRelaysOrFallsBack(t *testing.T) {
	t.Setenv("XRAYR_SOCKET_OWNER_REACTOR", "auto")

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

	session := newAdvancedUringOwnerRelaySession()
	if err := AdoptPair(inbound, outbound, session); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.opened:
	case <-time.After(3 * time.Second):
		t.Fatal("auto owner session did not open")
	}

	payload := bytes.Repeat([]byte("auto-owner-fallback-"), 512)
	received := make([]byte, len(payload))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("auto owner payload mismatch")
	}

	start := make(chan struct{})
	var concurrent sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			<-start
			for iteration := 0; iteration < 32; iteration++ {
				_ = session.conn[0].Wake(nil)
			}
		}()
	}
	concurrent.Add(1)
	go func() {
		defer concurrent.Done()
		<-start
		_ = session.conn[0].Close()
	}()
	close(start)
	concurrent.Wait()
	select {
	case <-session.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent wake/close did not close the session")
	}

	if defaultAdvancedUringOwner.err != nil {
		t.Logf("advanced io_uring unavailable; gnet fallback used: %v", defaultAdvancedUringOwner.err)
		if advancedUringOwnerAttempts.Value() != 0 {
			t.Fatalf("advanced adoption attempted after capability failure: %d", advancedUringOwnerAttempts.Value())
		}
		if advancedUringOwnerFallbacks.String() == "{}" {
			t.Fatal("capability fallback was not recorded")
		}
	} else {
		t.Log("advanced io_uring initialized; advanced backend used")
		if advancedUringOwnerSuccess.Value() == 0 {
			t.Fatal("advanced backend initialized but did not adopt the auto session")
		}
	}
}

func TestOwnerHybridReactorRelaysThroughBothBackends(t *testing.T) {
	t.Setenv("XRAYR_SOCKET_OWNER_REACTOR", "hybrid")

	inboundListener := listenAdvancedUringOwnerTCP(t)
	defer inboundListener.Close()
	targetListener := listenAdvancedUringOwnerTCP(t)
	defer targetListener.Close()

	for _, testCase := range []struct {
		name     string
		sequence uint64
		counter  *expvar.Int
	}{
		{name: "gnet-spillover", sequence: 0, counter: hybridGnet},
		{name: "advanced", sequence: 1, counter: hybridAdvanced},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			hybridOwnerSequence.Store(testCase.sequence)
			before := testCase.counter.Value()

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

			session := newAdvancedUringOwnerRelaySession()
			if err := AdoptPair(inbound, outbound, session); err != nil {
				t.Fatal(err)
			}
			select {
			case <-session.opened:
			case <-time.After(3 * time.Second):
				t.Fatal("hybrid owner session did not open")
			}
			payload := bytes.Repeat([]byte(testCase.name+"-"), 256)
			received := make([]byte, len(payload))
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(client, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("hybrid owner payload mismatch")
			}
			if got := testCase.counter.Value(); got != before+1 {
				t.Fatalf("backend counter = %d, want %d", got, before+1)
			}
		})
	}
}
