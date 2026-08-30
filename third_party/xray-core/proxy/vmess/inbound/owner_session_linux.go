//go:build linux

package inbound

import (
	"expvar"
	"io"
	stdnet "net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/owner"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var (
	ownerVMessAttempts = expvar.NewInt("xray_vmess_owner_attempts")
	ownerVMessSuccess  = expvar.NewInt("xray_vmess_owner_success")
	ownerVMessFallback = expvar.NewInt("xray_vmess_owner_fallback")
)

func vmessOwnerConnection(conn stat.Connection, dispatcher routing.Dispatcher) (*stdnet.TCPConn, []stats.Counter, []stats.Counter, bool) {
	if !owner.Enabled() {
		return nil, nil, nil, false
	}
	if _, ok := dispatcher.(routing.DirectDispatcher); !ok {
		return nil, nil, nil, false
	}
	return stat.UnwrapTCPConnection(conn)
}

func takeVMessOwnerPlaintext(reader buf.Reader, codec *encoding.OwnerBodyCodec) ([]byte, bool) {
	if reader == codec {
		return nil, true
	}
	buffered, ok := reader.(interface{ TakeBuffered() buf.MultiBuffer })
	if !ok {
		return nil, false
	}
	mb := buffered.TakeBuffered()
	if mb.IsEmpty() {
		return nil, true
	}
	pending := make([]byte, 0, mb.Len())
	for _, part := range mb {
		pending = append(pending, part.Bytes()...)
	}
	buf.ReleaseMulti(mb)
	return pending, true
}

type ownerVMessSession struct {
	codec    *encoding.OwnerBodyCodec
	flow     transport.DirectFlow
	timeouts policy.Timeout
	idle     owner.IdleTimer

	inbound  owner.Conn
	outbound owner.Conn

	inboundReadCounters   []stats.Counter
	inboundWriteCounters  []stats.Counter
	outboundReadCounters  []stats.Counter
	outboundWriteCounters []stats.Counter

	sizePrefix  []byte
	wantWire    int
	wantPadding int
	recordWire  []byte
	cachedWire  []byte

	pendingUpload    []byte
	pendingDownload  []byte
	pendingWire      []byte
	responseWire     []byte
	pendingWirePlain int
	pendingWireEnd   bool
	uploadReceipt    owner.WriteReceipt

	uploadReserved   bool
	downloadReserved bool
	uploadCredit     owner.Reservation
	downloadCredit   owner.Reservation
	uploadWaiting    atomic.Bool
	downloadWaiting  atomic.Bool
	uploadTimer      *time.Timer
	downloadTimer    *time.Timer
	inboundReadDone  bool
	outboundEOF      bool
	outboundReadDone bool
	responseEnded    bool
	uploadPaused     bool
	downloadPaused   bool
	closed           bool
}

func newOwnerVMessSession(codec *encoding.OwnerBodyCodec, link *transport.DirectLink, flow transport.DirectFlow, timeouts policy.Timeout, pendingPlaintext, cachedWire []byte, inboundRead, inboundWrite []stats.Counter) *ownerVMessSession {
	return &ownerVMessSession{
		codec:                 codec,
		flow:                  flow,
		timeouts:              timeouts,
		inboundReadCounters:   inboundRead,
		inboundWriteCounters:  inboundWrite,
		outboundReadCounters:  link.ReadCounters,
		outboundWriteCounters: link.WriteCounters,
		sizePrefix:            make([]byte, 0, codec.RequestSizeBytes()),
		cachedWire:            cachedWire,
		pendingUpload:         pendingPlaintext,
	}
}

func (s *ownerVMessSession) expire() {
	if s.inbound != nil {
		_ = s.inbound.Close()
	}
	if s.outbound != nil {
		_ = s.outbound.Close()
	}
}

func (s *ownerVMessSession) finishRead(role owner.Role) owner.Action {
	if role == owner.Inbound {
		if s.inboundReadDone {
			return owner.None
		}
		s.inboundReadDone = true
		s.idle.SetTimeout(s.timeouts.DownlinkOnly)
	} else {
		if s.outboundReadDone {
			return owner.None
		}
		s.outboundReadDone = true
		s.idle.SetTimeout(s.timeouts.UplinkOnly)
	}
	if s.inboundReadDone && s.outboundReadDone {
		return owner.Close
	}
	return owner.None
}

func addVMessOwnerCounters(counters []stats.Counter, bytes int) {
	if bytes <= 0 {
		return
	}
	for _, counter := range counters {
		if counter != nil {
			counter.Add(int64(bytes))
		}
	}
}

// consumeVMessOwnerPending keeps the original backing array after an
// asynchronous write completes. The owner endpoint already retains its own
// copy until the kernel reports completion, so the session copy only needs to
// preserve unacknowledged bytes; retaining its capacity avoids allocating one
// 4 KiB buffer for every record.
func consumeVMessOwnerPending(pending []byte, written int) []byte {
	if written <= 0 {
		return pending
	}
	if written >= len(pending) {
		return pending[:0]
	}
	copy(pending, pending[written:])
	return pending[:len(pending)-written]
}

// advanceVMessOwnerPendingWire advances within connection-owned encrypted
// response storage. The codec cannot reuse that storage while pendingWire is
// non-empty because the session pauses response production until it drains.
func advanceVMessOwnerPendingWire(pending []byte, written int) []byte {
	if written <= 0 {
		return pending
	}
	if written >= len(pending) {
		return nil
	}
	return pending[written:]
}

func (s *ownerVMessSession) reserve(bytes int, upload bool, wake owner.Conn) bool {
	if bytes <= 0 {
		return true
	}
	credit := &s.downloadCredit
	if upload {
		credit = &s.uploadCredit
	}
	delay, ok := credit.Acquire(s.flow, bytes)
	if !ok {
		return false
	}
	if delay <= 0 {
		return true
	}
	if upload {
		s.uploadReserved = true
		s.uploadWaiting.Store(true)
		s.uploadTimer = time.AfterFunc(delay, func() {
			s.uploadWaiting.Store(false)
			_ = wake.Wake(nil)
		})
	} else {
		s.downloadReserved = true
		s.downloadWaiting.Store(true)
		s.downloadTimer = time.AfterFunc(delay, func() {
			s.downloadWaiting.Store(false)
			_ = wake.Wake(nil)
		})
	}
	return true
}

func (s *ownerVMessSession) pauseUpload(writable bool) bool {
	if writable && s.outbound != nil {
		if err := s.outbound.ArmWrite(); err != nil {
			return false
		}
	}
	if !s.uploadPaused && s.inbound != nil {
		if err := s.inbound.SuspendRead(); err != nil {
			if writable && s.outbound != nil {
				_ = s.outbound.DisarmWrite()
			}
			return false
		}
		s.uploadPaused = true
	}
	return true
}

func (s *ownerVMessSession) resumeUpload() bool {
	if s.outbound != nil {
		if err := s.outbound.DisarmWrite(); err != nil {
			return false
		}
	}
	if s.uploadPaused && s.inbound != nil {
		if err := s.inbound.ResumeRead(); err != nil {
			return false
		}
		s.uploadPaused = false
		if len(s.cachedWire) > 0 {
			_ = owner.WakeProtocolPending(s.inbound)
		} else {
			_ = s.inbound.Wake(nil)
		}
	}
	return true
}

func (s *ownerVMessSession) pauseDownload(writable bool) bool {
	if writable && s.inbound != nil {
		if err := s.inbound.ArmWrite(); err != nil {
			return false
		}
	}
	if !s.downloadPaused && s.outbound != nil {
		if err := s.outbound.SuspendRead(); err != nil {
			if writable && s.inbound != nil {
				_ = s.inbound.DisarmWrite()
			}
			return false
		}
		s.downloadPaused = true
	}
	return true
}

func (s *ownerVMessSession) resumeDownload() bool {
	if s.inbound != nil {
		if err := s.inbound.DisarmWrite(); err != nil {
			return false
		}
	}
	if s.downloadPaused && s.outbound != nil {
		if err := s.outbound.ResumeRead(); err != nil {
			return false
		}
		s.downloadPaused = false
		_ = s.outbound.Wake(nil)
	}
	return true
}

func (s *ownerVMessSession) flushUpload() bool {
	if s.uploadReceipt.Valid() {
		if s.outbound == nil || len(s.pendingUpload) != 0 {
			return false
		}
		writer, ok := s.outbound.(owner.OwnedWriteConn)
		if !ok {
			return false
		}
		written, done, err := writer.CompleteOwnedWrite(s.uploadReceipt)
		addVMessOwnerCounters(s.outboundWriteCounters, written)
		if written > 0 {
			s.flow.AddUplink(int64(written))
		}
		if err != nil {
			return false
		}
		if !done {
			return s.pauseUpload(true)
		}
		s.uploadReceipt = owner.WriteReceipt{}
		s.uploadReserved = false
		return s.resumeUpload()
	}
	if len(s.pendingUpload) == 0 {
		s.uploadReserved = false
		return s.resumeUpload()
	}
	if s.outbound == nil {
		return true
	}
	if s.uploadWaiting.Load() {
		return s.pauseUpload(false)
	}
	if !s.uploadReserved {
		wake := s.inbound
		if wake == nil {
			wake = s.outbound
		}
		if !s.reserve(len(s.pendingUpload), true, wake) {
			return false
		}
		if s.uploadWaiting.Load() {
			return s.pauseUpload(false)
		}
		s.uploadReserved = true
	}
	written, err := s.outbound.TryWrite(s.pendingUpload)
	addVMessOwnerCounters(s.outboundWriteCounters, written)
	if written > 0 {
		s.flow.AddUplink(int64(written))
		s.pendingUpload = consumeVMessOwnerPending(s.pendingUpload, written)
	}
	if err != nil {
		return false
	}
	if len(s.pendingUpload) > 0 {
		return s.pauseUpload(true)
	}
	s.uploadReserved = false
	return s.resumeUpload()
}

func (s *ownerVMessSession) writeUpload(plaintext []byte) bool {
	if len(plaintext) == 0 {
		return true
	}
	if s.outbound == nil || len(s.pendingUpload) > 0 || s.uploadWaiting.Load() {
		s.pendingUpload = append(s.pendingUpload, plaintext...)
		return s.flushUpload()
	}
	if !s.reserve(len(plaintext), true, s.inbound) {
		return false
	}
	if s.uploadWaiting.Load() {
		s.pendingUpload = append(s.pendingUpload, plaintext...)
		return s.pauseUpload(false)
	}
	if writer, ok := s.outbound.(owner.OwnedWriteConn); ok {
		written, receipt, err := writer.BeginOwnedWrite(plaintext)
		addVMessOwnerCounters(s.outboundWriteCounters, written)
		if written > 0 {
			s.flow.AddUplink(int64(written))
		}
		if err != nil {
			return false
		}
		if receipt.Valid() {
			s.uploadReceipt = receipt
			s.uploadReserved = true
			return s.pauseUpload(true)
		}
		return written == len(plaintext)
	}
	written, err := s.outbound.TryWrite(plaintext)
	addVMessOwnerCounters(s.outboundWriteCounters, written)
	if written > 0 {
		s.flow.AddUplink(int64(written))
	}
	if err != nil {
		return false
	}
	if written < len(plaintext) {
		s.pendingUpload = append(s.pendingUpload, plaintext[written:]...)
		s.uploadReserved = true
		return s.pauseUpload(true)
	}
	return true
}

func (s *ownerVMessSession) flushDownload() bool {
	if s.inbound == nil {
		return len(s.pendingWire) == 0
	}
	if len(s.pendingWire) > 0 {
		written, err := s.inbound.TryWrite(s.pendingWire)
		addVMessOwnerCounters(s.inboundWriteCounters, written)
		if written > 0 {
			s.pendingWire = advanceVMessOwnerPendingWire(s.pendingWire, written)
		}
		if err != nil {
			return false
		}
		if len(s.pendingWire) > 0 {
			return s.pauseDownload(true)
		}
		if s.pendingWirePlain > 0 {
			s.flow.AddDownlink(int64(s.pendingWirePlain))
			s.pendingWirePlain = 0
		}
		if s.pendingWireEnd {
			s.pendingWireEnd = false
			s.responseEnded = true
		}
	}
	if s.downloadWaiting.Load() {
		return s.pauseDownload(false)
	}
	if len(s.pendingDownload) == 0 {
		s.downloadReserved = false
		return s.resumeDownload()
	}
	if !s.downloadReserved {
		wake := s.outbound
		if wake == nil {
			wake = s.inbound
		}
		if !s.reserve(len(s.pendingDownload), false, wake) {
			return false
		}
		if s.downloadWaiting.Load() {
			return s.pauseDownload(false)
		}
		s.downloadReserved = true
	}
	plaintext := s.pendingDownload
	s.pendingDownload = nil
	return s.writeReservedDownload(plaintext)
}

func (s *ownerVMessSession) writeReservedDownload(plaintext []byte) bool {
	maxPayload := s.codec.ResponsePayloadLimit()
	if maxPayload <= 0 {
		return false
	}
	for len(plaintext) > 0 {
		size := len(plaintext)
		if size > maxPayload {
			size = maxPayload
		}
		wire, err := s.codec.SealResponseRecord(s.responseWire[:0], plaintext[:size])
		if err != nil {
			return false
		}
		s.responseWire = wire[:0]
		written, err := s.inbound.TryWrite(wire)
		addVMessOwnerCounters(s.inboundWriteCounters, written)
		if err != nil {
			return false
		}
		plaintext = plaintext[size:]
		if written < len(wire) {
			s.pendingWire = wire[written:]
			s.pendingWirePlain = size
			s.pendingDownload = append(s.pendingDownload, plaintext...)
			return s.pauseDownload(true)
		}
		s.flow.AddDownlink(int64(size))
	}
	s.downloadReserved = false
	return s.resumeDownload()
}

func (s *ownerVMessSession) writeDownload(plaintext []byte) bool {
	if len(plaintext) == 0 {
		return true
	}
	if s.inbound == nil || len(s.pendingDownload) > 0 || len(s.pendingWire) > 0 || s.downloadWaiting.Load() {
		s.pendingDownload = append(s.pendingDownload, plaintext...)
		return s.flushDownload()
	}
	if !s.reserve(len(plaintext), false, s.outbound) {
		return false
	}
	if s.downloadWaiting.Load() {
		s.pendingDownload = append(s.pendingDownload, plaintext...)
		return s.pauseDownload(false)
	}
	s.downloadReserved = true
	return s.writeReservedDownload(plaintext)
}

func (s *ownerVMessSession) queueRecord(wire []byte) error {
	plaintext, err := s.codec.OpenRequest(wire, s.wantPadding)
	s.wantWire = 0
	s.wantPadding = 0
	if err != nil {
		return err
	}
	if !s.writeUpload(plaintext) {
		return io.ErrClosedPipe
	}
	return nil
}

func (s *ownerVMessSession) consumeEncrypted(input []byte) (bool, error) {
	for len(input) > 0 {
		if s.wantWire == 0 {
			need := s.codec.RequestSizeBytes() - len(s.sizePrefix)
			if need > len(input) {
				need = len(input)
			}
			s.sizePrefix = append(s.sizePrefix, input[:need]...)
			input = input[need:]
			if len(s.sizePrefix) < s.codec.RequestSizeBytes() {
				return false, nil
			}
			wireSize, padding, done, err := s.codec.DecodeRequestSize(s.sizePrefix)
			s.sizePrefix = s.sizePrefix[:0]
			if err != nil {
				return false, err
			}
			if done {
				return true, nil
			}
			s.wantWire = wireSize
			s.wantPadding = padding
		}

		if len(s.recordWire) > 0 || len(input) < s.wantWire {
			need := s.wantWire - len(s.recordWire)
			if need > len(input) {
				need = len(input)
			}
			s.recordWire = append(s.recordWire, input[:need]...)
			input = input[need:]
			if len(s.recordWire) < s.wantWire {
				return false, nil
			}
			if err := s.queueRecord(s.recordWire); err != nil {
				return false, err
			}
			s.recordWire = s.recordWire[:0]
		} else {
			wire := input[:s.wantWire]
			input = input[s.wantWire:]
			if err := s.queueRecord(wire); err != nil {
				return false, err
			}
		}
		if s.uploadWaiting.Load() || s.uploadPaused {
			if len(input) > 0 {
				s.cachedWire = append(s.cachedWire, input...)
			}
			return false, nil
		}
	}
	return false, nil
}

func (s *ownerVMessSession) processInbound(conn owner.Conn) owner.Action {
	if s.inboundReadDone {
		_, _ = conn.Discard(-1)
		return owner.None
	}
	if !s.flushUpload() {
		return owner.Close
	}
	if s.uploadWaiting.Load() || s.uploadPaused {
		return owner.None
	}
	if len(s.cachedWire) > 0 {
		cached := s.cachedWire
		s.cachedWire = nil
		done, err := s.consumeEncrypted(cached)
		if err != nil {
			return owner.Close
		}
		if done {
			return s.finishRead(owner.Inbound)
		}
		if s.uploadWaiting.Load() || s.uploadPaused {
			return owner.None
		}
	}
	buffered := conn.InboundBuffered()
	if buffered == 0 {
		return owner.None
	}
	wire, err := conn.Next(buffered)
	if err != nil {
		return owner.Close
	}
	addVMessOwnerCounters(s.inboundReadCounters, len(wire))
	done, err := s.consumeEncrypted(wire)
	if err != nil {
		return owner.Close
	}
	if done {
		return s.finishRead(owner.Inbound)
	}
	return owner.None
}

func (s *ownerVMessSession) finishResponse() owner.Action {
	if s.responseEnded {
		if !s.outboundReadDone {
			return s.finishRead(owner.Outbound)
		}
		return owner.None
	}
	if !s.outboundEOF || len(s.pendingDownload) > 0 || len(s.pendingWire) > 0 || s.downloadWaiting.Load() {
		return owner.None
	}
	wire, err := s.codec.SealResponseEnd(s.responseWire[:0])
	if err != nil {
		return owner.Close
	}
	s.responseWire = wire[:0]
	if len(wire) > 0 {
		written, err := s.inbound.TryWrite(wire)
		addVMessOwnerCounters(s.inboundWriteCounters, written)
		if err != nil {
			return owner.Close
		}
		if written < len(wire) {
			s.pendingWire = wire[written:]
			s.pendingWireEnd = true
			if !s.pauseDownload(true) {
				return owner.Close
			}
			return owner.None
		}
	}
	s.responseEnded = true
	return s.finishRead(owner.Outbound)
}

func (s *ownerVMessSession) processOutbound(conn owner.Conn) owner.Action {
	if !s.flushDownload() {
		return owner.Close
	}
	if s.downloadWaiting.Load() || s.downloadPaused {
		return owner.None
	}
	if s.outboundEOF {
		return s.finishResponse()
	}
	buffered := conn.InboundBuffered()
	if buffered == 0 {
		return owner.None
	}
	plaintext, err := conn.Next(buffered)
	if err != nil {
		return owner.Close
	}
	addVMessOwnerCounters(s.outboundReadCounters, len(plaintext))
	if !s.writeDownload(plaintext) {
		return owner.Close
	}
	return owner.None
}

func (s *ownerVMessSession) OnOpen(role owner.Role, conn owner.Conn) {
	if role == owner.Outbound {
		s.outbound = conn
		if len(s.pendingUpload) > 0 && !s.flushUpload() {
			_ = conn.Close()
		}
		return
	}
	s.inbound = conn
	s.idle.Start(s.timeouts.ConnectionIdle, s.expire)
	if !s.flushDownload() || s.processInbound(conn) == owner.Close {
		_ = conn.Close()
	}
}

func (s *ownerVMessSession) OnTraffic(role owner.Role, conn owner.Conn) owner.Action {
	s.idle.Update()
	if !s.flushUpload() || !s.flushDownload() {
		return owner.Close
	}
	if s.outboundEOF && !s.responseEnded {
		if action := s.finishResponse(); action == owner.Close {
			return action
		}
	}
	if role == owner.Inbound {
		return s.processInbound(conn)
	}
	return s.processOutbound(conn)
}

func (s *ownerVMessSession) OnWritable(role owner.Role, _ owner.Conn) owner.Action {
	if role == owner.Outbound {
		if !s.flushUpload() {
			return owner.Close
		}
		return owner.None
	}
	if !s.flushDownload() {
		return owner.Close
	}
	if s.outboundEOF {
		return s.finishResponse()
	}
	return owner.None
}

func (s *ownerVMessSession) OnReadClosed(role owner.Role, conn owner.Conn) owner.Action {
	s.idle.Update()
	if role == owner.Inbound {
		if len(s.sizePrefix) > 0 || s.wantWire > 0 || len(s.recordWire) > 0 || len(s.cachedWire) > 0 {
			return owner.Close
		}
		return s.finishRead(role)
	}
	s.outboundEOF = true
	if action := s.processOutbound(conn); action == owner.Close {
		return action
	}
	return s.finishResponse()
}

func (s *ownerVMessSession) OnClose(role owner.Role, _ owner.Conn, _ error) {
	if s.closed {
		return
	}
	s.closed = true
	s.idle.Stop()
	if s.uploadTimer != nil {
		s.uploadTimer.Stop()
	}
	if s.downloadTimer != nil {
		s.downloadTimer.Stop()
	}
	if role == owner.Inbound {
		if s.outbound != nil {
			_ = s.outbound.Close()
		}
	} else if s.inbound != nil {
		_ = s.inbound.Close()
	}
	s.sizePrefix = nil
	s.recordWire = nil
	s.cachedWire = nil
	s.pendingUpload = nil
	s.pendingDownload = nil
	s.pendingWire = nil
	s.uploadReceipt = owner.WriteReceipt{}
	s.responseWire = nil
	if s.flow != nil {
		s.flow.Release()
		s.flow = nil
	}
}
