//go:build linux

package shadowsocks

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"expvar"
	"io"
	stdnet "net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/owner"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	ownerSSLengthWire = 2 + 16
	ownerSSMaxPayload = buf.Size - ownerSSLengthWire - 16
)

var (
	ownerSSAttempts = expvar.NewInt("xray_ss_owner_attempts")
	ownerSSSuccess  = expvar.NewInt("xray_ss_owner_success")
	ownerSSFallback = expvar.NewInt("xray_ss_owner_fallback")
	ownerSSCloses   = expvar.NewMap("xray_ss_owner_closes")
)

func (s *Server) ownerEligible(conn stat.Connection, dispatcher routing.Dispatcher) (*stdnet.TCPConn, []stats.Counter, []stats.Counter, bool) {
	if !owner.Enabled() {
		return nil, nil, nil, false
	}
	if _, ok := dispatcher.(routing.DirectDispatcher); !ok {
		return nil, nil, nil, false
	}
	tcpConn, readCounters, writeCounters, ok := stat.UnwrapTCPConnection(conn)
	if !ok {
		return nil, nil, nil, false
	}

	s.validator.RLock()
	defer s.validator.RUnlock()
	if len(s.validator.users) == 0 {
		return nil, nil, nil, false
	}
	for _, user := range s.validator.users {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			return nil, nil, nil, false
		}
		aead, ok := account.Cipher.(*AEADCipher)
		if !ok || aead.KeySize() != 16 || aead.IVSize() != 16 {
			return nil, nil, nil, false
		}
	}
	return tcpConn, readCounters, writeCounters, true
}

type ownerTCPReader struct {
	conn        io.Reader
	auth        cipher.AEAD
	nonce       [12]byte
	pending     []byte
	lengthWire  []byte
	recordWire  []byte
	wantPayload int
}

// fillWire retains a partial AEAD frame across deadline errors. Direct
// dispatch sniffing intentionally uses a short read deadline; discarding the
// bytes returned with that timeout would shift the encrypted record boundary
// when the socket is handed to the owner reactor.
func (r *ownerTCPReader) fillWire(dst *[]byte, size int) ([]byte, error) {
	if size <= 0 || len(*dst) > size {
		return nil, io.ErrShortBuffer
	}
	if cap(*dst) < size {
		grown := make([]byte, len(*dst), size)
		copy(grown, *dst)
		*dst = grown
	}
	start := len(*dst)
	*dst = (*dst)[:size]
	n, err := io.ReadFull(r.conn, (*dst)[start:])
	if n < size-start {
		*dst = (*dst)[:start+n]
	}
	if err != nil {
		return nil, err
	}
	return *dst, nil
}

func (r *ownerTCPReader) readRecord() ([]byte, error) {
	if r.wantPayload == 0 {
		lengthWire, err := r.fillWire(&r.lengthWire, ownerSSLengthWire)
		if err != nil {
			return nil, err
		}
		length, err := r.auth.Open(lengthWire[:0], r.nonce[:], lengthWire, nil)
		r.lengthWire = r.lengthWire[:0]
		if err != nil || len(length) != 2 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		incrementOwnerNonce(r.nonce[:])
		payloadLength := int(binary.BigEndian.Uint16(length))
		if payloadLength == 0 {
			return nil, io.EOF
		}
		if payloadLength > ownerSSMaxPayload {
			return nil, io.ErrUnexpectedEOF
		}
		r.wantPayload = payloadLength + r.auth.Overhead()
	}
	payloadWire, err := r.fillWire(&r.recordWire, r.wantPayload)
	if err != nil {
		return nil, err
	}
	plaintext, err := r.auth.Open(payloadWire[:0], r.nonce[:], payloadWire, nil)
	// Open decrypts in place. A successful plaintext is handed to the caller,
	// so its backing array must not be reused by the next record while a
	// generic fallback (notably mux) may still be consuming it.
	r.recordWire = nil
	r.wantPayload = 0
	if err != nil {
		return nil, err
	}
	incrementOwnerNonce(r.nonce[:])
	return plaintext, nil
}

func (r *ownerTCPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.pending) > 0 {
		pending := r.pending
		r.pending = nil
		return buf.MultiBuffer{buf.FromBytes(pending)}, nil
	}
	plaintext, err := r.readRecord()
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buf.FromBytes(plaintext)}, nil
}

func (r *ownerTCPReader) TakeBuffered() buf.MultiBuffer {
	if len(r.pending) == 0 {
		return nil
	}
	pending := r.pending
	r.pending = nil
	return buf.MultiBuffer{buf.FromBytes(pending)}
}

func readOwnerTCPSession(validator *Validator, reader io.Reader) (*protocol.RequestHeader, *ownerTCPReader, error) {
	first := make([]byte, 50)
	if _, err := io.ReadFull(reader, first); err != nil {
		return nil, nil, err
	}
	user, aead, length, ivLength, err := validator.Get(first, protocol.RequestCommandTCP)
	if err != nil {
		return nil, nil, err
	}
	if aead == nil || ivLength != 16 || len(length) != 2 {
		return nil, nil, ErrNotFound
	}
	payloadLength := int(binary.BigEndian.Uint16(length))
	if payloadLength <= 0 || payloadLength > ownerSSMaxPayload {
		return nil, nil, io.ErrUnexpectedEOF
	}
	payloadWire := make([]byte, payloadLength+aead.Overhead())
	already := copy(payloadWire, first[int(ivLength)+ownerSSLengthWire:])
	if _, err := io.ReadFull(reader, payloadWire[already:]); err != nil {
		return nil, nil, err
	}
	ownerReader := &ownerTCPReader{conn: reader, auth: aead}
	incrementOwnerNonce(ownerReader.nonce[:])
	plaintext, err := aead.Open(payloadWire[:0], ownerReader.nonce[:], payloadWire, nil)
	if err != nil {
		return nil, nil, err
	}
	incrementOwnerNonce(ownerReader.nonce[:])

	addressBuffer := buf.FromBytes(plaintext)
	address, port, err := addrParser.ReadAddressPort(nil, addressBuffer)
	if err != nil {
		return nil, nil, err
	}
	if address == nil {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if addressBuffer.Len() > 0 {
		ownerReader.pending = append(ownerReader.pending, addressBuffer.Bytes()...)
	}
	return &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: address,
		Port:    port,
	}, ownerReader, nil
}

func incrementOwnerNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func takeOwnerBuffered(reader buf.Reader) ([]byte, bool) {
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

type ownerSSSession struct {
	account  *MemoryAccount
	decrypt  cipher.AEAD
	nonce    [12]byte
	flow     transport.DirectFlow
	timeouts policy.Timeout
	idle     owner.IdleTimer

	inbound  owner.Conn
	outbound owner.Conn

	inboundReadCounters   []stats.Counter
	inboundWriteCounters  []stats.Counter
	outboundReadCounters  []stats.Counter
	outboundWriteCounters []stats.Counter

	wantLength bool
	want       int
	lengthWire []byte
	recordWire []byte

	encrypt      cipher.AEAD
	encryptNonce [12]byte
	responseSalt [16]byte
	responseSize [2]byte
	responseWire []byte
	responseInit bool

	pendingUpload    []byte
	pendingDownload  []byte
	pendingWire      []byte
	pendingWirePlain int
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
	outboundReadDone bool
	uploadPaused     bool
	downloadPaused   bool
	failure          string
	closed           bool
}

func (s *ownerSSSession) fail(reason string) owner.Action {
	if s.failure == "" {
		s.failure = reason
	}
	return owner.Close
}

// consumeOwnerPending keeps a connection's bounded staging allocation after
// an asynchronous write completes. Only the unacknowledged bytes survive; a
// partial completion is compacted because the owner endpoint has already
// copied the remainder before TryWrite returns.
func consumeOwnerPending(pending []byte, written int) []byte {
	if written <= 0 {
		return pending
	}
	if written >= len(pending) {
		return pending[:0]
	}
	copy(pending, pending[written:])
	return pending[:len(pending)-written]
}

// advanceOwnerPendingWire advances within a response record owned by this
// session. Unlike callback-scoped upload plaintext, responseWire cannot be
// reused until the pending encrypted tail has been fully acknowledged.
func advanceOwnerPendingWire(pending []byte, written int) []byte {
	if written <= 0 {
		return pending
	}
	if written >= len(pending) {
		return nil
	}
	return pending[written:]
}

func newOwnerSSSession(reader *ownerTCPReader, request *protocol.RequestHeader, link *transport.DirectLink, flow transport.DirectFlow, timeouts policy.Timeout, pending []byte, inboundRead, inboundWrite []stats.Counter) *ownerSSSession {
	wantLength := reader.wantPayload == 0
	want := 0
	if !wantLength {
		want = reader.wantPayload - reader.auth.Overhead()
	}
	return &ownerSSSession{
		account:               request.User.Account.(*MemoryAccount),
		decrypt:               reader.auth,
		nonce:                 reader.nonce,
		flow:                  flow,
		timeouts:              timeouts,
		inboundReadCounters:   inboundRead,
		inboundWriteCounters:  inboundWrite,
		outboundReadCounters:  link.ReadCounters,
		outboundWriteCounters: link.WriteCounters,
		wantLength:            wantLength,
		want:                  want,
		lengthWire:            append([]byte(nil), reader.lengthWire...),
		recordWire:            append([]byte(nil), reader.recordWire...),
		pendingUpload:         pending,
		responseWire:          make([]byte, 0, 64*1024),
	}
}

func (s *ownerSSSession) expire() {
	if s.inbound != nil {
		_ = s.inbound.Close()
	}
	if s.outbound != nil {
		_ = s.outbound.Close()
	}
}

func (s *ownerSSSession) finishRead(role owner.Role) owner.Action {
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

func (s *ownerSSSession) OnOpen(role owner.Role, conn owner.Conn) {
	if role == owner.Inbound {
		s.inbound = conn
		s.idle.Start(s.timeouts.ConnectionIdle, s.expire)
		if !s.flushDownload() || s.processInbound(conn) == owner.Close {
			_ = conn.Close()
		}
		return
	}
	s.outbound = conn
	if len(s.pendingUpload) > 0 && !s.flushUpload() {
		_ = conn.Close()
	}
}

func addOwnerCounters(counters []stats.Counter, bytes int) {
	if bytes <= 0 {
		return
	}
	for _, counter := range counters {
		if counter != nil {
			counter.Add(int64(bytes))
		}
	}
}

func (s *ownerSSSession) reserve(bytes int, upload bool, wake owner.Conn) bool {
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

func (s *ownerSSSession) pauseUpload(writable bool) bool {
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

func (s *ownerSSSession) resumeUpload() bool {
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
		_ = s.inbound.Wake(nil)
	}
	return true
}

func (s *ownerSSSession) pauseDownload(writable bool) bool {
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

func (s *ownerSSSession) resumeDownload() bool {
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

func (s *ownerSSSession) flushUpload() bool {
	if s.uploadReceipt.Valid() {
		if s.outbound == nil || len(s.pendingUpload) != 0 {
			return false
		}
		writer, ok := s.outbound.(owner.OwnedWriteConn)
		if !ok {
			return false
		}
		written, done, err := writer.CompleteOwnedWrite(s.uploadReceipt)
		addOwnerCounters(s.outboundWriteCounters, written)
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
	addOwnerCounters(s.outboundWriteCounters, written)
	if written > 0 {
		s.flow.AddUplink(int64(written))
		s.pendingUpload = consumeOwnerPending(s.pendingUpload, written)
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

func (s *ownerSSSession) writeUpload(plaintext []byte) bool {
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
		addOwnerCounters(s.outboundWriteCounters, written)
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
	addOwnerCounters(s.outboundWriteCounters, written)
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

func (s *ownerSSSession) initResponse() bool {
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(s.responseSalt[:]); err != nil {
			return false
		}
		if s.account.CheckIV(s.responseSalt[:]) == nil {
			break
		}
		if attempt == 7 {
			return false
		}
	}
	aeadCipher, ok := s.account.Cipher.(*AEADCipher)
	if !ok {
		return false
	}
	subkey := make([]byte, aeadCipher.KeyBytes)
	hkdfSHA1(s.account.Key, s.responseSalt[:], subkey)
	s.encrypt = aeadCipher.AEADAuthCreator(subkey)
	s.responseInit = true
	return true
}

func (s *ownerSSSession) sealResponseRecord(plaintext []byte) []byte {
	if len(plaintext) == 0 || len(plaintext) > ownerSSMaxPayload {
		return nil
	}
	s.responseWire = s.responseWire[:0]
	if !s.responseInit {
		if !s.initResponse() {
			return nil
		}
		s.responseWire = append(s.responseWire, s.responseSalt[:]...)
	}
	binary.BigEndian.PutUint16(s.responseSize[:], uint16(len(plaintext)))
	s.responseWire = s.encrypt.Seal(s.responseWire, s.encryptNonce[:], s.responseSize[:], nil)
	incrementOwnerNonce(s.encryptNonce[:])
	s.responseWire = s.encrypt.Seal(s.responseWire, s.encryptNonce[:], plaintext, nil)
	incrementOwnerNonce(s.encryptNonce[:])
	return s.responseWire
}

func (s *ownerSSSession) flushDownload() bool {
	if s.inbound == nil {
		return len(s.pendingWire) == 0
	}
	if len(s.pendingWire) > 0 {
		written, err := s.inbound.TryWrite(s.pendingWire)
		addOwnerCounters(s.inboundWriteCounters, written)
		if written > 0 {
			s.pendingWire = advanceOwnerPendingWire(s.pendingWire, written)
		}
		if err != nil {
			return false
		}
		if len(s.pendingWire) > 0 {
			return s.pauseDownload(true)
		}
		s.flow.AddDownlink(int64(s.pendingWirePlain))
		s.pendingWirePlain = 0
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

func (s *ownerSSSession) writeReservedDownload(plaintext []byte) bool {
	for len(plaintext) > 0 {
		size := len(plaintext)
		if size > ownerSSMaxPayload {
			size = ownerSSMaxPayload
		}
		wire := s.sealResponseRecord(plaintext[:size])
		if wire == nil {
			return false
		}
		written, err := s.inbound.TryWrite(wire)
		addOwnerCounters(s.inboundWriteCounters, written)
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

func (s *ownerSSSession) writeDownload(plaintext []byte) bool {
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

func (s *ownerSSSession) processInbound(conn owner.Conn) owner.Action {
	if s.inboundReadDone {
		_, _ = conn.Discard(-1)
		return owner.None
	}
	if !s.flushUpload() {
		return s.fail("flush-upload")
	}
	if s.uploadWaiting.Load() || s.uploadPaused {
		return owner.None
	}
	for {
		if s.wantLength {
			need := ownerSSLengthWire - len(s.lengthWire)
			var wire []byte
			if need > 0 {
				if conn.InboundBuffered() < need {
					return owner.None
				}
				var err error
				wire, err = conn.Next(need)
				if err != nil {
					return s.fail("read-length")
				}
				addOwnerCounters(s.inboundReadCounters, len(wire))
			}
			if len(s.lengthWire) > 0 {
				s.lengthWire = append(s.lengthWire, wire...)
				wire = s.lengthWire
			}
			length, err := s.decrypt.Open(wire[:0], s.nonce[:], wire, nil)
			s.lengthWire = s.lengthWire[:0]
			if err != nil || len(length) != 2 {
				return s.fail("decrypt-length")
			}
			incrementOwnerNonce(s.nonce[:])
			s.want = int(binary.BigEndian.Uint16(length))
			if s.want <= 0 || s.want > ownerSSMaxPayload {
				return s.fail("invalid-length")
			}
			s.wantLength = false
		}
		wireSize := s.want + s.decrypt.Overhead()
		need := wireSize - len(s.recordWire)
		var wire []byte
		if need > 0 {
			if conn.InboundBuffered() < need {
				return owner.None
			}
			var err error
			wire, err = conn.Next(need)
			if err != nil {
				return s.fail("read-payload")
			}
			addOwnerCounters(s.inboundReadCounters, len(wire))
		}
		if len(s.recordWire) > 0 {
			s.recordWire = append(s.recordWire, wire...)
			wire = s.recordWire
		}
		plaintext, err := s.decrypt.Open(wire[:0], s.nonce[:], wire, nil)
		s.recordWire = s.recordWire[:0]
		if err != nil {
			return s.fail("decrypt-payload")
		}
		incrementOwnerNonce(s.nonce[:])
		s.want = 0
		s.wantLength = true
		if !s.writeUpload(plaintext) {
			return s.fail("write-upload")
		}
		if s.uploadWaiting.Load() || s.uploadPaused {
			return owner.None
		}
	}
}

func (s *ownerSSSession) processOutbound(conn owner.Conn) owner.Action {
	if !s.flushDownload() {
		return s.fail("flush-download")
	}
	if s.downloadWaiting.Load() || s.downloadPaused {
		return owner.None
	}
	buffered := conn.InboundBuffered()
	if buffered == 0 {
		return owner.None
	}
	plaintext, err := conn.Next(buffered)
	if err != nil {
		return s.fail("read-outbound")
	}
	addOwnerCounters(s.outboundReadCounters, len(plaintext))
	if !s.writeDownload(plaintext) {
		return s.fail("write-download")
	}
	return owner.None
}

func (s *ownerSSSession) OnTraffic(role owner.Role, conn owner.Conn) owner.Action {
	s.idle.Update()
	if !s.flushUpload() || !s.flushDownload() {
		return s.fail("flush-traffic")
	}
	if role == owner.Inbound {
		return s.processInbound(conn)
	}
	return s.processOutbound(conn)
}

func (s *ownerSSSession) OnWritable(role owner.Role, _ owner.Conn) owner.Action {
	if role == owner.Outbound {
		if !s.flushUpload() {
			return s.fail("flush-upload-writable")
		}
		return owner.None
	}
	if !s.flushDownload() {
		return s.fail("flush-download-writable")
	}
	return owner.None
}

func (s *ownerSSSession) OnReadClosed(role owner.Role, _ owner.Conn) owner.Action {
	s.idle.Update()
	if role == owner.Inbound && (!s.wantLength || s.want != 0 || len(s.lengthWire) > 0 || len(s.recordWire) > 0) {
		return s.fail("truncated-record")
	}
	return s.finishRead(role)
}

func (s *ownerSSSession) OnClose(role owner.Role, _ owner.Conn, err error) {
	if s.closed {
		return
	}
	s.closed = true
	s.idle.Stop()
	closeReason := s.failure
	if closeReason == "" {
		if errors.Is(err, io.EOF) {
			closeReason = "peer-eof"
		} else if err != nil {
			closeReason = "socket-error"
		} else {
			closeReason = "peer-close"
		}
	}
	if role == owner.Inbound {
		closeReason = "inbound-" + closeReason
	} else {
		closeReason = "outbound-" + closeReason
	}
	ownerSSCloses.Add(closeReason, 1)
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
	s.pendingUpload = nil
	s.pendingDownload = nil
	s.pendingWire = nil
	s.uploadReceipt = owner.WriteReceipt{}
	s.lengthWire = nil
	s.recordWire = nil
	s.responseWire = nil
	if s.flow != nil {
		s.flow.Release()
		s.flow = nil
	}
}
