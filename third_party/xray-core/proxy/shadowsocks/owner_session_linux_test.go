//go:build linux

package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/owner"
)

var errOwnerTestDeadline = errors.New("test deadline")

var ownerPendingWireBenchmarkSink []byte

type partialTimeoutReader struct {
	data   []byte
	offset int
	failAt int
	failed bool
}

func (r *partialTimeoutReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	limit := len(p)
	if remaining := len(r.data) - r.offset; limit > remaining {
		limit = remaining
	}
	if !r.failed && r.offset < r.failAt && r.offset+limit >= r.failAt {
		limit = r.failAt - r.offset
		n := copy(p, r.data[r.offset:r.offset+limit])
		r.offset += n
		r.failed = true
		return n, errOwnerTestDeadline
	}
	n := copy(p, r.data[r.offset:r.offset+limit])
	r.offset += n
	return n, nil
}

type ownerTestFlow struct {
	uplink   int64
	downlink int64
	released int
}

func (*ownerTestFlow) OwnerEligible() bool               { return true }
func (*ownerTestFlow) Acquire(int) (time.Duration, bool) { return 0, true }
func (f *ownerTestFlow) AddUplink(bytes int64)           { f.uplink += bytes }
func (f *ownerTestFlow) AddDownlink(bytes int64)         { f.downlink += bytes }
func (f *ownerTestFlow) Release()                        { f.released++ }

var _ transport.DirectFlow = (*ownerTestFlow)(nil)

func TestOwnerSSSessionReleasesFlowExactlyOnce(t *testing.T) {
	flow := new(ownerTestFlow)
	session := &ownerSSSession{flow: flow}
	session.OnClose(owner.Inbound, nil, nil)
	session.OnClose(owner.Outbound, nil, nil)
	if flow.released != 1 {
		t.Fatalf("flow releases = %d, want 1", flow.released)
	}
}

func TestNewOwnerSSSessionLazilyAllocatesResponseWire(t *testing.T) {
	account, err := (&Account{
		Password:   "owner-lazy-response-password",
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		User: &protocol.MemoryUser{Account: account},
	}
	session := newOwnerSSSession(
		new(ownerTCPReader),
		request,
		new(transport.DirectLink),
		nil,
		policy.Timeout{},
		nil,
		nil,
		nil,
	)
	if cap(session.responseWire) != 0 {
		t.Fatalf("response wire capacity = %d, want 0 before first response", cap(session.responseWire))
	}
}

func ownerTestEncryptedRecord(t *testing.T, plaintext []byte) (cipher.AEAD, []byte) {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(plaintext)))
	wire := aead.Seal(nil, nonce[:], length[:], nil)
	incrementOwnerNonce(nonce[:])
	wire = aead.Seal(wire, nonce[:], plaintext, nil)
	return aead, wire
}

type ownerTestConn struct {
	mu              sync.Mutex
	input           []byte
	output          bytes.Buffer
	closed          int
	tryLimit        int
	deferLogicalAck bool
	logicalAck      int
	paused          bool
	armed           bool
}

func (c *ownerTestConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.Write(p)
}

func (c *ownerTestConn) TryWrite(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logicalAck > 0 {
		acknowledged := c.logicalAck
		c.logicalAck = 0
		return acknowledged, nil
	}
	if c.deferLogicalAck {
		c.deferLogicalAck = false
		written, err := c.output.Write(p)
		c.logicalAck = written
		return 0, err
	}
	limit := len(p)
	if c.tryLimit < 0 {
		limit = 0
	} else if c.tryLimit > 0 && limit > c.tryLimit {
		limit = c.tryLimit
	}
	return c.output.Write(p[:limit])
}

func (c *ownerTestConn) SuspendRead() error {
	c.mu.Lock()
	c.paused = true
	c.mu.Unlock()
	return nil
}

func (c *ownerTestConn) ResumeRead() error {
	c.mu.Lock()
	c.paused = false
	c.mu.Unlock()
	return nil
}

func (c *ownerTestConn) ArmWrite() error {
	c.mu.Lock()
	c.armed = true
	c.mu.Unlock()
	return nil
}

func (c *ownerTestConn) DisarmWrite() error {
	c.mu.Lock()
	c.armed = false
	c.mu.Unlock()
	return nil
}

func (c *ownerTestConn) Next(n int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 {
		n = len(c.input)
	}
	if n > len(c.input) {
		return nil, io.ErrShortBuffer
	}
	result := append([]byte(nil), c.input[:n]...)
	c.input = c.input[n:]
	return result, nil
}

func (c *ownerTestConn) Discard(n int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || n >= len(c.input) {
		n = len(c.input)
	}
	c.input = c.input[n:]
	return n, nil
}

func (c *ownerTestConn) InboundBuffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.input)
}

func (*ownerTestConn) Wake(gnet.AsyncCallback) error { return nil }

func (c *ownerTestConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *ownerTestConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestOwnerSSSessionPreservesOppositeDirectionAfterReadClose(t *testing.T) {
	timeouts := policy.Timeout{
		ConnectionIdle: time.Minute,
		UplinkOnly:     time.Minute,
		DownlinkOnly:   time.Minute,
	}
	session := &ownerSSSession{timeouts: timeouts, wantLength: true}
	inbound, outbound := new(ownerTestConn), new(ownerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	if action := session.OnReadClosed(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("inbound half-close action = %v, want None", action)
	}
	if inbound.closeCount() != 0 || outbound.closeCount() != 0 {
		t.Fatal("one read-half-close closed the relay")
	}
	if action := session.OnReadClosed(owner.Outbound, outbound); action != owner.Close {
		t.Fatalf("both read halves closed action = %v, want Close", action)
	}
}

func TestConsumeOwnerPendingRetainsCapacity(t *testing.T) {
	pending := append(make([]byte, 0, 16), []byte("abcdefgh")...)
	base := &pending[:cap(pending)][0]
	pending = consumeOwnerPending(pending, 3)
	if got, want := string(pending), "defgh"; got != want {
		t.Fatalf("pending = %q, want %q", got, want)
	}
	if &pending[:cap(pending)][0] != base {
		t.Fatal("partial completion replaced the pending backing array")
	}
	pending = consumeOwnerPending(pending, len(pending))
	if len(pending) != 0 || cap(pending) != 16 {
		t.Fatalf("drained pending len/cap = %d/%d, want 0/16", len(pending), cap(pending))
	}
}

func TestAdvanceOwnerPendingWireRetainsTailAlias(t *testing.T) {
	wire := append(make([]byte, 0, 16), []byte("abcdefgh")...)
	pending := advanceOwnerPendingWire(wire[2:], 3)
	if got, want := string(pending), "fgh"; got != want {
		t.Fatalf("pending = %q, want %q", got, want)
	}
	if &pending[0] != &wire[5] {
		t.Fatal("pending wire no longer aliases the session-owned tail")
	}
	if pending = advanceOwnerPendingWire(pending, len(pending)); pending != nil {
		t.Fatalf("drained pending = %#v, want nil", pending)
	}
}

func BenchmarkOwnerPendingWireStage(b *testing.B) {
	wire := bytes.Repeat([]byte{0xa5}, 4096)
	b.Run("copy", func(b *testing.B) {
		pending := make([]byte, 0, len(wire))
		b.SetBytes(int64(len(wire)))
		b.ReportAllocs()
		for range b.N {
			pending = append(pending[:0], wire...)
			ownerPendingWireBenchmarkSink = pending
		}
	})
	b.Run("alias", func(b *testing.B) {
		b.SetBytes(int64(len(wire)))
		b.ReportAllocs()
		for range b.N {
			ownerPendingWireBenchmarkSink = wire
		}
	})
}

func TestOwnerSSSessionRejectsTruncatedRecordOnReadClose(t *testing.T) {
	session := &ownerSSSession{
		timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
		wantLength: true,
	}
	inbound, outbound := new(ownerTestConn), new(ownerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()
	session.wantLength = false
	session.want = 32

	if action := session.OnReadClosed(owner.Inbound, inbound); action != owner.Close {
		t.Fatalf("truncated record action = %v, want Close", action)
	}
	if session.failure != "truncated-record" {
		t.Fatalf("failure = %q, want truncated-record", session.failure)
	}
}

func TestOwnerSSSessionZeroDirectionalTimeoutClosesBothSockets(t *testing.T) {
	session := &ownerSSSession{
		timeouts: policy.Timeout{
			ConnectionIdle: time.Minute,
			DownlinkOnly:   0,
		},
		wantLength: true,
	}
	inbound, outbound := new(ownerTestConn), new(ownerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)

	if action := session.OnReadClosed(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("zero-timeout half-close action = %v, want None", action)
	}
	if inbound.closeCount() != 1 || outbound.closeCount() != 1 {
		t.Fatalf("close counts = inbound %d, outbound %d; want 1,1", inbound.closeCount(), outbound.closeCount())
	}
}

func TestOwnerTCPReaderRetainsPartialRecordAcrossReadError(t *testing.T) {
	payload := bytes.Repeat([]byte("partial-record-"), 32)
	aead, wire := ownerTestEncryptedRecord(t, payload)
	for _, split := range []int{7, ownerSSLengthWire + 11} {
		t.Run(map[bool]string{true: "length", false: "payload"}[split < ownerSSLengthWire], func(t *testing.T) {
			source := &partialTimeoutReader{data: wire, failAt: split}
			reader := &ownerTCPReader{conn: source, auth: aead}
			if _, err := reader.readRecord(); !errors.Is(err, errOwnerTestDeadline) {
				t.Fatalf("first read error = %v, want test deadline", err)
			}
			if len(reader.lengthWire)+len(reader.recordWire) == 0 {
				t.Fatal("partial encrypted bytes were discarded")
			}
			got, err := reader.readRecord()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

func TestOwnerTCPReaderTransfersPlaintextOwnership(t *testing.T) {
	first := bytes.Repeat([]byte("first-record-"), 32)
	second := bytes.Repeat([]byte("second-record-"), 32)
	aead, wire := ownerTestEncryptedRecord(t, first)

	var nonce [12]byte
	incrementOwnerNonce(nonce[:])
	incrementOwnerNonce(nonce[:])
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(second)))
	wire = aead.Seal(wire, nonce[:], length[:], nil)
	incrementOwnerNonce(nonce[:])
	wire = aead.Seal(wire, nonce[:], second, nil)

	reader := &ownerTCPReader{conn: bytes.NewReader(wire), auth: aead}
	firstBuffer, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(firstBuffer)
	secondBuffer, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(secondBuffer)

	if got := firstBuffer[0].Bytes(); !bytes.Equal(got, first) {
		t.Fatalf("first payload changed after second read: got %d bytes, want %d", len(got), len(first))
	}
	if got := secondBuffer[0].Bytes(); !bytes.Equal(got, second) {
		t.Fatalf("second payload mismatch: got %d bytes, want %d", len(got), len(second))
	}
}

func TestOwnerSSSessionAdoptsPartialEncryptedRecord(t *testing.T) {
	payload := bytes.Repeat([]byte("handoff-record-"), 32)
	for _, split := range []int{7, ownerSSLengthWire + 11} {
		t.Run(map[bool]string{true: "length", false: "payload"}[split < ownerSSLengthWire], func(t *testing.T) {
			aead, wire := ownerTestEncryptedRecord(t, payload)
			source := &partialTimeoutReader{data: wire, failAt: split}
			reader := &ownerTCPReader{conn: source, auth: aead}
			if _, err := reader.readRecord(); !errors.Is(err, errOwnerTestDeadline) {
				t.Fatalf("first read error = %v, want test deadline", err)
			}

			wantLength := reader.wantPayload == 0
			want := 0
			if !wantLength {
				want = reader.wantPayload - reader.auth.Overhead()
			}
			flow := new(ownerTestFlow)
			session := &ownerSSSession{
				decrypt:    reader.auth,
				nonce:      reader.nonce,
				flow:       flow,
				timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
				wantLength: wantLength,
				want:       want,
				lengthWire: append([]byte(nil), reader.lengthWire...),
				recordWire: append([]byte(nil), reader.recordWire...),
			}
			inbound := &ownerTestConn{input: append([]byte(nil), source.data[source.offset:]...)}
			outbound := new(ownerTestConn)
			session.OnOpen(owner.Outbound, outbound)
			session.OnOpen(owner.Inbound, inbound)
			defer session.idle.Stop()

			if got := outbound.output.Bytes(); !bytes.Equal(got, payload) {
				t.Fatalf("forwarded payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
			if flow.uplink != int64(len(payload)) {
				t.Fatalf("uplink = %d, want %d", flow.uplink, len(payload))
			}
			if session.failure != "" {
				t.Fatalf("unexpected session failure: %s", session.failure)
			}
		})
	}
}

func TestOwnerSSSessionUploadBackpressureCountsActualWrites(t *testing.T) {
	flow := new(ownerTestFlow)
	session := &ownerSSSession{
		flow:       flow,
		timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
		wantLength: true,
	}
	inbound := new(ownerTestConn)
	outbound := &ownerTestConn{tryLimit: 3}
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	payload := []byte("partial-upload")
	if !session.writeUpload(payload) {
		t.Fatal("initial partial upload failed")
	}
	if flow.uplink != 3 {
		t.Fatalf("uplink after partial write = %d, want 3", flow.uplink)
	}
	if got := outbound.output.Bytes(); !bytes.Equal(got, payload[:3]) {
		t.Fatalf("partial output = %q, want %q", got, payload[:3])
	}
	if len(session.pendingUpload) == 0 || &session.pendingUpload[0] == &payload[3] {
		t.Fatal("callback-scoped upload tail was not copied into session storage")
	}
	if !inbound.paused || !outbound.armed {
		t.Fatalf("backpressure state = paused %v, armed %v; want true,true", inbound.paused, outbound.armed)
	}

	outbound.tryLimit = 0
	if action := session.OnWritable(owner.Outbound, outbound); action != owner.None {
		t.Fatalf("writable action = %v, want None", action)
	}
	if flow.uplink != int64(len(payload)) {
		t.Fatalf("final uplink = %d, want %d", flow.uplink, len(payload))
	}
	if got := outbound.output.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("final output = %q, want %q", got, payload)
	}
	if inbound.paused || outbound.armed {
		t.Fatalf("released state = paused %v, armed %v; want false,false", inbound.paused, outbound.armed)
	}
}

func TestOwnerSSSessionDownloadBackpressureCountsCompletedRecord(t *testing.T) {
	account, err := (&Account{
		Password:   "owner-response-password",
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Email: "owner-response@example.com", Account: account}
	flow := new(ownerTestFlow)
	session := &ownerSSSession{
		account:    account.(*MemoryAccount),
		flow:       flow,
		timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
		wantLength: true,
	}
	inbound := &ownerTestConn{tryLimit: 7}
	outbound := new(ownerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	payload := bytes.Repeat([]byte("partial-download-"), 32)
	if !session.writeDownload(payload) {
		t.Fatal("initial partial download failed")
	}
	if len(session.pendingWire) == 0 || &session.pendingWire[0] != &session.responseWire[7] {
		t.Fatal("partial encrypted response does not alias responseWire at the acknowledged offset")
	}
	if flow.downlink != 0 {
		t.Fatalf("downlink was credited before the encrypted record completed: %d", flow.downlink)
	}
	if !outbound.paused || !inbound.armed {
		t.Fatalf("backpressure state = paused %v, armed %v; want true,true", outbound.paused, inbound.armed)
	}

	pendingLength := len(session.pendingWire)
	inbound.tryLimit = 5
	if action := session.OnWritable(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("partial writable action = %v, want None", action)
	}
	if got, want := len(session.pendingWire), pendingLength-5; got != want {
		t.Fatalf("pending wire after second partial write = %d, want %d", got, want)
	}
	if &session.pendingWire[0] != &session.responseWire[12] {
		t.Fatal("second partial completion copied instead of advancing the responseWire alias")
	}
	if flow.downlink != 0 {
		t.Fatalf("downlink was credited before the encrypted record completed: %d", flow.downlink)
	}

	inbound.tryLimit = 0
	if action := session.OnWritable(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("writable action = %v, want None", action)
	}
	if session.pendingWire != nil {
		t.Fatalf("drained pending wire = %#v, want nil", session.pendingWire)
	}
	if flow.downlink != int64(len(payload)) {
		t.Fatalf("final downlink = %d, want %d", flow.downlink, len(payload))
	}
	if outbound.paused || inbound.armed {
		t.Fatalf("released state = paused %v, armed %v; want false,false", outbound.paused, inbound.armed)
	}

	response, err := ReadTCPResponse(user, bytes.NewReader(inbound.output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := response.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(decoded)
	got := make([]byte, 0, decoded.Len())
	for _, part := range decoded {
		got = append(got, part.Bytes()...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded response mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestOwnerSSSessionDownloadDeferredLogicalAckDoesNotCopyOrRetransmit(t *testing.T) {
	account, err := (&Account{
		Password:   "owner-deferred-ack-password",
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Email: "owner-deferred-ack@example.com", Account: account}
	flow := new(ownerTestFlow)
	session := &ownerSSSession{
		account:    account.(*MemoryAccount),
		flow:       flow,
		timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
		wantLength: true,
	}
	inbound := &ownerTestConn{deferLogicalAck: true}
	outbound := new(ownerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	payload := bytes.Repeat([]byte("deferred-ack-download-"), 16)
	if !session.writeDownload(payload) {
		t.Fatal("deferred-ack download failed")
	}
	if len(session.pendingWire) == 0 || &session.pendingWire[0] != &session.responseWire[0] {
		t.Fatal("logical acknowledgement retained a copied response instead of responseWire")
	}
	wire := append([]byte(nil), inbound.output.Bytes()...)
	if flow.downlink != 0 {
		t.Fatalf("downlink was credited before logical acknowledgement: %d", flow.downlink)
	}

	if action := session.OnWritable(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("deferred acknowledgement action = %v, want None", action)
	}
	if session.pendingWire != nil {
		t.Fatalf("drained pending wire = %#v, want nil", session.pendingWire)
	}
	if got := inbound.output.Bytes(); !bytes.Equal(got, wire) {
		t.Fatalf("logical acknowledgement retransmitted response bytes: got %d, want %d", len(got), len(wire))
	}
	if flow.downlink != int64(len(payload)) {
		t.Fatalf("final downlink = %d, want %d", flow.downlink, len(payload))
	}

	response, err := ReadTCPResponse(user, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := response.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(decoded)
	got := make([]byte, 0, decoded.Len())
	for _, part := range decoded {
		got = append(got, part.Bytes()...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded response mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
