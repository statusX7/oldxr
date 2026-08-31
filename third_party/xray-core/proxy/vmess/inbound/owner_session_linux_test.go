//go:build linux

package inbound

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport/internet/owner"
)

type vmessOwnerTestConn struct {
	mu             sync.Mutex
	input          []byte
	output         bytes.Buffer
	closed         int
	tryLimit       int
	paused         bool
	armed          bool
	wakes          int
	forced         int
	delivered      int
	skipped        int
	skipResumeWake bool
	resumeWakeNoop bool
}

func (c *vmessOwnerTestConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.Write(p)
}

func (c *vmessOwnerTestConn) TryWrite(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := len(p)
	if c.tryLimit < 0 {
		limit = 0
	} else if c.tryLimit > 0 && limit > c.tryLimit {
		limit = c.tryLimit
	}
	return c.output.Write(p[:limit])
}

func (c *vmessOwnerTestConn) SuspendRead() error {
	c.mu.Lock()
	c.paused = true
	c.mu.Unlock()
	return nil
}

func (c *vmessOwnerTestConn) ResumeRead() error {
	c.mu.Lock()
	c.paused = false
	c.resumeWakeNoop = c.skipResumeWake
	c.mu.Unlock()
	return nil
}

func (c *vmessOwnerTestConn) ArmWrite() error {
	c.mu.Lock()
	c.armed = true
	c.mu.Unlock()
	return nil
}

func (c *vmessOwnerTestConn) DisarmWrite() error {
	c.mu.Lock()
	c.armed = false
	c.mu.Unlock()
	return nil
}

func (c *vmessOwnerTestConn) Next(n int) ([]byte, error) {
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

func (c *vmessOwnerTestConn) Discard(n int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || n >= len(c.input) {
		n = len(c.input)
	}
	c.input = c.input[n:]
	return n, nil
}

func (c *vmessOwnerTestConn) InboundBuffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.input)
}

func (c *vmessOwnerTestConn) Wake(callback gnet.AsyncCallback) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wakes++
	resumeWakeNoop := c.resumeWakeNoop
	c.resumeWakeNoop = false
	if callback != nil {
		c.forced++
	}
	if callback == nil && resumeWakeNoop {
		c.skipped++
		return nil
	}
	c.delivered++
	return nil
}

func (c *vmessOwnerTestConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *vmessOwnerTestConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.output.Bytes()...)
}

func (c *vmessOwnerTestConn) wakeCounts() (wakes, forced, delivered, skipped int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wakes, c.forced, c.delivered, c.skipped
}

type vmessOwnerTestFlow struct {
	uplink   int64
	downlink int64
	released int
}

func (*vmessOwnerTestFlow) OwnerEligible() bool               { return true }
func (*vmessOwnerTestFlow) Acquire(int) (time.Duration, bool) { return 0, true }
func (f *vmessOwnerTestFlow) AddUplink(bytes int64)           { f.uplink += bytes }
func (f *vmessOwnerTestFlow) AddDownlink(bytes int64)         { f.downlink += bytes }
func (f *vmessOwnerTestFlow) Release()                        { f.released++ }

func TestOwnerVMessSessionReleasesFlowExactlyOnce(t *testing.T) {
	flow := new(vmessOwnerTestFlow)
	session := &ownerVMessSession{flow: flow}
	session.OnClose(owner.Inbound, nil, nil)
	session.OnClose(owner.Outbound, nil, nil)
	if flow.released != 1 {
		t.Fatalf("flow releases = %d, want 1", flow.released)
	}
}

func TestConsumeVMessOwnerPendingRetainsCapacity(t *testing.T) {
	pending := append(make([]byte, 0, 16), []byte("abcdefgh")...)
	base := &pending[:cap(pending)][0]
	pending = consumeVMessOwnerPending(pending, 3)
	if got, want := string(pending), "defgh"; got != want {
		t.Fatalf("pending = %q, want %q", got, want)
	}
	if &pending[:cap(pending)][0] != base {
		t.Fatal("partial completion replaced the pending backing array")
	}
	pending = consumeVMessOwnerPending(pending, len(pending))
	if len(pending) != 0 || cap(pending) != 16 {
		t.Fatalf("drained pending len/cap = %d/%d, want 0/16", len(pending), cap(pending))
	}
}

func newVMessOwnerCodecForResponseTest(t *testing.T) (*encoding.OwnerBodyCodec, *encoding.ClientSession, *protocol.RequestHeader) {
	t.Helper()
	id := uuid.New()
	account, err := (&vmess.Account{Id: id.String()}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Email: "owner@example.com", Account: account}
	request := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommandTCP,
		Address:  net.DomainAddress("example.com"),
		Port:     443,
		Security: protocol.SecurityType_AES128_GCM,
		Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking,
	}

	wire := buf.New()
	t.Cleanup(wire.Release)
	client := encoding.NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
	if err := client.EncodeRequestHeader(request, wire); err != nil {
		t.Fatal(err)
	}
	requestWriter, err := client.EncodeRequestBody(request, wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
		t.Fatal(err)
	}
	validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
	t.Cleanup(func() { common.Close(validator) })
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	history := encoding.NewSessionHistory()
	t.Cleanup(func() { common.Close(history) })
	server := encoding.NewServerSession(validator, history)
	server.SetAEADForced(true)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(wire.Bytes()))}
	decoded, err := server.DecodeRequestHeader(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := server.NewOwnerBodyCodec(decoded, reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.PrepareResponse(&protocol.ResponseHeader{}); err != nil {
		t.Fatal(err)
	}
	return codec, client, request
}

func TestOwnerVMessSessionSendsTerminationAfterOutboundReadClose(t *testing.T) {
	codec, client, request := newVMessOwnerCodecForResponseTest(t)
	session := &ownerVMessSession{
		codec:        codec,
		timeouts:     policy.Timeout{ConnectionIdle: time.Minute, UplinkOnly: time.Minute, DownlinkOnly: time.Minute},
		responseWire: make([]byte, 0, 1024),
	}
	inbound, outbound := new(vmessOwnerTestConn), new(vmessOwnerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	if action := session.OnReadClosed(owner.Outbound, outbound); action != owner.None {
		t.Fatalf("outbound half-close action = %v, want None", action)
	}
	response := bytes.NewReader(inbound.bytes())
	if _, err := client.DecodeResponseHeader(response); err != nil {
		t.Fatal(err)
	}
	body, err := client.DecodeResponseBody(request, response)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := body.ReadMultiBuffer(); err != io.EOF || !data.IsEmpty() {
		length := data.Len()
		buf.ReleaseMulti(data)
		t.Fatalf("termination read = (%d bytes, %v), want (0, EOF)", length, err)
	}
	if action := session.OnReadClosed(owner.Inbound, inbound); action != owner.Close {
		t.Fatalf("both read halves closed action = %v, want Close", action)
	}
}

func TestOwnerVMessSessionRejectsTruncatedRequestOnReadClose(t *testing.T) {
	session := &ownerVMessSession{
		timeouts:   policy.Timeout{ConnectionIdle: time.Minute},
		wantWire:   32,
		recordWire: []byte{1, 2, 3},
	}
	inbound, outbound := new(vmessOwnerTestConn), new(vmessOwnerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()
	if action := session.OnReadClosed(owner.Inbound, inbound); action != owner.Close {
		t.Fatalf("truncated request action = %v, want Close", action)
	}
}

func TestOwnerVMessSessionUploadBackpressureCountsActualWrites(t *testing.T) {
	flow := new(vmessOwnerTestFlow)
	session := &ownerVMessSession{
		flow:     flow,
		timeouts: policy.Timeout{ConnectionIdle: time.Minute},
	}
	inbound := new(vmessOwnerTestConn)
	outbound := &vmessOwnerTestConn{tryLimit: 4}
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	payload := []byte("partial-vmess-upload")
	if !session.writeUpload(payload) {
		t.Fatal("initial partial upload failed")
	}
	if flow.uplink != 4 {
		t.Fatalf("uplink after partial write = %d, want 4", flow.uplink)
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
	if got := outbound.bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("final output = %q, want %q", got, payload)
	}
	if inbound.paused || outbound.armed {
		t.Fatalf("released state = paused %v, armed %v; want false,false", inbound.paused, outbound.armed)
	}
}

func TestOwnerVMessSessionForcesWakeForProtocolBufferedRequest(t *testing.T) {
	session := &ownerVMessSession{
		timeouts:     policy.Timeout{ConnectionIdle: time.Minute},
		cachedWire:   []byte("next encrypted VMess record"),
		uploadPaused: true,
	}
	inbound := &vmessOwnerTestConn{skipResumeWake: true}
	outbound := new(vmessOwnerTestConn)
	session.inbound = inbound
	session.outbound = outbound

	if !session.resumeUpload() {
		t.Fatal("resume upload failed")
	}
	wakes, forced, delivered, skipped := inbound.wakeCounts()
	if wakes != 1 || forced != 1 || delivered != 1 || skipped != 0 {
		t.Fatalf("wake counts = total %d forced %d delivered %d skipped %d, want 1,1,1,0", wakes, forced, delivered, skipped)
	}
}

func TestOwnerVMessSessionOrdinaryResumeWakeMayBeSkipped(t *testing.T) {
	session := &ownerVMessSession{
		timeouts:     policy.Timeout{ConnectionIdle: time.Minute},
		uploadPaused: true,
	}
	inbound := &vmessOwnerTestConn{skipResumeWake: true}
	outbound := new(vmessOwnerTestConn)
	session.inbound = inbound
	session.outbound = outbound

	if !session.resumeUpload() {
		t.Fatal("resume upload failed")
	}
	wakes, forced, delivered, skipped := inbound.wakeCounts()
	if wakes != 1 || forced != 0 || delivered != 0 || skipped != 1 {
		t.Fatalf("wake counts = total %d forced %d delivered %d skipped %d, want 1,0,0,1", wakes, forced, delivered, skipped)
	}
}

func TestOwnerVMessSessionDownloadBackpressureCountsCompletedRecords(t *testing.T) {
	codec, client, request := newVMessOwnerCodecForResponseTest(t)
	flow := new(vmessOwnerTestFlow)
	session := &ownerVMessSession{
		codec:        codec,
		flow:         flow,
		timeouts:     policy.Timeout{ConnectionIdle: time.Minute},
		responseWire: make([]byte, 0, 64*1024),
	}
	inbound := &vmessOwnerTestConn{tryLimit: 9}
	outbound := new(vmessOwnerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	payload := bytes.Repeat([]byte("partial-vmess-download-"), 4000)
	if !session.writeDownload(payload) {
		t.Fatal("initial partial download failed")
	}
	if flow.downlink != 0 {
		t.Fatalf("downlink was credited before the encrypted record completed: %d", flow.downlink)
	}
	if !outbound.paused || !inbound.armed {
		t.Fatalf("backpressure state = paused %v, armed %v; want true,true", outbound.paused, inbound.armed)
	}

	inbound.tryLimit = 0
	if action := session.OnWritable(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("writable action = %v, want None", action)
	}
	if flow.downlink != int64(len(payload)) {
		t.Fatalf("final downlink = %d, want %d", flow.downlink, len(payload))
	}
	if outbound.paused || inbound.armed {
		t.Fatalf("released state = paused %v, armed %v; want false,false", outbound.paused, inbound.armed)
	}

	response := bytes.NewReader(inbound.bytes())
	if _, err := client.DecodeResponseHeader(response); err != nil {
		t.Fatal(err)
	}
	body, err := client.DecodeResponseBody(request, response)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, len(payload))
	for len(got) < len(payload) {
		data, err := body.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range data {
			got = append(got, part.Bytes()...)
		}
		buf.ReleaseMulti(data)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded response mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestOwnerVMessSessionFinishesPartialTerminationBeforeClosingReadSide(t *testing.T) {
	codec, client, request := newVMessOwnerCodecForResponseTest(t)
	session := &ownerVMessSession{
		codec:        codec,
		timeouts:     policy.Timeout{ConnectionIdle: time.Minute, UplinkOnly: time.Minute, DownlinkOnly: time.Minute},
		responseWire: make([]byte, 0, 1024),
	}
	inbound := &vmessOwnerTestConn{tryLimit: 5}
	outbound := new(vmessOwnerTestConn)
	session.OnOpen(owner.Outbound, outbound)
	session.OnOpen(owner.Inbound, inbound)
	defer session.idle.Stop()

	if action := session.OnReadClosed(owner.Outbound, outbound); action != owner.None {
		t.Fatalf("partial termination action = %v, want None", action)
	}
	if session.responseEnded || len(session.pendingWire) == 0 || !session.pendingWireEnd {
		t.Fatalf("termination state = ended %v, pending %d, end %v", session.responseEnded, len(session.pendingWire), session.pendingWireEnd)
	}
	if !outbound.paused || !inbound.armed {
		t.Fatalf("backpressure state = paused %v, armed %v; want true,true", outbound.paused, inbound.armed)
	}

	inbound.tryLimit = 0
	if action := session.OnWritable(owner.Inbound, inbound); action != owner.None {
		t.Fatalf("termination writable action = %v, want None", action)
	}
	if !session.responseEnded || !session.outboundReadDone {
		t.Fatalf("termination completion = ended %v, readDone %v; want true,true", session.responseEnded, session.outboundReadDone)
	}

	response := bytes.NewReader(inbound.bytes())
	if _, err := client.DecodeResponseHeader(response); err != nil {
		t.Fatal(err)
	}
	body, err := client.DecodeResponseBody(request, response)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := body.ReadMultiBuffer(); err != io.EOF || !data.IsEmpty() {
		length := data.Len()
		buf.ReleaseMulti(data)
		t.Fatalf("termination read = (%d bytes, %v), want (0, EOF)", length, err)
	}
}
