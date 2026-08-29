//go:build linux

package inbound

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
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
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/owner"
)

type vmessOwnerTestConn struct {
	mu       sync.Mutex
	input    []byte
	output   bytes.Buffer
	closed   int
	tryLimit int
	paused   bool
	armed    bool
	shutdown int
	wakes    int
	forced   int
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

func (c *vmessOwnerTestConn) ShutdownWrite() error {
	c.mu.Lock()
	c.shutdown++
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
	c.wakes++
	if callback != nil {
		c.forced++
	}
	c.mu.Unlock()
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

func (c *vmessOwnerTestConn) wakeCounts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wakes, c.forced
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
	inbound := new(vmessOwnerTestConn)
	outbound := new(vmessOwnerTestConn)
	session.inbound = inbound
	session.outbound = outbound

	if !session.resumeUpload() {
		t.Fatal("resume upload failed")
	}
	wakes, forced := inbound.wakeCounts()
	if wakes != 1 || forced != 1 {
		t.Fatalf("wake counts = total %d forced %d, want 1,1", wakes, forced)
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

type vmessOwnerIntegrationFlow struct {
	released chan struct{}
	once     sync.Once
}

func newVMessOwnerIntegrationFlow() *vmessOwnerIntegrationFlow {
	return &vmessOwnerIntegrationFlow{released: make(chan struct{})}
}

func (*vmessOwnerIntegrationFlow) OwnerEligible() bool               { return true }
func (*vmessOwnerIntegrationFlow) Acquire(int) (time.Duration, bool) { return 0, true }
func (*vmessOwnerIntegrationFlow) AddUplink(int64)                   {}
func (*vmessOwnerIntegrationFlow) AddDownlink(int64)                 {}
func (f *vmessOwnerIntegrationFlow) Release() {
	f.once.Do(func() { close(f.released) })
}

func listenVMessOwnerIntegrationTCP(t *testing.T) *stdnet.TCPListener {
	t.Helper()
	listener, err := stdnet.ListenTCP("tcp", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestOwnerVMessSessionProtocolEOFHalfClosesOutboundAndPreservesReverseTraffic(t *testing.T) {
	for _, reactor := range []string{"gnet", "uring"} {
		t.Run(reactor, func(t *testing.T) {
			t.Setenv("XRAYR_SOCKET_OWNER_REACTOR", reactor)

			inboundListener := listenVMessOwnerIntegrationTCP(t)
			targetListener := listenVMessOwnerIntegrationTCP(t)
			client, err := stdnet.DialTCP("tcp", nil, inboundListener.Addr().(*stdnet.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			inbound, err := inboundListener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			outbound, err := stdnet.DialTCP("tcp", nil, targetListener.Addr().(*stdnet.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			target, err := targetListener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()

			id := uuid.New()
			account, err := (&vmess.Account{Id: id.String()}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			user := &protocol.MemoryUser{Email: "owner-integration@example.com", Account: account}
			request := &protocol.RequestHeader{
				Version:  1,
				User:     user,
				Command:  protocol.RequestCommandTCP,
				Address:  net.DomainAddress("example.com"),
				Port:     443,
				Security: protocol.SecurityType_AES128_GCM,
				Option: protocol.RequestOptionChunkStream |
					protocol.RequestOptionChunkMasking |
					protocol.RequestOptionGlobalPadding |
					protocol.RequestOptionAuthenticatedLength,
			}

			clientSession := encoding.NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
			var header bytes.Buffer
			if err := clientSession.EncodeRequestHeader(request, &header); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(header.Bytes()); err != nil {
				t.Fatal(err)
			}

			validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
			defer common.Close(validator)
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			history := encoding.NewSessionHistory()
			defer common.Close(history)
			serverSession := encoding.NewServerSession(validator, history)
			serverSession.SetAEADForced(true)
			requestReader := &buf.BufferedReader{Reader: buf.NewReader(inbound)}
			decoded, err := serverSession.DecodeRequestHeader(requestReader, false)
			if err != nil {
				t.Fatal(err)
			}
			codec, err := serverSession.NewOwnerBodyCodec(decoded, requestReader)
			if err != nil {
				t.Fatal(err)
			}
			if err := codec.PrepareResponse(&protocol.ResponseHeader{}); err != nil {
				t.Fatal(err)
			}

			flow := newVMessOwnerIntegrationFlow()
			link := transport.NewDirectLink(nil, nil, nil)
			ownerSession := newOwnerVMessSession(
				codec,
				link,
				flow,
				policy.Timeout{ConnectionIdle: 300 * time.Millisecond, UplinkOnly: 2 * time.Second, DownlinkOnly: 2 * time.Second},
				nil,
				codec.TakeEncryptedBuffered(),
				nil,
				nil,
			)
			if err := owner.AdoptPair(inbound, outbound, ownerSession); err != nil {
				t.Fatalf("adopt %s owner: %v", reactor, err)
			}

			requestWriter, err := clientSession.EncodeRequestBody(request, client)
			if err != nil {
				t.Fatal(err)
			}
			var responseReader buf.Reader
			gaps := []time.Duration{25 * time.Millisecond, 75 * time.Millisecond, 150 * time.Millisecond, 40 * time.Millisecond}
			for iteration := 0; iteration < 16; iteration++ {
				requestPayload := bytes.Repeat([]byte{byte(iteration + 1)}, 257+iteration*131)
				if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(requestPayload)}); err != nil {
					t.Fatalf("request burst %d: %v", iteration, err)
				}
				_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
				received := make([]byte, len(requestPayload))
				if _, err := io.ReadFull(target, received); err != nil {
					t.Fatalf("target request burst %d: %v", iteration, err)
				}
				if !bytes.Equal(received, requestPayload) {
					t.Fatalf("owner request burst %d mismatch", iteration)
				}

				responsePayload := bytes.Repeat([]byte{byte(255 - iteration)}, 193+iteration*97)
				if _, err := target.Write(responsePayload); err != nil {
					t.Fatalf("target response burst %d: %v", iteration, err)
				}
				_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
				if responseReader == nil {
					if _, err := clientSession.DecodeResponseHeader(client); err != nil {
						t.Fatal(err)
					}
					responseReader, err = clientSession.DecodeResponseBody(request, client)
					if err != nil {
						t.Fatal(err)
					}
				}
				var response []byte
				for len(response) < len(responsePayload) {
					mb, readErr := responseReader.ReadMultiBuffer()
					for _, part := range mb {
						response = append(response, part.Bytes()...)
					}
					buf.ReleaseMulti(mb)
					if readErr != nil {
						t.Fatalf("client response burst %d: %v", iteration, readErr)
					}
				}
				if !bytes.Equal(response, responsePayload) {
					t.Fatalf("owner response burst %d mismatch: got %d want %d", iteration, len(response), len(responsePayload))
				}
				time.Sleep(gaps[iteration%len(gaps)])
			}

			// A VMess termination record ends the logical upload even though the
			// client keeps its TCP read half open for the final response. The
			// target must observe EOF exactly as it does through the stock pipe.
			if err := requestWriter.WriteMultiBuffer(nil); err != nil {
				t.Fatal(err)
			}
			_ = target.SetReadDeadline(time.Now().Add(time.Second))
			one := make([]byte, 1)
			if n, err := target.Read(one); n != 0 || err != io.EOF {
				t.Fatalf("target read after VMess protocol EOF = (%d, %v), want (0, EOF)", n, err)
			}

			finalResponse := bytes.Repeat([]byte("reverse-after-upload-eof-"), 193)
			if _, err := target.Write(finalResponse); err != nil {
				t.Fatal(err)
			}
			if err := target.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var response []byte
			for {
				mb, readErr := responseReader.ReadMultiBuffer()
				for _, part := range mb {
					response = append(response, part.Bytes()...)
				}
				buf.ReleaseMulti(mb)
				if readErr != nil {
					if readErr != io.EOF {
						t.Fatal(readErr)
					}
					break
				}
			}
			if !bytes.Equal(response, finalResponse) {
				t.Fatalf("reverse payload mismatch: got %d want %d", len(response), len(finalResponse))
			}
			select {
			case <-flow.released:
			case <-time.After(3 * time.Second):
				t.Fatal("owner VMess flow was not released")
			}
		})
	}
}
