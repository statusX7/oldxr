package engine

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	ss "github.com/xtls/xray-core/proxy/shadowsocks"

	"oldxr.local/phase6/fastss/internal/panel"
)

func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() { cancel(); listener.Close(); _ = ctx }
}

func TestNodeRealShadowsocksTCPPayloadIntegrityAndTraffic(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()
	echoHost, echoPortRaw, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	echoPort, err := net.LookupPort("tcp", echoPortRaw)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := NewNode(NodeOptions{
		NodeID: 1, ListenIP: "127.0.0.1", Features: Features{Traffic: true, Device: true, Rule: true},
		DeviceLimit: 2, Rules: &Rules{exact: make(map[string]struct{})}, Replay: NewReplayFilter(1024),
	})
	const password = "phase6-real-ss-secret"
	if err := node.UpdateUsers([]panel.User{{UID: 7, Port: 0, Cipher: "aes-128-gcm", Password: password}}); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- node.Start(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for node.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if node.Addr() == nil {
		t.Fatal("node listener did not start")
	}

	conn, err := net.Dial("tcp", node.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	user := NewClientUser(7, password)
	request := RequestHeader(user, echoHost, uint16(echoPort))
	writer, err := ss.WriteTCPRequest(request, conn)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("phase6-fastss-integrity-"), 4096)
	var container buf.MultiBufferContainer
	if _, err := container.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(container.MultiBuffer); err != nil {
		t.Fatal(err)
	}
	container.MultiBuffer = nil
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	response, err := ss.ReadTCPResponse(user, conn)
	if err != nil {
		t.Fatal(err)
	}
	reader := &buf.BufferedReader{Reader: response}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload mismatch")
	}

	deadline = time.Now().Add(3 * time.Second)
	var traffic []panel.Traffic
	for time.Now().Before(deadline) {
		traffic = node.TrafficSnapshot()
		if len(traffic) > 0 && traffic[0].Upload == int64(len(payload)) && traffic[0].Download == int64(len(payload)) {
			break
		}
		if len(traffic) > 0 {
			node.RestoreTraffic(traffic)
		}
		time.Sleep(time.Millisecond)
	}
	if len(traffic) != 1 || traffic[0].Upload != int64(len(payload)) || traffic[0].Download != int64(len(payload)) {
		t.Fatalf("traffic = %#v, want exact bidirectional payload bytes", traffic)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("node did not stop")
	}
}

func TestNodeRejectsSameUserWireReplay(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()
	echoHost, echoPortRaw, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	echoPort, err := net.LookupPort("tcp", echoPortRaw)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := NewNode(NodeOptions{NodeID: 11, ListenIP: "127.0.0.1", Replay: NewReplayFilter(1024), Rules: &Rules{exact: make(map[string]struct{})}})
	const password = "phase6-replay-secret"
	if err := node.UpdateUsers([]panel.User{{UID: 9, Port: 0, Cipher: "aes-128-gcm", Password: password}}); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- node.Start(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for node.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if node.Addr() == nil {
		t.Fatal("node listener did not start")
	}

	user := NewClientUser(9, password)
	request := RequestHeader(user, echoHost, uint16(echoPort))
	var wire bytes.Buffer
	writer, err := ss.WriteTCPRequest(request, &wire)
	if err != nil {
		t.Fatal(err)
	}
	payload := buf.FromBytes([]byte("replay-me"))
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	requestBytes := append([]byte(nil), wire.Bytes()...)

	send := func() {
		conn, err := net.Dial("tcp", node.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(requestBytes); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, conn)
		conn.Close()
	}
	send()
	send()

	deadline = time.Now().Add(3 * time.Second)
	for node.Stats().Replays != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := node.Stats().Replays; got != 1 {
		t.Fatalf("replay rejects = %d, want 1", got)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("node did not stop")
	}
}
