package engine

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/xtls/xray-core/common/protocol"
	ss "github.com/xtls/xray-core/proxy/shadowsocks"
)

const maxPendingPlaintext = 256 * 1024

type endpointRole uint8

const (
	clientEndpoint endpointRole = iota + 1
	targetEndpoint
)

type eventEndpoint struct {
	session *eventSession
	role    endpointRole
}

type eventSession struct {
	node   *Node
	snap   *snapshot
	client gnet.Conn
	target gnet.Conn

	user       *UserRuntime
	account    *ss.MemoryAccount
	remoteIP   string
	auth       cipher.AEAD
	authNonce  [12]byte
	want       int
	wantLength bool
	admitted   bool
	released   bool
	dialing    bool

	targetAddress string
	pendingUpload []byte

	response      cipher.AEAD
	responseSalt  [ssSaltSize]byte
	responseNonce [12]byte
	responseReady bool
	responseWire  []byte
}

type ssEventEngine struct {
	gnet.BuiltinEventEngine
	ctx         context.Context
	nodesByPort map[int]*Node
	engine      gnet.Engine
	connections atomic.Int64
}

func runGnetNodes(ctx context.Context, nodes []*Node) error {
	addresses := make([]string, 0, len(nodes))
	nodesByPort := make(map[int]*Node, len(nodes))
	for _, node := range nodes {
		snap := node.live.Load()
		if snap == nil {
			return fmt.Errorf("node %d users are not loaded", node.options.NodeID)
		}
		if _, exists := nodesByPort[snap.port]; exists {
			return fmt.Errorf("duplicate Shadowsocks listen port %d", snap.port)
		}
		nodesByPort[snap.port] = node
		addresses = append(addresses, "tcp://"+net.JoinHostPort(node.options.ListenIP, strconv.Itoa(snap.port)))
	}
	handler := &ssEventEngine{ctx: ctx, nodesByPort: nodesByPort}
	return gnet.Rotate(handler, addresses,
		gnet.WithMulticore(false),
		gnet.WithNumEventLoop(1),
		gnet.WithEdgeTriggeredIO(false),
		gnet.WithReuseAddr(true),
		gnet.WithReadBufferCap(16*1024),
		gnet.WithWriteBufferCap(64*1024),
		gnet.WithTCPNoDelay(gnet.TCPNoDelay),
	)
}

func (e *ssEventEngine) OnBoot(engine gnet.Engine) gnet.Action {
	e.engine = engine
	go func() {
		<-e.ctx.Done()
		stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = engine.Stop(stopContext)
	}()
	return gnet.None
}

func (e *ssEventEngine) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	if endpoint, ok := conn.Context().(*eventEndpoint); ok && endpoint.role == targetEndpoint {
		session := endpoint.session
		session.target = conn
		if len(session.pendingUpload) > 0 {
			if !e.writePlain(session, conn, session.pendingUpload, false) {
				return nil, gnet.Close
			}
			session.pendingUpload = nil
		}
		return nil, gnet.None
	}

	port, err := addressPort(conn.LocalAddr())
	if err != nil {
		return nil, gnet.Close
	}
	node := e.nodesByPort[port]
	if node == nil {
		return nil, gnet.Close
	}
	snap := node.live.Load()
	if snap == nil {
		return nil, gnet.Close
	}
	session := &eventSession{node: node, snap: snap, client: conn, remoteIP: addressHost(conn.RemoteAddr())}
	conn.SetContext(&eventEndpoint{session: session, role: clientEndpoint})
	node.accepted.Add(1)
	e.connections.Add(1)
	return nil, gnet.None
}

func (e *ssEventEngine) OnTraffic(conn gnet.Conn) gnet.Action {
	endpoint, ok := conn.Context().(*eventEndpoint)
	if !ok || endpoint.session == nil {
		return gnet.Close
	}
	if endpoint.role == targetEndpoint {
		return e.processTarget(conn, endpoint.session)
	}
	return e.processClient(conn, endpoint.session)
}

func (e *ssEventEngine) processClient(conn gnet.Conn, session *eventSession) gnet.Action {
	for {
		if session.auth == nil {
			if conn.InboundBuffered() < ssSaltSize+ssLengthWireSize {
				return gnet.None
			}
			wire, err := conn.Peek(ssSaltSize + ssLengthWireSize)
			if err != nil {
				return gnet.Close
			}
			memoryUser, aead, length, saltLength, err := session.snap.validator.Get(wire, protocol.RequestCommandTCP)
			if err != nil || saltLength != ssSaltSize || len(length) != 2 {
				session.node.authFailures.Add(1)
				return gnet.Close
			}
			user := session.snap.handles[memoryUser]
			if user == nil {
				session.node.authFailures.Add(1)
				return gnet.Close
			}
			if session.node.options.Replay.CheckAndAdd(session.node.options.ReplayScope, user.UID, wire[:ssSaltSize]) {
				session.node.replays.Add(1)
				return gnet.Close
			}
			if !user.admit(session.remoteIP, session.node.options.Features.Device) {
				session.node.deviceRejects.Add(1)
				return gnet.Close
			}
			if _, err := conn.Discard(ssSaltSize + ssLengthWireSize); err != nil {
				user.release(session.remoteIP, session.node.options.Features.Device)
				return gnet.Close
			}
			session.user = user
			session.account = memoryUser.Account.(*ss.MemoryAccount)
			session.auth = aead
			session.want = int(binary.BigEndian.Uint16(length))
			incrementNonce(session.authNonce[:]) // validator consumed length with nonce zero.
			session.admitted = true
			session.node.authenticated.Add(1)
			session.node.active.Add(1)
			if session.want == 0 || session.want > ssMaxPayload {
				return gnet.Close
			}
		}

		if session.wantLength {
			if conn.InboundBuffered() < ssLengthWireSize {
				return gnet.None
			}
			wire, err := conn.Next(ssLengthWireSize)
			if err != nil {
				return gnet.Close
			}
			length, err := session.auth.Open(wire[:0], session.authNonce[:], wire, nil)
			if err != nil || len(length) != 2 {
				return gnet.Close
			}
			incrementNonce(session.authNonce[:])
			session.want = int(binary.BigEndian.Uint16(length))
			session.wantLength = false
			if session.want == 0 {
				return gnet.Close
			}
			if session.want > ssMaxPayload {
				return gnet.Close
			}
		}

		payloadWireSize := session.want + ssTagSize
		if conn.InboundBuffered() < payloadWireSize {
			return gnet.None
		}
		wire, err := conn.Next(payloadWireSize)
		if err != nil {
			return gnet.Close
		}
		plaintext, err := session.auth.Open(wire[:0], session.authNonce[:], wire, nil)
		if err != nil {
			return gnet.Close
		}
		incrementNonce(session.authNonce[:])
		session.wantLength = true
		session.want = 0

		if session.targetAddress == "" {
			target, consumed, err := parseSSTarget(plaintext)
			if err != nil {
				return gnet.Close
			}
			host, _, err := net.SplitHostPort(target)
			if err != nil {
				return gnet.Close
			}
			if session.node.options.Features.Rule && session.node.options.Rules.Blocked(host) {
				session.node.ruleRejects.Add(1)
				return gnet.Close
			}
			session.targetAddress = target
			if len(plaintext) > consumed && !e.queueOrWriteUpload(session, plaintext[consumed:]) {
				return gnet.Close
			}
			e.dialTarget(session)
			continue
		}
		if !e.queueOrWriteUpload(session, plaintext) {
			return gnet.Close
		}
	}
}

func (e *ssEventEngine) queueOrWriteUpload(session *eventSession, plaintext []byte) bool {
	if len(plaintext) == 0 {
		return true
	}
	if session.target != nil {
		return e.writePlain(session, session.target, plaintext, false)
	}
	if len(session.pendingUpload)+len(plaintext) > maxPendingPlaintext {
		return false
	}
	session.pendingUpload = append(session.pendingUpload, plaintext...)
	return true
}

func (e *ssEventEngine) dialTarget(session *eventSession) {
	if session.dialing || session.targetAddress == "" {
		return
	}
	session.dialing = true
	client := session.client
	dialer := net.Dialer{Timeout: 8 * time.Second}
	if sendIP := session.node.options.SendIP; sendIP != "" && sendIP != "0.0.0.0" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(sendIP)}
	}
	go func() {
		target, err := dialer.DialContext(e.ctx, "tcp", session.targetAddress)
		if err != nil {
			_ = client.Close()
			return
		}
		endpoint := &eventEndpoint{session: session, role: targetEndpoint}
		result, err := client.EventLoop().Enroll(gnet.NewContext(context.Background(), endpoint), target)
		if err != nil {
			target.Close()
			_ = client.Close()
			return
		}
		registered := <-result
		if registered.Err != nil {
			_ = client.Close()
		}
	}()
}

func (e *ssEventEngine) processTarget(conn gnet.Conn, session *eventSession) gnet.Action {
	buffered := conn.InboundBuffered()
	if buffered == 0 || session.client == nil || session.user == nil {
		return gnet.None
	}
	plaintext, err := conn.Next(buffered)
	if err != nil {
		return gnet.Close
	}
	if session.node.options.Features.Limiter && session.user.limiter != nil {
		if err := session.user.limiter.WaitN(e.ctx, len(plaintext)); err != nil {
			return gnet.Close
		}
	}
	if !session.responseReady {
		if _, err := rand.Read(session.responseSalt[:]); err != nil {
			return gnet.Close
		}
		response, err := newAES128GCMSession(session.account, session.responseSalt[:])
		if err != nil {
			return gnet.Close
		}
		session.response = response
		session.responseReady = true
	}
	session.responseWire = session.responseWire[:0]
	if session.responseNonce == ([12]byte{}) {
		session.responseWire = append(session.responseWire, session.responseSalt[:]...)
	}
	session.responseWire = sealSSRecords(session.response, session.responseNonce[:], session.responseWire, plaintext)
	if _, err := session.client.Write(session.responseWire); err != nil {
		return gnet.Close
	}
	if session.node.options.Features.Traffic {
		session.user.download.Add(int64(len(plaintext)))
	}
	return gnet.None
}

func (e *ssEventEngine) writePlain(session *eventSession, target gnet.Conn, plaintext []byte, download bool) bool {
	if session.node.options.Features.Limiter && session.user.limiter != nil {
		if err := session.user.limiter.WaitN(e.ctx, len(plaintext)); err != nil {
			return false
		}
	}
	written, err := target.Write(plaintext)
	if written > 0 && session.node.options.Features.Traffic {
		if download {
			session.user.download.Add(int64(written))
		} else {
			session.user.upload.Add(int64(written))
		}
	}
	return err == nil && written == len(plaintext)
}

func (e *ssEventEngine) OnClose(conn gnet.Conn, _ error) gnet.Action {
	endpoint, ok := conn.Context().(*eventEndpoint)
	if !ok || endpoint.session == nil {
		return gnet.None
	}
	session := endpoint.session
	if !session.released {
		session.released = true
		if session.admitted {
			session.user.release(session.remoteIP, session.node.options.Features.Device)
			session.node.active.Add(-1)
		}
		e.connections.Add(-1)
	}
	if endpoint.role == clientEndpoint {
		session.client = nil
		if session.target != nil {
			peer := session.target
			session.target = nil
			_ = conn.EventLoop().Close(peer)
		}
	} else {
		session.target = nil
		if session.client != nil {
			peer := session.client
			session.client = nil
			_ = conn.EventLoop().Close(peer)
		}
	}
	return gnet.None
}

func addressPort(address net.Addr) (int, error) {
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(port)
}

func addressHost(address net.Addr) string {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}
