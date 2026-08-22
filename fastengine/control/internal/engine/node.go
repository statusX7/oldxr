package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	ss "github.com/xtls/xray-core/proxy/shadowsocks"

	"oldxr.local/phase6/fastss/internal/panel"
)

type snapshot struct {
	validator *ss.Validator
	handles   map[*protocol.MemoryUser]*UserRuntime
	byUID     map[int]*UserRuntime
	port      int
}

type NodeOptions struct {
	NodeID      int
	ReplayScope uint64
	ListenIP    string
	SendIP      string
	SpeedBytes  int64
	DeviceLimit int
	Features    Features
	Rules       *Rules
	Replay      *ReplayFilter
}

type Node struct {
	options NodeOptions
	live    atomic.Pointer[snapshot]

	mu       sync.Mutex
	listener net.Listener
	runtimes map[int]*UserRuntime

	accepted      atomic.Int64
	authenticated atomic.Int64
	authFailures  atomic.Int64
	replays       atomic.Int64
	deviceRejects atomic.Int64
	ruleRejects   atomic.Int64
	active        atomic.Int64
}

type NodeStats struct {
	NodeID        int   `json:"node_id"`
	Registered    int   `json:"registered"`
	Accepted      int64 `json:"accepted"`
	Authenticated int64 `json:"authenticated"`
	AuthFailures  int64 `json:"auth_failures"`
	Replays       int64 `json:"replays"`
	DeviceRejects int64 `json:"device_rejects"`
	RuleRejects   int64 `json:"rule_rejects"`
	Active        int64 `json:"active"`
}

func NewNode(options NodeOptions) *Node {
	if options.ReplayScope == 0 {
		options.ReplayScope = uint64(options.NodeID)
	}
	return &Node{options: options, runtimes: make(map[int]*UserRuntime)}
}

func (n *Node) UpdateUsers(users []panel.User) error {
	if len(users) == 0 {
		return errors.New("empty user list")
	}
	validator := new(ss.Validator)
	handles := make(map[*protocol.MemoryUser]*UserRuntime, len(users))
	byUID := make(map[int]*UserRuntime, len(users))
	port := users[0].Port

	n.mu.Lock()
	defer n.mu.Unlock()
	for _, user := range users {
		if user.UID <= 0 || user.Password == "" || user.Port != port {
			return fmt.Errorf("invalid or mixed-port user uid=%d port=%d", user.UID, user.Port)
		}
		if !strings.EqualFold(user.Cipher, "aes-128-gcm") && !strings.EqualFold(user.Cipher, "aead_aes_128_gcm") {
			return fmt.Errorf("uid=%d uses unsupported cipher %q", user.UID, user.Cipher)
		}
		account, err := (&ss.Account{
			Password:   user.Password,
			CipherType: ss.CipherType_AES_128_GCM,
			IvCheck:    false, // engine-wide identity-aware ReplayFilter owns this check.
		}).AsAccount()
		if err != nil {
			return err
		}
		memoryUser := &protocol.MemoryUser{Email: strconv.Itoa(user.UID), Account: account}
		if err := validator.Add(memoryUser); err != nil {
			return err
		}
		runtimeUser := n.runtimes[user.UID]
		if runtimeUser == nil {
			runtimeUser = newUserRuntime(user.UID, user.Password, n.options.SpeedBytes, n.options.DeviceLimit)
			n.runtimes[user.UID] = runtimeUser
		} else if runtimeUser.Password != user.Password {
			// Keep traffic/device ownership for the panel UID while replacing credentials.
			runtimeUser.Password = user.Password
		}
		handles[memoryUser] = runtimeUser
		byUID[user.UID] = runtimeUser
	}
	current := n.live.Load()
	if current != nil && current.port != port {
		return fmt.Errorf("hot port change %d -> %d is not supported by prototype", current.port, port)
	}
	n.live.Store(&snapshot{validator: validator, handles: handles, byUID: byUID, port: port})
	return nil
}

func (n *Node) Start(ctx context.Context) error {
	snap := n.live.Load()
	if snap == nil {
		return errors.New("users must be loaded before Start")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(n.options.ListenIP, strconv.Itoa(snap.port)))
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.listener = listener
	n.mu.Unlock()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	var acceptDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay *= 2
				}
				if maximum := time.Second; acceptDelay > maximum {
					acceptDelay = maximum
				}
				timer := time.NewTimer(acceptDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return err
		}
		acceptDelay = 0
		n.accepted.Add(1)
		go n.handle(ctx, conn)
	}
}

type saltCaptureConn struct {
	net.Conn
	salt [16]byte
	n    int
}

func (c *saltCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.n < len(c.salt) && n > 0 {
		copied := copy(c.salt[c.n:], p[:n])
		c.n += copied
	}
	return n, err
}

func (n *Node) handle(parent context.Context, raw net.Conn) {
	defer raw.Close()
	snap := n.live.Load()
	if snap == nil {
		return
	}
	captured := &saltCaptureConn{Conn: raw}
	request, reader, err := ss.ReadTCPSession(snap.validator, captured)
	if err != nil {
		n.authFailures.Add(1)
		return
	}
	user := snap.handles[request.User]
	if user == nil || captured.n != len(captured.salt) {
		n.authFailures.Add(1)
		return
	}
	if n.options.Replay.CheckAndAdd(n.options.ReplayScope, user.UID, captured.salt[:]) {
		n.replays.Add(1)
		return
	}
	n.authenticated.Add(1)

	ip := remoteIP(raw)
	if !user.admit(ip, n.options.Features.Device) {
		n.deviceRejects.Add(1)
		return
	}
	defer user.release(ip, n.options.Features.Device)
	n.active.Add(1)
	defer n.active.Add(-1)

	host := request.Address.String()
	if n.options.Features.Rule && n.options.Rules.Blocked(host) {
		n.ruleRejects.Add(1)
		return
	}
	dialer := net.Dialer{Timeout: 8 * time.Second}
	if n.options.SendIP != "" && n.options.SendIP != "0.0.0.0" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(n.options.SendIP)}
	}
	target, err := dialer.DialContext(parent, "tcp", net.JoinHostPort(host, strconv.Itoa(int(request.Port))))
	if err != nil {
		return
	}
	defer target.Close()

	responseWriter, err := ss.WriteTCPResponse(request, raw)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 2)
	go func() {
		writer := &featureWriter{inner: buf.NewWriter(target), user: user, ctx: ctx, features: n.options.Features}
		err := buf.Copy(reader, writer)
		closeWrite(target)
		errCh <- err
	}()
	go func() {
		writer := &featureWriter{inner: responseWriter, user: user, ctx: ctx, download: true, features: n.options.Features}
		err := buf.Copy(buf.NewReader(target), writer)
		closeWrite(raw)
		errCh <- err
	}()
	first := <-errCh
	if meaningfulCopyError(first) {
		deadline := time.Now()
		raw.SetDeadline(deadline)
		target.SetDeadline(deadline)
	}
	second := <-errCh
	if meaningfulCopyError(first) || meaningfulCopyError(second) {
		return
	}
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
}

func meaningfulCopyError(err error) bool {
	return err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed)
}

func (n *Node) TrafficSnapshot() []panel.Traffic {
	snap := n.live.Load()
	if snap == nil {
		return nil
	}
	traffic := make([]panel.Traffic, 0, len(snap.byUID))
	for uid, user := range snap.byUID {
		up, down := user.snapshotTraffic()
		if up != 0 || down != 0 {
			traffic = append(traffic, panel.Traffic{UID: uid, Upload: up, Download: down})
		}
	}
	return traffic
}

func (n *Node) RestoreTraffic(traffic []panel.Traffic) {
	snap := n.live.Load()
	if snap == nil {
		return
	}
	for _, item := range traffic {
		if user := snap.byUID[item.UID]; user != nil {
			user.restoreTraffic(item.Upload, item.Download)
		}
	}
}

func (n *Node) Stats() NodeStats {
	snap := n.live.Load()
	registered := 0
	if snap != nil {
		registered = len(snap.byUID)
	}
	return NodeStats{
		NodeID: n.options.NodeID, Registered: registered,
		Accepted: n.accepted.Load(), Authenticated: n.authenticated.Load(), AuthFailures: n.authFailures.Load(),
		Replays: n.replays.Load(), DeviceRejects: n.deviceRejects.Load(), RuleRejects: n.ruleRejects.Load(), Active: n.active.Load(),
	}
}

func (n *Node) Addr() net.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.listener == nil {
		return nil
	}
	return n.listener.Addr()
}

func NewClientUser(uid int, password string) *protocol.MemoryUser {
	account, _ := (&ss.Account{Password: password, CipherType: ss.CipherType_AES_128_GCM, IvCheck: false}).AsAccount()
	return &protocol.MemoryUser{Email: strconv.Itoa(uid), Account: account}
}

func RequestHeader(user *protocol.MemoryUser, address string, port uint16) *protocol.RequestHeader {
	return &protocol.RequestHeader{Version: ss.Version, User: user, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress(address), Port: xnet.Port(port)}
}
