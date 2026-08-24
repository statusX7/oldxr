package controller_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	_ "github.com/XrayR-project/XrayR/main/distro/all"
	"github.com/XrayR-project/XrayR/service/controller"
)

type controllerRacePanel struct {
	mu          sync.Mutex
	node        api.NodeInfo
	users       []api.UserInfo
	nodeCalls   int
	userCalls   int
	statusCalls int
}

func (p *controllerRacePanel) GetNodeInfo() (*api.NodeInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodeCalls++
	node := p.node
	return &node, nil
}

func (p *controllerRacePanel) GetUserList() (*[]api.UserInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userCalls++
	users := append([]api.UserInfo(nil), p.users...)
	return &users, nil
}

func (p *controllerRacePanel) ReportNodeStatus(*api.NodeStatus) error {
	p.mu.Lock()
	p.statusCalls++
	p.mu.Unlock()
	return nil
}
func (*controllerRacePanel) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (*controllerRacePanel) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (*controllerRacePanel) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}
func (*controllerRacePanel) ReportIllegal(*[]api.DetectResult) error { return nil }
func (*controllerRacePanel) Debug()                                  {}
func (*controllerRacePanel) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "http://panel.invalid", NodeID: 1, NodeType: "V2ray"}
}

func newControllerTestPort(t *testing.T) uint32 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func newControllerTestServer(t *testing.T) *core.Instance {
	t.Helper()
	policyConfig, err := (&conf.PolicyConfig{Levels: map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	dnsConfig, err := (&conf.DNSConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	routeConfig, err := (&conf.RouterConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage((&conf.LogConfig{LogLevel: "none"}).Build()),
		serial.ToTypedMessage(&mydispatcher.Config{}),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(policyConfig),
		serial.ToTypedMessage(dnsConfig),
		serial.ToTypedMessage(routeConfig),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestControllerPeriodicStateRace(t *testing.T) {
	port := newControllerTestPort(t)
	server := newControllerTestServer(t)

	panel := &controllerRacePanel{
		node: api.NodeInfo{
			NodeType:          "V2ray",
			NodeID:            1,
			Port:              port,
			TransportProtocol: "tcp",
		},
		users: []api.UserInfo{{
			UID:   1,
			Email: "race@example.com",
			UUID:  "00000000-0000-0000-0000-000000000001",
		}},
	}
	c := controller.New(server, panel, &controller.Config{
		ListenIP:                "127.0.0.1",
		UpdatePeriodic:          1,
		DisableGetRule:          true,
		AutoSpeedLimitConfig:    &controller.AutoSpeedLimitConfig{},
		GlobalDeviceLimitConfig: nil,
	}, "V2board")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// The node and user workers intentionally keep their original independent
	// cadence. State publication and snapshots must make their overlap safe.
	time.Sleep(2500 * time.Millisecond)
	panel.mu.Lock()
	nodeCalls, userCalls, statusCalls := panel.nodeCalls, panel.userCalls, panel.statusCalls
	panel.mu.Unlock()
	if nodeCalls < 2 || userCalls < 2 || statusCalls < 1 {
		t.Fatalf("periodic monitors did not execute all work: node=%d user=%d status=%d", nodeCalls, userCalls, statusCalls)
	}
}
