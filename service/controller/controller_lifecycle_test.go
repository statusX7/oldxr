package controller_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/service/controller"
)

func TestControllerStartAndClose(t *testing.T) {
	server := newControllerTestServer(t)
	panel := &controllerRacePanel{
		node: api.NodeInfo{
			NodeType:          "V2ray",
			NodeID:            1,
			Port:              newControllerTestPort(t),
			TransportProtocol: "tcp",
		},
		users: []api.UserInfo{{
			UID:   1,
			Email: "lifecycle@example.com",
			UUID:  "00000000-0000-0000-0000-000000000001",
		}},
	}
	managed := controller.New(server, panel, &controller.Config{
		ListenIP:             "127.0.0.1",
		UpdatePeriodic:       3600,
		DisableGetRule:       true,
		AutoSpeedLimitConfig: &controller.AutoSpeedLimitConfig{},
	}, "V2board")
	if err := managed.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := managed.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := managed.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	panel.mu.Lock()
	nodeCalls, userCalls := panel.nodeCalls, panel.userCalls
	panel.mu.Unlock()
	if nodeCalls != 1 || userCalls != 1 {
		t.Fatalf("initial panel calls = node:%d user:%d, want 1/1", nodeCalls, userCalls)
	}
}
