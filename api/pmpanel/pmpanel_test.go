package pmpanel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/pmpanel"
)

const (
	testNodeID = 4
	testKey    = "test-pmpanel-key"
)

type requestRecorder struct {
	mu      sync.Mutex
	online  map[string]any
	traffic map[string]any
}

func writeResponse(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"ret": 200, "data": data}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func newFixtureServer(t *testing.T) (*httptest.Server, *requestRecorder) {
	t.Helper()
	recorder := new(requestRecorder)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/node", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("key"); got != testKey {
			t.Errorf("key header = %q, want %q", got, testKey)
		}
		if got := r.URL.Query().Get("nodeId"); got != "4" {
			t.Errorf("nodeId = %q, want 4", got)
		}
		switch r.URL.Query().Get("type") {
		case "v2ray":
			writeResponse(t, w, map[string]any{
				"outPort": 443, "alterId": 4, "network": "ws", "security": "tls",
				"host": "vmess.example.com", "path": "/pmpanel-vmess", "speedlimit": 16,
			})
		case "ss":
			writeResponse(t, w, map[string]any{"outPort": 8388, "method": "aes-128-gcm", "speedlimit": 16})
		case "trojan":
			writeResponse(t, w, map[string]any{
				"outPort": 8443, "host": "trojan.example.com", "grpc": true,
				"sni": "trojan-service", "speedlimit": 16,
			})
		default:
			http.Error(w, "unknown type", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("all"); got != "true" {
			t.Errorf("all = %q, want true", got)
		}
		writeResponse(t, w, []any{map[string]any{
			"id": 101, "passwd": "fixture-user-password", "nodeSpeedlimit": 16, "nodeConnector": 2,
		}})
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		writeResponse(t, w, []any{map[string]any{"id": 9, "regex": "^blocked\\.example$"}})
	})
	mux.HandleFunc("/api/online", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode online report: %v", err)
		}
		recorder.mu.Lock()
		recorder.online = body
		recorder.mu.Unlock()
		writeResponse(t, w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/traffic", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode traffic report: %v", err)
		}
		recorder.mu.Lock()
		recorder.traffic = body
		recorder.mu.Unlock()
		writeResponse(t, w, map[string]any{"ok": true})
	})
	return httptest.NewServer(mux), recorder
}

func newClient(serverURL, nodeType string) *pmpanel.APIClient {
	return pmpanel.New(&api.Config{
		APIHost:     serverURL,
		Key:         testKey,
		NodeID:      testNodeID,
		NodeType:    nodeType,
		SpeedLimit:  8,
		DeviceLimit: 3,
		Timeout:     1,
	})
}

func TestNodeCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t)
	defer server.Close()

	t.Run("V2ray", func(t *testing.T) {
		node, err := newClient(server.URL, "V2ray").GetNodeInfo()
		if err != nil {
			t.Fatalf("GetNodeInfo: %v", err)
		}
		if node.Port != 443 || node.AlterID != 4 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Host != "vmess.example.com" || node.Path != "/pmpanel-vmess" {
			t.Fatalf("unexpected V2ray node: %+v", node)
		}
		if node.SpeedLimit != 1_000_000 {
			t.Fatalf("SpeedLimit = %d, want 1000000", node.SpeedLimit)
		}
	})

	t.Run("Shadowsocks", func(t *testing.T) {
		node, err := newClient(server.URL, "Shadowsocks").GetNodeInfo()
		if err != nil {
			t.Fatalf("GetNodeInfo: %v", err)
		}
		if node.Port != 8388 || node.CypherMethod != "aes-128-gcm" || node.TransportProtocol != "tcp" {
			t.Fatalf("unexpected Shadowsocks node: %+v", node)
		}
	})

	t.Run("Trojan", func(t *testing.T) {
		node, err := newClient(server.URL, "Trojan").GetNodeInfo()
		if err != nil {
			t.Fatalf("GetNodeInfo: %v", err)
		}
		if node.Port != 8443 || node.TransportProtocol != "grpc" || !node.EnableTLS || node.Host != "trojan.example.com" || node.ServiceName != "trojan-service" {
			t.Fatalf("unexpected Trojan node: %+v", node)
		}
	})
}

func TestUsersRulesAndReports(t *testing.T) {
	server, recorder := newFixtureServer(t)
	defer server.Close()
	client := newClient(server.URL, "V2ray")

	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	wantUser := api.UserInfo{
		UID: 101, Passwd: "fixture-user-password", UUID: "fixture-user-password",
		SpeedLimit: 1_000_000, DeviceLimit: 3,
	}
	if len(*users) != 1 || !reflect.DeepEqual((*users)[0], wantUser) {
		t.Fatalf("users = %#v, want %#v", *users, []api.UserInfo{wantUser})
	}
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule: %v", err)
	}
	if len(*rules) != 1 || (*rules)[0].ID != 9 || (*rules)[0].Pattern.String() != "^blocked\\.example$" {
		t.Fatalf("unexpected rules: %#v", *rules)
	}

	online := []api.OnlineUser{{UID: 101, IP: "192.0.2.1"}}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Fatalf("ReportNodeOnlineUsers: %v", err)
	}
	traffic := []api.UserTraffic{{UID: 101, Upload: 1234, Download: 5678}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatalf("ReportNodeStatus: %v", err)
	}
	detect := []api.DetectResult{{UID: 101, RuleID: 9}}
	if err := client.ReportIllegal(&detect); err != nil {
		t.Fatalf("ReportIllegal: %v", err)
	}

	recorder.mu.Lock()
	gotOnline := recorder.online
	gotTraffic := recorder.traffic
	recorder.mu.Unlock()
	if gotOnline["type"] != "v2ray" || gotOnline["nodeId"] != float64(testNodeID) {
		t.Fatalf("online envelope = %#v", gotOnline)
	}
	if gotTraffic["type"] != "v2ray" || gotTraffic["nodeId"] != float64(testNodeID) {
		t.Fatalf("traffic envelope = %#v", gotTraffic)
	}
}

func TestHTTPErrorIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()
	if _, err := newClient(server.URL, "V2ray").GetNodeInfo(); err == nil {
		t.Fatal("HTTP 400 was accepted")
	}
}
