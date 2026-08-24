package sspanel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/sspanel"
)

const (
	testNodeID = 7
	testKey    = "test-sspanel-key"
)

type requestRecorder struct {
	mu     sync.Mutex
	counts map[string]int
}

func (r *requestRecorder) record(path string) {
	r.mu.Lock()
	r.counts[path]++
	r.mu.Unlock()
}

func writeResponse(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"ret": 1, "data": data}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func fixtureUsers() []any {
	return []any{map[string]any{
		"id": 101, "email": "user@example.com", "passwd": "fixture-password",
		"uuid": "11111111-1111-1111-1111-111111111111", "port": 8388,
		"method": "aes-128-gcm", "node_speedlimit": 16, "node_connector": 2,
		"is_multi_user": 1, "alive_ip": 0,
	}}
}

func newFixtureServer(t *testing.T, rawServer string) (*httptest.Server, *requestRecorder) {
	t.Helper()
	recorder := &requestRecorder{counts: make(map[string]int)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != testKey {
			t.Errorf("key = %q, want %q", got, testKey)
		}
		if got := r.URL.Query().Get("muKey"); got != testKey {
			t.Errorf("muKey = %q, want %q", got, testKey)
		}
		if r.Method == http.MethodPost {
			var body json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode %s body: %v", r.URL.Path, err)
			}
			recorder.record(r.URL.Path)
			writeResponse(t, w, map[string]any{"accepted": true})
			return
		}
		switch r.URL.Path {
		case "/mod_mu/nodes/7/info":
			writeResponse(t, w, map[string]any{
				"node_group": 1, "node_class": 0, "node_speedlimit": 16,
				"server": rawServer, "version": "",
			})
		case "/mod_mu/users":
			if got := r.URL.Query().Get("node_id"); got != "7" {
				t.Errorf("node_id = %q, want 7", got)
			}
			writeResponse(t, w, fixtureUsers())
		case "/mod_mu/func/detect_rules":
			writeResponse(t, w, []any{map[string]any{"id": 9, "regex": "^blocked\\.example$"}})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	return server, recorder
}

func newClient(serverURL, nodeType string) *sspanel.APIClient {
	return sspanel.New(&api.Config{
		APIHost: serverURL, Key: testKey, NodeID: testNodeID, NodeType: nodeType,
		SpeedLimit: 8, DeviceLimit: 3, Timeout: 1, DisableCustomConfig: true,
	})
}

func TestV2rayCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t, "vmess.example.com;443;4;tls;ws;path=/sspanel-vmess|host=vmess.example.com")
	defer server.Close()
	client := newClient(server.URL, "V2ray")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 443 || node.AlterID != 4 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Path != "/sspanel-vmess" || node.Host != "vmess.example.com" {
		t.Fatalf("unexpected V2ray node: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	wantUser := api.UserInfo{
		UID: 101, Email: "user@example.com", UUID: "11111111-1111-1111-1111-111111111111",
		Passwd: "fixture-password", SpeedLimit: 1_000_000, DeviceLimit: 3,
		Port: 8388, Method: "aes-128-gcm",
	}
	if len(*users) != 1 || !reflect.DeepEqual((*users)[0], wantUser) {
		t.Fatalf("users = %#v, want %#v", *users, []api.UserInfo{wantUser})
	}
}

func TestShadowsocksCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t, "ss.example.com")
	defer server.Close()
	node, err := newClient(server.URL, "Shadowsocks").GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8388 || node.CypherMethod != "aes-128-gcm" || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected Shadowsocks node: %+v", node)
	}
}

func TestTrojanCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t, "trojan.example.com;port=443#8443|host=trojan.example.com|grpc=1|servicename=trojan-service")
	defer server.Close()
	node, err := newClient(server.URL, "Trojan").GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8443 || node.TransportProtocol != "grpc" || !node.EnableTLS || node.Host != "trojan.example.com" || node.ServiceName != "trojan-service" {
		t.Fatalf("unexpected Trojan node: %+v", node)
	}
}

func TestRulesAndReports(t *testing.T) {
	server, recorder := newFixtureServer(t, "vmess.example.com;443;4;tls;ws;path=/sspanel-vmess|host=vmess.example.com")
	defer server.Close()
	client := newClient(server.URL, "V2ray")
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule: %v", err)
	}
	if len(*rules) != 1 || (*rules)[0].ID != 9 || (*rules)[0].Pattern.String() != "^blocked\\.example$" {
		t.Fatalf("unexpected rules: %#v", *rules)
	}
	if err := client.ReportNodeStatus(&api.NodeStatus{CPU: 1, Mem: 2, Disk: 3, Uptime: 4}); err != nil {
		t.Fatalf("ReportNodeStatus: %v", err)
	}
	online := []api.OnlineUser{{UID: 101, IP: "192.0.2.1"}}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Fatalf("ReportNodeOnlineUsers: %v", err)
	}
	traffic := []api.UserTraffic{{UID: 101, Upload: 1234, Download: 5678}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	detect := []api.DetectResult{{UID: 101, RuleID: 9}}
	if err := client.ReportIllegal(&detect); err != nil {
		t.Fatalf("ReportIllegal: %v", err)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for path := range map[string]struct{}{
		"/mod_mu/nodes/7/info":    {},
		"/mod_mu/users/aliveip":   {},
		"/mod_mu/users/traffic":   {},
		"/mod_mu/users/detectlog": {},
	} {
		if got := recorder.counts[path]; got != 1 {
			t.Fatalf("%s calls = %d, want 1", path, got)
		}
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
