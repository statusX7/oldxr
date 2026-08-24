package proxypanel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/proxypanel"
)

const (
	testNodeID = 7
	testKey    = "test-proxypanel-key"
)

type requestRecorder struct {
	mu     sync.Mutex
	bodies map[string][]json.RawMessage
}

func (r *requestRecorder) record(path string, body json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies[path] = append(r.bodies[path], append(json.RawMessage(nil), body...))
}

func writeResponse(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": "success", "code": 200, "data": data, "message": "ok",
	}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func newFixtureServer(t *testing.T) (*httptest.Server, *requestRecorder) {
	t.Helper()
	recorder := &requestRecorder{bodies: make(map[string][]json.RawMessage)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("key"); got != testKey {
			t.Errorf("key = %q, want %q", got, testKey)
		}
		if r.Header.Get("timestamp") == "" {
			t.Error("timestamp header is empty")
		}
		if r.Method == http.MethodPost {
			var body json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode %s body: %v", r.URL.Path, err)
			}
			recorder.record(r.URL.Path, body)
			writeResponse(t, w, map[string]any{"accepted": true})
			return
		}

		switch {
		case r.URL.Path == "/api/v2ray/v1/node/7":
			writeResponse(t, w, map[string]any{
				"id": 7, "speed_limit": 16, "client_limit": 2,
				"v2_port": 443, "v2_alter_id": 4, "v2_net": "ws", "v2_type": "none",
				"v2_host": "vmess.example.com", "v2_path": "/proxy-vmess", "v2_tls": true,
			})
		case r.URL.Path == "/api/ss/v1/node/7":
			writeResponse(t, w, map[string]any{
				"id": 7, "speed_limit": 16, "client_limit": 2, "method": "aes-128-gcm", "port": 8388,
			})
		case r.URL.Path == "/api/trojan/v1/node/7":
			writeResponse(t, w, map[string]any{
				"id": 7, "speed_limit": 16, "client_limit": 2, "trojan_port": 8443,
			})
		case r.URL.Path == "/api/v2ray/v1/userList/7":
			writeResponse(t, w, []any{map[string]any{"uid": 101, "vmess_uid": "vmess-user", "speed_limit": 16}})
		case r.URL.Path == "/api/ss/v1/userList/7":
			writeResponse(t, w, []any{map[string]any{"uid": 202, "passwd": "ss-user", "speed_limit": 16}})
		case r.URL.Path == "/api/trojan/v1/userList/7":
			writeResponse(t, w, []any{map[string]any{"uid": 303, "password": "trojan-user", "speed_limit": 16}})
		case strings.HasSuffix(r.URL.Path, "/nodeRule/7"):
			writeResponse(t, w, map[string]any{
				"mode":  "reject",
				"rules": []any{map[string]any{"id": 9, "type": "reg", "pattern": "^blocked\\.example$"}},
			})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	return server, recorder
}

func newClient(serverURL, nodeType string) *proxypanel.APIClient {
	return proxypanel.New(&api.Config{
		APIHost: serverURL, Key: testKey, NodeID: testNodeID, NodeType: nodeType,
		SpeedLimit: 8, DeviceLimit: 3, Timeout: 1,
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
		if node.Port != 443 || node.AlterID != 4 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Host != "vmess.example.com" || node.Path != "/proxy-vmess" {
			t.Fatalf("unexpected V2ray node: %+v", node)
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
		if node.Port != 8443 || !node.EnableTLS || node.TransportProtocol != "tcp" {
			t.Fatalf("unexpected Trojan node: %+v", node)
		}
	})
}

func TestUserCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t)
	defer server.Close()
	tests := []struct {
		nodeType string
		want     api.UserInfo
	}{
		{"V2ray", api.UserInfo{UID: 101, UUID: "vmess-user", SpeedLimit: 1_000_000, DeviceLimit: 3}},
		{"Shadowsocks", api.UserInfo{UID: 202, Passwd: "ss-user", SpeedLimit: 1_000_000, DeviceLimit: 3}},
		{"Trojan", api.UserInfo{UID: 303, UUID: "trojan-user", SpeedLimit: 1_000_000, DeviceLimit: 3}},
	}
	for _, test := range tests {
		t.Run(test.nodeType, func(t *testing.T) {
			users, err := newClient(server.URL, test.nodeType).GetUserList()
			if err != nil {
				t.Fatalf("GetUserList: %v", err)
			}
			if len(*users) != 1 || !reflect.DeepEqual((*users)[0], test.want) {
				t.Fatalf("users = %#v, want %#v", *users, []api.UserInfo{test.want})
			}
		})
	}
}

func TestRulesAndReports(t *testing.T) {
	server, recorder := newFixtureServer(t)
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
	detect := []api.DetectResult{{UID: 101, RuleID: 9}, {UID: 101, RuleID: 10}}
	if err := client.ReportIllegal(&detect); err != nil {
		t.Fatalf("ReportIllegal: %v", err)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for path, wantCount := range map[string]int{
		"/api/v2ray/v1/nodeStatus/7":  1,
		"/api/v2ray/v1/nodeOnline/7":  1,
		"/api/v2ray/v1/userTraffic/7": 1,
		"/api/v2ray/v1/trigger/7":     2,
	} {
		if got := len(recorder.bodies[path]); got != wantCount {
			t.Fatalf("%s calls = %d, want %d", path, got, wantCount)
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
