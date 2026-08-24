package v2raysocks_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/v2raysocks"
)

const (
	testNodeID = 280002
	testToken  = "test-v2raysocks-token"
)

type requestRecorder struct {
	mu      sync.Mutex
	traffic []map[string]any
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func newFixtureServer(t *testing.T) (*httptest.Server, *requestRecorder) {
	t.Helper()
	recorder := new(requestRecorder)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("node_id"); got != "280002" {
			t.Errorf("node_id = %q, want 280002", got)
		}
		if got := r.URL.Query().Get("token"); got != testToken {
			t.Errorf("token = %q, want %q", got, testToken)
		}
		nodeType := r.URL.Query().Get("nodetype")
		switch r.URL.Query().Get("act") {
		case "config":
			switch nodeType {
			case "v2ray":
				writeJSON(t, w, map[string]any{
					"inbounds": []any{map[string]any{
						"port": 443,
						"streamSettings": map[string]any{
							"network": "ws", "security": "tls",
							"wsSettings": map[string]any{
								"path": "/v2raysocks-vmess", "headers": map[string]any{"Host": "vmess.example.com"},
							},
						},
					}},
					"routing": map[string]any{"rules": []any{
						map[string]any{"type": "field"},
						map[string]any{"domain": []string{"regexp:^blocked\\.example$"}},
					}},
				})
			case "shadowsocks":
				writeJSON(t, w, map[string]any{"inbounds": []any{map[string]any{
					"port": 8388, "settings": map[string]any{"method": "aes-128-gcm"},
				}}})
			case "trojan":
				writeJSON(t, w, map[string]any{"inbounds": []any{map[string]any{
					"port":           8443,
					"streamSettings": map[string]any{"tlsSettings": map[string]any{"serverName": "trojan.example.com"}},
				}}})
			default:
				http.Error(w, "unknown node type", http.StatusBadRequest)
			}
		case "user":
			var user any
			switch nodeType {
			case "v2ray":
				user = map[string]any{"id": 101, "v2ray_user": map[string]any{
					"uuid": "11111111-1111-1111-1111-111111111111", "email": "vmess@example.com", "alter_id": 4, "speed_limit": 16,
				}}
			case "shadowsocks":
				user = map[string]any{"id": 202, "shadowsocks_user": map[string]any{
					"secret": "ss-secret", "cipher": "aes-128-gcm", "speed_limit": 16,
				}}
			case "trojan":
				user = map[string]any{"id": 303, "trojan_user": map[string]any{
					"password": "trojan-secret", "speed_limit": 16,
				}}
			}
			writeJSON(t, w, map[string]any{"data": []any{user}})
		case "submit":
			var body []map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode traffic: %v", err)
			}
			recorder.mu.Lock()
			recorder.traffic = body
			recorder.mu.Unlock()
			writeJSON(t, w, map[string]any{"ok": true})
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}))
	return server, recorder
}

func newClient(serverURL, nodeType string) *v2raysocks.APIClient {
	return v2raysocks.New(&api.Config{
		APIHost: serverURL, Key: testToken, NodeID: testNodeID, NodeType: nodeType,
		SpeedLimit: 8, DeviceLimit: 3, Timeout: 1,
	})
}

func TestV2rayCompatibility(t *testing.T) {
	server, recorder := newFixtureServer(t)
	defer server.Close()
	client := newClient(server.URL, "V2ray")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 443 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Path != "/v2raysocks-vmess" || node.Host != "vmess.example.com" {
		t.Fatalf("unexpected V2ray node: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	wantUser := api.UserInfo{
		UID: 101, Email: "vmess@example.com", UUID: "11111111-1111-1111-1111-111111111111",
		AlterID: 4, SpeedLimit: 1_000_000, DeviceLimit: 3,
	}
	if len(*users) != 1 || !reflect.DeepEqual((*users)[0], wantUser) {
		t.Fatalf("users = %#v, want %#v", *users, []api.UserInfo{wantUser})
	}
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule: %v", err)
	}
	if len(*rules) != 1 || (*rules)[0].Pattern.String() != "^blocked\\.example$" {
		t.Fatalf("unexpected rules: %#v", *rules)
	}
	traffic := []api.UserTraffic{{UID: 101, Upload: 1234, Download: 5678}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	recorder.mu.Lock()
	gotTraffic := recorder.traffic
	recorder.mu.Unlock()
	wantTraffic := []map[string]any{{"user_id": float64(101), "u": float64(1234), "d": float64(5678)}}
	if !reflect.DeepEqual(gotTraffic, wantTraffic) {
		t.Fatalf("traffic = %#v, want %#v", gotTraffic, wantTraffic)
	}
}

func TestShadowsocksCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t)
	defer server.Close()
	client := newClient(server.URL, "Shadowsocks")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8388 || node.CypherMethod != "aes-128-gcm" || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected Shadowsocks node: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 || (*users)[0].UID != 202 || (*users)[0].Passwd != "ss-secret" || (*users)[0].Method != "aes-128-gcm" {
		t.Fatalf("unexpected Shadowsocks users: %#v", *users)
	}
}

func TestTrojanCompatibility(t *testing.T) {
	server, _ := newFixtureServer(t)
	defer server.Close()
	client := newClient(server.URL, "Trojan")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8443 || !node.EnableTLS || node.Host != "trojan.example.com" || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected Trojan node: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 || (*users)[0].UID != 303 || (*users)[0].UUID != "trojan-secret" {
		t.Fatalf("unexpected Trojan users: %#v", *users)
	}
}

func TestLegacyNoOpReports(t *testing.T) {
	client := newClient("http://127.0.0.1.invalid", "V2ray")
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatalf("ReportNodeStatus: %v", err)
	}
	online := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Fatalf("ReportNodeOnlineUsers: %v", err)
	}
	detect := []api.DetectResult{{UID: 1, RuleID: 2}}
	if err := client.ReportIllegal(&detect); err != nil {
		t.Fatalf("ReportIllegal: %v", err)
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
