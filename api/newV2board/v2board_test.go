package newV2board_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/newV2board"
)

const (
	testNodeID = 7
	testToken  = "test-uniproxy-token"
)

func newClient(serverURL, nodeType string) *newV2board.APIClient {
	return newV2board.New(&api.Config{
		APIHost:     serverURL,
		Key:         testToken,
		NodeID:      testNodeID,
		NodeType:    nodeType,
		SpeedLimit:  8,
		DeviceLimit: 3,
		Timeout:     1,
	})
}

func assertUniProxyRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.URL.Query().Get("node_id"); got != "7" {
		t.Errorf("node_id = %q, want 7", got)
	}
	if got := r.URL.Query().Get("token"); got != testToken {
		t.Errorf("token = %q, want %q", got, testToken)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func TestV2rayNodeUsersRulesAndTraffic(t *testing.T) {
	var (
		trafficMu sync.Mutex
		traffic   map[string][]int64
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		assertUniProxyRequest(t, r)
		if got := r.URL.Query().Get("node_type"); got != "v2ray" {
			t.Errorf("node_type = %q, want v2ray", got)
		}
		writeJSON(t, w, map[string]any{
			"server_port": 443,
			"network":     "ws",
			"tls":         1,
			"networkSettings": map[string]any{
				"path":    "/uniproxy-vmess",
				"headers": map[string]any{"Host": "vmess.example.com"},
			},
			"routes": []any{
				map[string]any{"id": 11, "match": []string{"^blocked\\.example$"}, "action": "block"},
				map[string]any{"id": 12, "match": []string{"dns.example"}, "action": "dns", "action_value": "1.1.1.1"},
			},
		})
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		assertUniProxyRequest(t, r)
		w.Header().Set("Etag", `"users-v1"`)
		writeJSON(t, w, map[string]any{"users": []any{map[string]any{
			"id": 101, "uuid": "11111111-1111-1111-1111-111111111111", "speed_limit": 16,
		}}})
	})
	mux.HandleFunc("/api/v1/server/UniProxy/push", func(w http.ResponseWriter, r *http.Request) {
		assertUniProxyRequest(t, r)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		var received map[string][]int64
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode traffic request: %v", err)
		}
		trafficMu.Lock()
		traffic = received
		trafficMu.Unlock()
		writeJSON(t, w, map[string]any{"ok": true})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "V2ray")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 443 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Path != "/uniproxy-vmess" || node.Host != "vmess.example.com" {
		t.Fatalf("unexpected V2ray node: %+v", node)
	}
	if len(node.NameServerConfig) != 1 || node.NameServerConfig[0].Address.Address.String() != "1.1.1.1" {
		t.Fatalf("unexpected DNS routes: %#v", node.NameServerConfig)
	}

	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	wantUser := api.UserInfo{
		UID:         101,
		Email:       "11111111-1111-1111-1111-111111111111@v2board.user",
		SpeedLimit:  1_000_000,
		DeviceLimit: 3,
		UUID:        "11111111-1111-1111-1111-111111111111",
	}
	if len(*users) != 1 || !reflect.DeepEqual((*users)[0], wantUser) {
		t.Fatalf("users = %#v, want %#v", *users, []api.UserInfo{wantUser})
	}

	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule: %v", err)
	}
	if len(*rules) != 1 || (*rules)[0].ID != 0 || (*rules)[0].Pattern.String() != "^blocked\\.example$" {
		t.Fatalf("unexpected rules: %#v", *rules)
	}

	report := []api.UserTraffic{{UID: 101, Upload: 1234, Download: 5678}}
	if err := client.ReportUserTraffic(&report); err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	trafficMu.Lock()
	gotTraffic := traffic
	trafficMu.Unlock()
	wantTraffic := map[string][]int64{"101": []int64{1234, 5678}}
	if !reflect.DeepEqual(gotTraffic, wantTraffic) {
		t.Fatalf("traffic = %#v, want %#v", gotTraffic, wantTraffic)
	}
}

func TestShadowsocksNodeAndUsers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		assertUniProxyRequest(t, r)
		if got := r.URL.Query().Get("node_type"); got != "shadowsocks" {
			t.Errorf("node_type = %q, want shadowsocks", got)
		}
		writeJSON(t, w, map[string]any{
			"server_port": 8388,
			"cipher":      "aes-128-gcm",
			"server_key":  "fixture-server-key",
			"obfs":        "http",
			"obfs_settings": map[string]any{
				"path": "ss-path",
			},
		})
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"users": []any{map[string]any{
			"id": 202, "uuid": "ss-user-secret", "speed_limit": 0,
		}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "Shadowsocks")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8388 || node.CypherMethod != "aes-128-gcm" || node.ServerKey != "fixture-server-key" || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected Shadowsocks node: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 || (*users)[0].UID != 202 || (*users)[0].Passwd != "ss-user-secret" {
		t.Fatalf("unexpected Shadowsocks users: %#v", *users)
	}
}

func TestTrojanNode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"server_port": 8443,
			"host":        "trojan.example.com",
			"server_name": "trojan-service",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "Trojan")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8443 || !node.EnableTLS || node.Host != "trojan.example.com" || node.ServiceName != "trojan-service" {
		t.Fatalf("unexpected Trojan node: %+v", node)
	}
}

func TestUserETag(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Etag", `"users-v1"`)
			writeJSON(t, w, map[string]any{"users": []any{map[string]any{"id": 1, "uuid": "one"}}})
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"users-v1"` {
			t.Errorf("If-None-Match = %q, want users-v1", got)
		}
		w.WriteHeader(http.StatusNotModified)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "V2ray")
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("first GetUserList: %v", err)
	}
	if _, err := client.GetUserList(); err == nil || err.Error() != "users no change" {
		t.Fatalf("second GetUserList error = %v, want users no change", err)
	}
}

func TestLegacyNoOpReports(t *testing.T) {
	client := newClient("http://127.0.0.1.invalid", "V2ray")
	status := &api.NodeStatus{}
	online := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	detect := []api.DetectResult{{UID: 1, RuleID: 2}}
	if err := client.ReportNodeStatus(status); err != nil {
		t.Fatalf("ReportNodeStatus: %v", err)
	}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Fatalf("ReportNodeOnlineUsers: %v", err)
	}
	if err := client.ReportIllegal(&detect); err != nil {
		t.Fatalf("ReportIllegal: %v", err)
	}
}
