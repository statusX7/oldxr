package v2board_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/v2board"
)

const (
	testNodeID = 7
	testToken  = "test-panel-token"
)

func newClient(serverURL, nodeType string) *v2board.APIClient {
	return v2board.New(&api.Config{
		APIHost:     serverURL,
		Key:         testToken,
		NodeID:      testNodeID,
		NodeType:    nodeType,
		SpeedLimit:  8,
		DeviceLimit: 3,
		Timeout:     1,
	})
}

func assertLegacyQuery(t *testing.T, r *http.Request, wantLocalPort bool) {
	t.Helper()
	if got := r.URL.Query().Get("node_id"); got != "7" {
		t.Fatalf("node_id = %q, want 7", got)
	}
	if got := r.URL.Query().Get("token"); got != testToken {
		t.Fatalf("token = %q, want %q", got, testToken)
	}
	if wantLocalPort {
		if got := r.URL.Query().Get("local_port"); got != "1" {
			t.Fatalf("local_port = %q, want 1", got)
		}
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func TestV2BoardV2rayCompatibility(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/Deepbwork/config", func(w http.ResponseWriter, r *http.Request) {
		assertLegacyQuery(t, r, true)
		writeJSON(t, w, map[string]any{
			"inbounds": []any{map[string]any{
				"port": 443,
				"streamSettings": map[string]any{
					"network":  "ws",
					"security": "tls",
					"wsSettings": map[string]any{
						"path":    "/legacy-vmess",
						"headers": map[string]any{"Host": "legacy.example.com"},
					},
				},
			}},
			"routing": map[string]any{"rules": []any{
				map[string]any{"type": "field"},
				map[string]any{"domain": []string{"regexp:^blocked\\.example$"}},
			}},
		})
	})
	mux.HandleFunc("/api/v1/server/Deepbwork/user", func(w http.ResponseWriter, r *http.Request) {
		assertLegacyQuery(t, r, false)
		writeJSON(t, w, map[string]any{
			"msg": "ok",
			"data": []any{map[string]any{
				"id": 101,
				"v2ray_user": map[string]any{
					"uuid":     "11111111-1111-1111-1111-111111111111",
					"email":    "legacy-vmess@example.com",
					"alter_id": 4,
				},
			}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "V2ray")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.NodeType != "V2ray" || node.Port != 443 || node.TransportProtocol != "ws" || !node.EnableTLS {
		t.Fatalf("unexpected node info: %+v", node)
	}
	if node.Host != "legacy.example.com" || node.Path != "/legacy-vmess" {
		t.Fatalf("unexpected ws compatibility fields: %+v", node)
	}

	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	wantUser := api.UserInfo{
		UID:         101,
		Email:       "legacy-vmess@example.com",
		SpeedLimit:  1_000_000,
		DeviceLimit: 3,
		UUID:        "11111111-1111-1111-1111-111111111111",
		AlterID:     4,
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
}

func TestV2BoardTrojanCompatibility(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/TrojanTidalab/config", func(w http.ResponseWriter, r *http.Request) {
		assertLegacyQuery(t, r, true)
		writeJSON(t, w, map[string]any{
			"local_port": 8443,
			"ssl":        map[string]any{"sni": "trojan.example.com"},
		})
	})
	mux.HandleFunc("/api/v1/server/TrojanTidalab/user", func(w http.ResponseWriter, r *http.Request) {
		assertLegacyQuery(t, r, false)
		writeJSON(t, w, map[string]any{
			"data": []any{map[string]any{
				"id":          202,
				"trojan_user": map[string]any{"password": "legacy-trojan-password"},
			}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "Trojan")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8443 || node.Host != "trojan.example.com" || !node.EnableTLS || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected node info: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 || (*users)[0].UID != 202 || (*users)[0].UUID != "legacy-trojan-password" || (*users)[0].Email != "legacy-trojan-password" {
		t.Fatalf("unexpected users: %#v", *users)
	}
}

func TestV2BoardShadowsocksCompatibility(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/ShadowsocksTidalab/user", func(w http.ResponseWriter, r *http.Request) {
		requests++
		assertLegacyQuery(t, r, false)
		writeJSON(t, w, map[string]any{
			"data": []any{map[string]any{
				"id":     303,
				"port":   8388,
				"cipher": "aes-128-gcm",
				"secret": "legacy-shadowsocks-secret",
			}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "Shadowsocks")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Port != 8388 || node.CypherMethod != "aes-128-gcm" || node.TransportProtocol != "tcp" {
		t.Fatalf("unexpected node info: %+v", node)
	}
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 || (*users)[0].UID != 303 || (*users)[0].Passwd != "legacy-shadowsocks-secret" || (*users)[0].Method != "aes-128-gcm" {
		t.Fatalf("unexpected users: %#v", *users)
	}
	if requests != 2 {
		t.Fatalf("user endpoint requests = %d, want legacy node/user fetches", requests)
	}
}

func TestV2BoardReportUserTraffic(t *testing.T) {
	var received []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/Deepbwork/submit", func(w http.ResponseWriter, r *http.Request) {
		assertLegacyQuery(t, r, false)
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode traffic: %v", err)
		}
		writeJSON(t, w, map[string]any{"ret": 1, "msg": "ok"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newClient(server.URL, "V2ray")
	traffic := []api.UserTraffic{{UID: 101, Upload: 1234, Download: 5678}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	want := []map[string]any{{"user_id": float64(101), "u": float64(1234), "d": float64(5678)}}
	if !reflect.DeepEqual(received, want) {
		t.Fatalf("traffic = %#v, want %#v", received, want)
	}
}

func TestV2BoardLegacyNoOpReports(t *testing.T) {
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
