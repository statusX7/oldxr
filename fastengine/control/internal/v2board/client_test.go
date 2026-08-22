package v2board

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestVMessLegacyContractAndIndependentETag(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("node_id") != "7" || request.URL.Query().Get("token") != "fixture-token" {
			t.Fatalf("query = %s", request.URL.RawQuery)
		}
		switch request.URL.Path {
		case "/api/v1/server/Deepbwork/config":
			if request.URL.Query().Get("local_port") != "1" {
				t.Fatalf("local_port = %q", request.URL.Query().Get("local_port"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"inbounds": []any{map[string]any{
				"port":           "21001",
				"streamSettings": map[string]any{"network": "tcp", "security": "none", "tcpSettings": map[string]any{"header": map[string]any{"type": "none"}}},
			}}})
		case "/api/v1/server/Deepbwork/user":
			mu.Lock()
			requests[request.URL.Path] = append(requests[request.URL.Path], request.Header.Get("If-None-Match"))
			mu.Unlock()
			if request.Header.Get("If-None-Match") == `"vmess-v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"vmess-v1"`)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
				"id":         42,
				"v2ray_user": map[string]any{"uuid": "0000002a-0001-4000-8000-00010000002a", "email": "fixture@example.invalid", "alter_id": 0},
			}}})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	client := New(server.URL, "fixture-token", 7, 2, VMess)
	node, err := client.FetchNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if node.Port != 21001 || node.Network != "tcp" || node.Security != "none" || node.HeaderType != "none" {
		t.Fatalf("node = %#v", node)
	}
	users, unchanged, err := client.FetchUsers(context.Background())
	if err != nil || unchanged || len(users) != 1 || users[0].UID != 42 || users[0].AlterID != 0 {
		t.Fatalf("first users = %#v unchanged=%v err=%v", users, unchanged, err)
	}
	users, unchanged, err = client.FetchUsers(context.Background())
	if err != nil || !unchanged || users != nil {
		t.Fatalf("second users = %#v unchanged=%v err=%v", users, unchanged, err)
	}
}

func TestProtocolClientsDoNotShareETagOrSubmitPath(t *testing.T) {
	var submitted string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/server/Deepbwork/user":
			if request.Header.Get("If-None-Match") != "" {
				t.Fatalf("VMess inherited another client's ETag")
			}
			w.Header().Set("ETag", `"vmess"`)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": 1, "v2ray_user": map[string]any{"uuid": "00000001-0001-4000-8000-000100000001", "alter_id": 0}}}})
		case "/api/v1/server/ShadowsocksTidalab/user":
			if request.Header.Get("If-None-Match") != "" {
				t.Fatalf("SS inherited another client's ETag")
			}
			w.Header().Set("ETag", `"ss"`)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": 1, "port": 22001, "cipher": "aes-128-gcm", "secret": "secret"}}})
		case "/api/v1/server/Deepbwork/submit", "/api/v1/server/ShadowsocksTidalab/submit":
			submitted = request.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"data": true})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	vmess := New(server.URL, "fixture", 1, 2, VMess)
	ss := New(server.URL, "fixture", 1, 2, Shadowsocks)
	if _, _, err := vmess.FetchUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ss.FetchUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := vmess.SubmitTraffic(context.Background(), []Traffic{{UID: 1, Upload: 2, Download: 3}}); err != nil {
		t.Fatal(err)
	}
	if submitted != "/api/v1/server/Deepbwork/submit" {
		t.Fatalf("VMess submit path = %q", submitted)
	}
	if err := ss.SubmitTraffic(context.Background(), []Traffic{{UID: 1, Upload: 2, Download: 3}}); err != nil {
		t.Fatal(err)
	}
	if submitted != "/api/v1/server/ShadowsocksTidalab/submit" {
		t.Fatalf("SS submit path = %q", submitted)
	}
}

func Test304WithoutCachedUsersFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	_, _, err := New(server.URL, "fixture", 1, 2, VMess).FetchUsers(context.Background())
	if err == nil {
		t.Fatal("304 without a full response unexpectedly succeeded")
	}
}
