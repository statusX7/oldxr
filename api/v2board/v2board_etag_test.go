package v2board_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/v2board"
)

func newETagClient(serverURL, nodeType string) *v2board.APIClient {
	return v2board.New(&api.Config{
		APIHost:     serverURL,
		Key:         "etag-test-token",
		NodeID:      7,
		NodeType:    nodeType,
		SpeedLimit:  8,
		DeviceLimit: 3,
		Timeout:     1,
	})
}

func writeETagUsers(t *testing.T, w http.ResponseWriter, nodeType string, version int) {
	t.Helper()
	var user map[string]any
	switch nodeType {
	case "V2ray":
		user = map[string]any{
			"id": version,
			"v2ray_user": map[string]any{
				"uuid":     "11111111-1111-1111-1111-111111111111",
				"email":    fmt.Sprintf("etag-%d@example.com", version),
				"alter_id": 0,
			},
		}
	case "Shadowsocks":
		user = map[string]any{
			"id":     version,
			"port":   8388,
			"cipher": "aes-128-gcm",
			"secret": fmt.Sprintf("etag-secret-%d", version),
		}
	default:
		t.Fatalf("unsupported node type %q", nodeType)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"data": []any{user}}); err != nil {
		t.Fatalf("encode users: %v", err)
	}
}

func TestV2BoardUserETagLifecycle(t *testing.T) {
	var state struct {
		sync.Mutex
		version  int
		invalid  bool
		omitETag bool
		headers  []string
	}
	state.version = 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		version := state.version
		invalid := state.invalid
		omitETag := state.omitETag
		state.headers = append(state.headers, r.Header.Get("If-None-Match"))
		state.Unlock()

		etag := fmt.Sprintf("\"users-v%d\"", version)
		if !omitETag && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if !omitETag {
			w.Header().Set("ETag", etag)
		}
		if invalid {
			_, _ = w.Write([]byte("not-json"))
			return
		}
		writeETagUsers(t, w, "V2ray", version)
	}))
	defer server.Close()

	client := newETagClient(server.URL, "V2ray")
	users, err := client.GetUserList()
	if err != nil || len(*users) != 1 || (*users)[0].UID != 1 {
		t.Fatalf("initial users=%#v err=%v", users, err)
	}
	if _, err := client.GetUserList(); err == nil || err.Error() != "users no change" {
		t.Fatalf("unchanged error=%v, want users no change", err)
	}

	state.Lock()
	state.version = 2
	state.invalid = true
	state.Unlock()
	if _, err := client.GetUserList(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid changed response error=%v", err)
	}

	state.Lock()
	state.invalid = false
	state.Unlock()
	users, err = client.GetUserList()
	if err != nil || (*users)[0].UID != 2 {
		t.Fatalf("recovered users=%#v err=%v", users, err)
	}

	state.Lock()
	state.version = 3
	state.omitETag = true
	state.Unlock()
	users, err = client.GetUserList()
	if err != nil || (*users)[0].UID != 3 {
		t.Fatalf("no-etag users=%#v err=%v", users, err)
	}
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("full response after ETag removal: %v", err)
	}

	state.Lock()
	headers := append([]string(nil), state.headers...)
	state.Unlock()
	wantHeaders := []string{"", `"users-v1"`, `"users-v1"`, `"users-v1"`, `"users-v2"`, ""}
	if fmt.Sprint(headers) != fmt.Sprint(wantHeaders) {
		t.Fatalf("If-None-Match sequence=%q, want %q", headers, wantHeaders)
	}
}

func TestV2BoardRejects304WithoutCachedUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	_, err := newETagClient(server.URL, "V2ray").GetUserList()
	if err == nil || !strings.Contains(err.Error(), "304 without a cached user list") {
		t.Fatalf("error=%v, want missing-cache diagnostic", err)
	}
}

func TestV2BoardUserETagFailureRecoveryAndClientIsolation(t *testing.T) {
	var state struct {
		sync.Mutex
		version int
		fail    bool
		headers []string
	}
	state.version = 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		version := state.version
		fail := state.fail
		state.headers = append(state.headers, r.Header.Get("If-None-Match"))
		state.Unlock()
		if fail {
			http.Error(w, "temporary panel failure", http.StatusServiceUnavailable)
			return
		}
		etag := fmt.Sprintf("\"users-v%d\"", version)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		writeETagUsers(t, w, "V2ray", version)
	}))
	defer server.Close()

	first := newETagClient(server.URL, "V2ray")
	if _, err := first.GetUserList(); err != nil {
		t.Fatalf("prime first client: %v", err)
	}
	state.Lock()
	state.version = 2
	state.fail = true
	state.Unlock()
	if _, err := first.GetUserList(); err == nil || !strings.Contains(err.Error(), "temporary panel failure") {
		t.Fatalf("temporary failure error=%v", err)
	}
	state.Lock()
	state.fail = false
	state.Unlock()
	users, err := first.GetUserList()
	if err != nil || len(*users) != 1 || (*users)[0].UID != 2 {
		t.Fatalf("recovered users=%#v err=%v", users, err)
	}

	second := newETagClient(server.URL, "V2ray")
	if _, err := second.GetUserList(); err != nil {
		t.Fatalf("prime isolated client: %v", err)
	}
	state.Lock()
	headers := append([]string(nil), state.headers...)
	state.Unlock()
	wantHeaders := []string{"", `"users-v1"`, `"users-v1"`, ""}
	if fmt.Sprint(headers) != fmt.Sprint(wantHeaders) {
		t.Fatalf("If-None-Match sequence=%q, want %q", headers, wantHeaders)
	}
}

func TestV2BoardShadowsocksSharesNodeAndUserFetch(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.Header.Get("If-None-Match") == `"ss-users-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"ss-users-v1"`)
		writeETagUsers(t, w, "Shadowsocks", 1)
	}))
	defer server.Close()

	client := newETagClient(server.URL, "Shadowsocks")
	for cycle := 1; cycle <= 2; cycle++ {
		node, err := client.GetNodeInfo()
		if err != nil || node.Port != 8388 || node.CypherMethod != "aes-128-gcm" {
			t.Fatalf("cycle %d node=%#v err=%v", cycle, node, err)
		}
		users, err := client.GetUserList()
		if cycle == 1 {
			if err != nil || len(*users) != 1 || (*users)[0].UID != 1 {
				t.Fatalf("cycle %d users=%#v err=%v", cycle, users, err)
			}
		} else if err == nil || err.Error() != "users no change" {
			t.Fatalf("cycle %d error=%v, want users no change", cycle, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 {
		t.Fatalf("user endpoint requests=%d, want one per node/user cycle", requests)
	}
}

func TestV2BoardShadowsocksPublishesEmptyUsersWithCachedNodeInfo(t *testing.T) {
	var state struct {
		sync.Mutex
		empty   bool
		version int
	}
	state.version = 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		empty := state.empty
		version := state.version
		state.Unlock()
		etag := fmt.Sprintf("\"ss-users-v%d\"", version)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		if empty {
			writeJSON(t, w, map[string]any{"data": []any{}})
			return
		}
		writeETagUsers(t, w, "Shadowsocks", version)
	}))
	defer server.Close()

	client := newETagClient(server.URL, "Shadowsocks")
	node, err := client.GetNodeInfo()
	if err != nil || node.Port != 8388 || node.CypherMethod != "aes-128-gcm" {
		t.Fatalf("initial node=%#v err=%v", node, err)
	}
	users, err := client.GetUserList()
	if err != nil || len(*users) != 1 {
		t.Fatalf("initial users=%#v err=%v", users, err)
	}

	state.Lock()
	state.empty = true
	state.version = 2
	state.Unlock()
	node, err = client.GetNodeInfo()
	if err != nil || node.Port != 8388 || node.CypherMethod != "aes-128-gcm" {
		t.Fatalf("empty-list node=%#v err=%v", node, err)
	}
	users, err = client.GetUserList()
	if err != nil || users == nil || len(*users) != 0 {
		t.Fatalf("empty users=%#v err=%v", users, err)
	}

	node, err = client.GetNodeInfo()
	if err != nil || node.Port != 8388 || node.CypherMethod != "aes-128-gcm" {
		t.Fatalf("cached empty-list node=%#v err=%v", node, err)
	}
	if _, err := client.GetUserList(); err == nil || err.Error() != "users no change" {
		t.Fatalf("cached empty-list error=%v, want users no change", err)
	}
}

func TestV2BoardShadowsocksRejectsInitialEmptyUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"data": []any{}})
	}))
	defer server.Close()

	if _, err := newETagClient(server.URL, "Shadowsocks").GetNodeInfo(); err == nil || !strings.Contains(err.Error(), "number of node users is 0") {
		t.Fatalf("error=%v, want initial empty-user diagnostic", err)
	}
}

func TestV2BoardConcurrentRefreshPublishesOnce(t *testing.T) {
	var state struct {
		sync.Mutex
		version int
		full    int
	}
	state.version = 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		version := state.version
		state.Unlock()
		etag := fmt.Sprintf("\"users-v%d\"", version)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("If-None-Match") == `"users-v1"` {
			time.Sleep(20 * time.Millisecond)
		}
		state.Lock()
		state.full++
		state.Unlock()
		w.Header().Set("ETag", etag)
		writeETagUsers(t, w, "V2ray", version)
	}))
	defer server.Close()

	client := newETagClient(server.URL, "V2ray")
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("prime users: %v", err)
	}
	state.Lock()
	state.version = 2
	state.full = 0
	state.Unlock()

	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			users, err := client.GetUserList()
			if err != nil && err.Error() == "users no change" {
				return
			}
			if err != nil {
				errs <- err
				return
			}
			if len(*users) != 1 || (*users)[0].UID != 2 {
				errs <- fmt.Errorf("unexpected users: %#v", users)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	state.Lock()
	full := state.full
	state.Unlock()
	if full != 1 {
		t.Fatalf("changed full responses=%d, want exactly one serialized publication", full)
	}
}
