package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestClientETagStateIsIndependent(t *testing.T) {
	t.Helper()
	var mu sync.Mutex
	requests := make(map[string][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "fixture-key" {
			t.Errorf("token = %q", r.URL.Query().Get("token"))
		}
		nodeID := r.URL.Query().Get("node_id")
		mu.Lock()
		requests[nodeID] = append(requests[nodeID], r.Header.Get("If-None-Match"))
		mu.Unlock()
		if r.Header.Get("If-None-Match") == "site-"+nodeID {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "site-"+nodeID)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []User{{UID: 7, Cipher: "aes-128-gcm", Password: "fixture"}}})
	}))
	defer server.Close()

	a := New(server.URL, "fixture-key", 1, 2)
	b := New(server.URL, "fixture-key", 2, 2)
	for _, client := range []*Client{a, b} {
		users, unchanged, err := client.FetchUsers(context.Background())
		if err != nil || unchanged || len(users) != 1 {
			t.Fatalf("first fetch = users:%d unchanged:%v err:%v", len(users), unchanged, err)
		}
		users, unchanged, err = client.FetchUsers(context.Background())
		if err != nil || !unchanged || users != nil {
			t.Fatalf("second fetch = users:%v unchanged:%v err:%v", users, unchanged, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if got := requests["1"]; len(got) != 2 || got[0] != "" || got[1] != "site-1" {
		t.Fatalf("site 1 ETags = %#v", got)
	}
	if got := requests["2"]; len(got) != 2 || got[0] != "" || got[1] != "site-2" {
		t.Fatalf("site 2 ETags = %#v", got)
	}
}

func TestClientSubmitsLegacyTrafficShape(t *testing.T) {
	var got []Traffic
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/server/ShadowsocksTidalab/submit" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("node_id") != "9" || r.URL.Query().Get("token") != "fixture-key" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	want := []Traffic{{UID: 42, Upload: 123, Download: 456}}
	if err := New(server.URL, "fixture-key", 9, 2).SubmitTraffic(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("traffic = %#v, want %#v", got, want)
	}
}
