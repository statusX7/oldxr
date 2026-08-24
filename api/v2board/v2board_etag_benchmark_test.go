package v2board

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

type etagBenchmarkTransport struct {
	body        []byte
	etag        string
	conditional bool
}

func (t etagBenchmarkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	status := http.StatusOK
	body := t.body
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("ETag", t.etag)
	if t.conditional && request.Header.Get("If-None-Match") == t.etag {
		status = http.StatusNotModified
		body = nil
	}
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status),
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    request,
	}, nil
}

func etagBenchmarkUserBody(users int) []byte {
	data := make([]map[string]any, users)
	for i := range data {
		uid := i + 1
		data[i] = map[string]any{
			"id": uid,
			"v2ray_user": map[string]any{
				"uuid":     fmt.Sprintf("%08d-1111-2222-3333-444444444444", uid),
				"email":    fmt.Sprintf("user-%d@v2board.user", uid),
				"alter_id": 0,
			},
		}
	}
	body, err := json.Marshal(map[string]any{"msg": "ok", "data": data})
	if err != nil {
		panic(err)
	}
	return body
}

func benchmarkV2BoardUserSync(b *testing.B, users int, conditional bool) {
	client := New(&api.Config{
		APIHost:  "http://panel.example",
		Key:      "benchmark-token",
		NodeID:   7,
		NodeType: "V2ray",
	})
	client.client.SetTransport(etagBenchmarkTransport{
		body:        etagBenchmarkUserBody(users),
		etag:        `"benchmark-users-v1"`,
		conditional: conditional,
	})
	if _, err := client.GetUserList(); err != nil {
		b.Fatalf("prime GetUserList: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.GetUserList()
		if err != nil && err.Error() != "users no change" {
			b.Fatalf("GetUserList: %v", err)
		}
	}
}

func BenchmarkV2BoardConditionalUserSync(b *testing.B) {
	for _, users := range []int{1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("users-%d", users), func(b *testing.B) {
			benchmarkV2BoardUserSync(b, users, true)
		})
	}
}

func BenchmarkV2BoardFullUserSync(b *testing.B) {
	for _, users := range []int{1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("users-%d", users), func(b *testing.B) {
			benchmarkV2BoardUserSync(b, users, false)
		})
	}
}
