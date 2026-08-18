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

type benchmarkUserTransport struct {
	body        []byte
	etag        string
	conditional bool
}

func (t benchmarkUserTransport) RoundTrip(request *http.Request) (*http.Response, error) {
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

func benchmarkUserBody(users int) []byte {
	return benchmarkProtocolUserBody(users, "V2ray")
}

func benchmarkProtocolUserBody(users int, nodeType string) []byte {
	data := make([]map[string]any, users)
	for i := range data {
		uid := i + 1
		switch nodeType {
		case "V2ray":
			data[i] = map[string]any{
				"id": uid,
				"v2ray_user": map[string]any{
					"uuid":     fmt.Sprintf("%08d-1111-2222-3333-444444444444", uid),
					"email":    fmt.Sprintf("user-%d@v2board.user", uid),
					"alter_id": 0,
				},
			}
		case "Trojan":
			data[i] = map[string]any{
				"id": uid,
				"trojan_user": map[string]any{
					"password": fmt.Sprintf("%08d-1111-2222-3333-444444444444", uid),
				},
			}
		case "Shadowsocks":
			data[i] = map[string]any{
				"id":     uid,
				"port":   8388,
				"cipher": "aes-128-gcm",
				"secret": fmt.Sprintf("%08d-1111-2222-3333-444444444444", uid),
			}
		default:
			panic("unsupported benchmark node type: " + nodeType)
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
	client.client.SetTransport(benchmarkUserTransport{
		body:        benchmarkUserBody(users),
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
	for _, users := range []int{1000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("users-%d", users), func(b *testing.B) {
			benchmarkV2BoardUserSync(b, users, true)
		})
	}
}

func BenchmarkV2BoardFullUserSync(b *testing.B) {
	for _, users := range []int{1000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("users-%d", users), func(b *testing.B) {
			benchmarkV2BoardUserSync(b, users, false)
		})
	}
}

func BenchmarkV2BoardConditionalUserSyncByProtocol(b *testing.B) {
	for _, nodeType := range []string{"V2ray", "Trojan", "Shadowsocks"} {
		for _, users := range []int{1000, 10_000, 50_000} {
			b.Run(fmt.Sprintf("%s/users-%d", nodeType, users), func(b *testing.B) {
				client := New(&api.Config{
					APIHost:  "http://panel.example",
					Key:      "benchmark-token",
					NodeID:   7,
					NodeType: nodeType,
				})
				client.client.SetTransport(benchmarkUserTransport{
					body:        benchmarkProtocolUserBody(users, nodeType),
					etag:        `"benchmark-users-v1"`,
					conditional: true,
				})
				if _, err := client.GetUserList(); err != nil {
					b.Fatalf("prime GetUserList: %v", err)
				}
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := client.GetUserList(); err == nil || err.Error() != "users no change" {
						b.Fatalf("GetUserList error = %v, want users no change", err)
					}
				}
			})
		}
	}
}
