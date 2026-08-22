package fastengine

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

func TestUnixAdminProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan map[string]any, 4)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var request map[string]any
			decodeErr := json.NewDecoder(bufio.NewReader(connection)).Decode(&request)
			if decodeErr == nil {
				requests <- request
				if request["operation"] == "ping" {
					_ = json.NewEncoder(connection).Encode(map[string]any{"ok": true, "result": map[string]any{"pong": true}})
				} else {
					_ = json.NewEncoder(connection).Encode(map[string]any{"ok": true, "result": []Traffic{{UID: 7, Upload: 11, Download: 13}}})
				}
			}
			_ = connection.Close()
		}
	}()

	client := New(path)
	if err := client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	traffic, err := client.TakeVMessTraffic(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(traffic) != 1 || traffic[0] != (Traffic{UID: 7, Upload: 11, Download: 13}) {
		t.Fatalf("traffic = %#v", traffic)
	}
	if err := client.UpdateVMessPolicy(context.Background(), 4, 125_000, 3, []string{"blocked"}); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateShadowsocksPolicy(context.Background(), 5, 250_000, 4, []string{"denied"}); err != nil {
		t.Fatal(err)
	}
	first := <-requests
	second := <-requests
	third := <-requests
	fourth := <-requests
	if first["operation"] != "ping" || second["operation"] != "take_vmess_traffic" || second["site"] != float64(3) {
		t.Fatalf("requests = %#v %#v", first, second)
	}
	if third["operation"] != "update_vmess_policy" || third["site"] != float64(4) || third["speed_bytes_per_second"] != float64(125_000) || third["device_limit"] != float64(3) {
		t.Fatalf("VMess policy request = %#v", third)
	}
	if fourth["operation"] != "update_ss_policy" || fourth["site"] != float64(5) || fourth["speed_bytes_per_second"] != float64(250_000) || fourth["device_limit"] != float64(4) {
		t.Fatalf("Shadowsocks policy request = %#v", fourth)
	}
}

func TestAdminErrorIsReturned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = bufio.NewReader(connection).ReadBytes('\n')
		_ = json.NewEncoder(connection).Encode(map[string]any{"ok": false, "error": "rejected fixture"})
	}()
	if err := New(path).Ping(context.Background()); err == nil || err.Error() != "rejected fixture" {
		t.Fatalf("error = %v", err)
	}
}
