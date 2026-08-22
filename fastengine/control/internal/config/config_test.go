package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePath = "testdata/fastengine.yml"

func TestLoadOldXRConfig(t *testing.T) {
	nodes, err := Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(nodes), 1; got != want {
		t.Fatalf("Shadowsocks nodes = %d, want %d", got, want)
	}
	if nodes[0].API.NodeID != 1001 || nodes[0].API.APIKey != "fixture-token" {
		t.Fatalf("unexpected first node: %#v", nodes[0])
	}
}

func TestLoadFastEnginePreservesNodeOrder(t *testing.T) {
	loaded, err := LoadFastEngine(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	nodes := loaded.Nodes
	if got, want := len(nodes), 2; got != want {
		t.Fatalf("FastEngine nodes = %d, want %d", got, want)
	}
	for index, node := range nodes {
		wantType := "V2ray"
		if index%2 == 1 {
			wantType = "Shadowsocks"
		}
		if node.API.NodeType != wantType {
			t.Fatalf("node %d type = %q, want %q", index, node.API.NodeType, wantType)
		}
	}
	if loaded.Connection.Handshake != 8 || loaded.Connection.ConnIdle != 60 || loaded.Connection.BufferSize != 16 {
		t.Fatalf("connection config = %#v", loaded.Connection)
	}
}

func TestLoadFastEngineFallsBackWhenSniffingIsEnabled(t *testing.T) {
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yml")
	contents = []byte(strings.ReplaceAll(string(contents), "DisableSniffing: true", "DisableSniffing: false"))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadFastEngine(path)
	if !errors.Is(err, ErrLegacyRequired) {
		t.Fatalf("sniffing-enabled config error = %v", err)
	}
}
