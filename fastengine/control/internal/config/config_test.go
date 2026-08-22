package config

import "testing"

func TestLoadOldXRPhase4Config(t *testing.T) {
	nodes, err := Load("/root/projects/oldxr-lab/configs/10sites-1000registered-50active.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(nodes), 10; got != want {
		t.Fatalf("Shadowsocks nodes = %d, want %d", got, want)
	}
	if nodes[0].API.NodeID != 1001 || nodes[0].API.APIKey != "phase4-site-token-01" {
		t.Fatalf("unexpected first node: %#v", nodes[0])
	}
}

func TestLoadFastEnginePreservesTwentyNodeOrder(t *testing.T) {
	nodes, err := LoadFastEngine("/root/projects/oldxr-lab/configs/10sites-1000registered-50active.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(nodes), 20; got != want {
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
}
