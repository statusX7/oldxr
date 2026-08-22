package main

import (
	"os"
	"path/filepath"
	"testing"

	"oldxr.local/phase6/fastss/internal/config"
	"oldxr.local/phase6/fastss/internal/v2board"
)

func TestNormalizeVMessRejectsLegacyAlterID(t *testing.T) {
	_, err := normalizeVMessUsers([]v2board.User{{UID: 1, UUID: "00000001-0001-4000-8000-000100000001", AlterID: 4}})
	if err == nil {
		t.Fatal("legacy alter_id unexpectedly entered FastVMess")
	}
}

func TestNormalizeShadowsocksRequiresOnePortAndCipher(t *testing.T) {
	users := []v2board.User{
		{UID: 1, Port: 22001, Cipher: "aes-128-gcm", Password: "one"},
		{UID: 2, Port: 22001, Cipher: "AES-128-GCM", Password: "two"},
	}
	normalized, port, err := normalizeShadowsocksUsers(users)
	if err != nil {
		t.Fatal(err)
	}
	if port != 22001 || len(normalized) != 2 {
		t.Fatalf("port=%d users=%#v", port, normalized)
	}
	users[1].Port++
	if _, _, err := normalizeShadowsocksUsers(users); err == nil {
		t.Fatal("mixed SS ports unexpectedly succeeded")
	}
}

func TestValidateVMessNodeFailsClosedForUnsupportedTransport(t *testing.T) {
	if err := validateVMessNode(v2board.NodeInfo{Port: 443, Network: "ws", Security: "tls"}); err == nil {
		t.Fatal("unsupported VMess transport unexpectedly entered FastVMess")
	}
	if err := validateVMessNode(v2board.NodeInfo{Port: 21001, Network: "tcp", Security: "none", HeaderType: "none"}); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizedRulesCombineValidatedLocalAndPanelRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.list")
	if err := os.WriteFile(path, []byte("^tcp:local\\.invalid:443$\n[\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	local, err := readLocalRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(local) != 1 || local[0] != `^tcp:local\.invalid:443$` {
		t.Fatalf("local rules = %#v", local)
	}
	node := managedNode{
		config:     config.Node{Controller: config.ControllerConfig{}},
		localRules: local,
		rules:      []string{`regexp:^tcp:panel\.invalid:443$`},
	}
	rules, err := node.normalizedRules()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`^tcp:local\.invalid:443$`, `^tcp:panel\.invalid:443$`}
	if len(rules) != len(want) || rules[0] != want[0] || rules[1] != want[1] {
		t.Fatalf("rules = %#v, want %#v", rules, want)
	}
	node.config.Controller.DisableGetRule = true
	rules, err = node.normalizedRules()
	if err != nil || len(rules) != 0 {
		t.Fatalf("disabled rules = %#v, error = %v", rules, err)
	}
}
