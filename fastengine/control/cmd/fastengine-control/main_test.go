package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/statusX7/oldxr/fastengine/control/internal/config"
	"github.com/statusX7/oldxr/fastengine/control/internal/v2board"
)

func TestNormalizeVMessRejectsLegacyAlterID(t *testing.T) {
	_, err := normalizeVMessUsers([]v2board.User{{UID: 1, UUID: "00000001-0001-4000-8000-000100000001", AlterID: 4}})
	if err == nil {
		t.Fatal("legacy alter_id unexpectedly entered FastVMess")
	}
}

func TestConnectionPolicyArgumentsReachFastEngine(t *testing.T) {
	got := appendConnectionArguments(nil, config.ConnectionConfig{
		Handshake: 8, ConnIdle: 60, UplinkOnly: 2, DownlinkOnly: 3,
	})
	want := []string{
		"--handshake-seconds", "8",
		"--conn-idle-seconds", "60",
		"--uplink-only-seconds", "2",
		"--downlink-only-seconds", "3",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("connection arguments = %#v, want %#v", got, want)
	}
}

func TestEngineInputsPreservePerNodeSniffing(t *testing.T) {
	nodes := []*managedNode{
		{
			protocol: v2board.VMess,
			config: config.Node{Controller: config.ControllerConfig{
				ListenIP:        "127.0.0.1",
				DisableSniffing: false,
			}},
			users: []v2board.User{{
				UID:  1,
				UUID: "00000001-0001-4000-8000-000100000001",
			}},
			port: 21001,
		},
		{
			protocol: v2board.Shadowsocks,
			config: config.Node{Controller: config.ControllerConfig{
				ListenIP:        "127.0.0.1",
				DisableSniffing: true,
			}},
			port: 22001,
		},
	}
	vmess, ssAddress, ssPorts, ssSniffing, err := engineInputs(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(vmess) != 1 || !vmess[0].Protocol.Sniffing {
		t.Fatalf("VMess inputs = %#v", vmess)
	}
	if ssAddress != "127.0.0.1" || !reflect.DeepEqual(ssPorts, []string{"22001"}) || !reflect.DeepEqual(ssSniffing, []string{"false"}) {
		t.Fatalf("SS address=%q ports=%#v sniffing=%#v", ssAddress, ssPorts, ssSniffing)
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
	if err := validateVMessNode(v2board.NodeInfo{Port: 443, Network: "ws", Security: "tls"}); !errors.Is(err, config.ErrLegacyRequired) {
		t.Fatal("unsupported VMess transport unexpectedly entered FastVMess")
	}
	if err := validateVMessNode(v2board.NodeInfo{Port: 21001, Network: "tcp", Security: "none", HeaderType: "none"}); err != nil {
		t.Fatal(err)
	}
}

func TestInvocationArgumentsPreserveLegacyCompatibleForms(t *testing.T) {
	arguments, versionOnly := invocationArguments([]string{"run", "--config", "/tmp/config.yml"})
	if versionOnly || len(arguments) != 2 || arguments[0] != "--config" || arguments[1] != "/tmp/config.yml" {
		t.Fatalf("run arguments = %#v, version=%v", arguments, versionOnly)
	}
	arguments, versionOnly = invocationArguments([]string{"version"})
	if !versionOnly || arguments != nil {
		t.Fatalf("version arguments = %#v, version=%v", arguments, versionOnly)
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
