package controller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/transport/internet/xtls"
)

func TestLegacyAccountCompatibility(t *testing.T) {
	controller := new(Controller)
	userInfo := []api.UserInfo{{
		UID:   42,
		Email: "legacy@example.com",
		UUID:  "30a49a3f-cb0c-4c0f-b7be-09b3e01187ba",
	}}

	vmessUsers := controller.buildVmessUser(&userInfo, 8, "legacy-vmess")
	vmessMessage, err := vmessUsers[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	vmessAccount, ok := vmessMessage.(*vmess.Account)
	if !ok {
		t.Fatalf("unexpected VMess account type %T", vmessMessage)
	}
	if vmessAccount.AlterId != 8 {
		t.Fatalf("VMess AlterId = %d, want 8", vmessAccount.AlterId)
	}

	trojanUsers := controller.buildTrojanUser(&userInfo, "legacy-trojan")
	trojanMessage, err := trojanUsers[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	trojanAccount, ok := trojanMessage.(*trojan.Account)
	if !ok {
		t.Fatalf("unexpected Trojan account type %T", trojanMessage)
	}
	if trojanAccount.Flow != "xtls-rprx-direct" {
		t.Fatalf("Trojan Flow = %q, want %q", trojanAccount.Flow, "xtls-rprx-direct")
	}

	vlessUsers := controller.buildVlessUser(&userInfo, "legacy-vless")
	vlessMessage, err := vlessUsers[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	vlessAccount, ok := vlessMessage.(*vless.Account)
	if !ok {
		t.Fatalf("unexpected VLESS account type %T", vlessMessage)
	}
	if vlessAccount.Flow != "xtls-rprx-vision,none" {
		t.Fatalf("VLESS Flow = %q, want %q", vlessAccount.Flow, "xtls-rprx-vision,none")
	}
}

func TestLegacyXTLSInboundCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	if err := os.WriteFile(certFile, []byte("fixture certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("fixture key"), 0o600); err != nil {
		t.Fatal(err)
	}

	config := &Config{CertConfig: &mylego.CertConfig{
		CertMode:         "file",
		CertFile:         certFile,
		KeyFile:          keyFile,
		RejectUnknownSni: true,
	}}
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		Port:              12345,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		TLSType:           "xtls",
		EnableVless:       true,
	}

	inbound, err := InboundBuilder(config, nodeInfo, "legacy-xtls")
	if err != nil {
		t.Fatal(err)
	}
	receiverMessage, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver, ok := receiverMessage.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("unexpected receiver type %T", receiverMessage)
	}
	stream := receiver.StreamSettings
	wantSecurityType := serial.GetMessageType(&xtls.Config{})
	if stream.SecurityType != wantSecurityType {
		t.Fatalf("SecurityType = %q, want %q", stream.SecurityType, wantSecurityType)
	}
	if len(stream.SecuritySettings) != 1 {
		t.Fatalf("SecuritySettings length = %d, want 1", len(stream.SecuritySettings))
	}
	securityMessage, err := stream.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	security, ok := securityMessage.(*xtls.Config)
	if !ok {
		t.Fatalf("unexpected XTLS settings type %T", securityMessage)
	}
	if !security.RejectUnknownSni {
		t.Fatal("RejectUnknownSni was not preserved")
	}
	if len(security.Certificate) != 1 || security.Certificate[0].CertificatePath != certFile || security.Certificate[0].KeyPath != keyFile {
		t.Fatalf("XTLS certificate paths were not preserved: %+v", security.Certificate)
	}
}

func TestOutboundSendIPCompatibility(t *testing.T) {
	outbound, err := OutboundBuilder(
		&Config{SendIP: "192.0.2.7/24"},
		&api.NodeInfo{NodeType: "V2ray"},
		"legacy-send-ip",
	)
	if err != nil {
		t.Fatal(err)
	}

	senderMessage, err := outbound.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender, ok := senderMessage.(*proxyman.SenderConfig)
	if !ok {
		t.Fatalf("unexpected sender type %T", senderMessage)
	}
	if got := sender.Via.AsAddress().String(); got != "192.0.2.7" {
		t.Fatalf("SendIP address = %q, want %q", got, "192.0.2.7")
	}
	if sender.ViaCidr != "24" {
		t.Fatalf("SendIP CIDR = %q, want %q", sender.ViaCidr, "24")
	}
}
