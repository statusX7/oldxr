package panel

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestProductionExampleConfig(t *testing.T) {
	configPath := filepath.Join("..", "main", "config.yml.example")
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("read %s: %v", configPath, err)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		t.Fatalf("parse %s: %v", configPath, err)
	}

	if config.LogConfig == nil || config.LogConfig.Level != "none" {
		t.Fatalf("Log.Level = %#v, want none", config.LogConfig)
	}
	if config.ConnectionConfig == nil {
		t.Fatal("ConnectionConfig is missing")
	}
	connection := config.ConnectionConfig
	if connection.Handshake != 4 || connection.ConnIdle != 120 || connection.UplinkOnly != 0 || connection.DownlinkOnly != 0 {
		t.Fatalf("unexpected connection timeouts: %+v", *connection)
	}
	if connection.BufferSize != 8 {
		t.Fatalf("ConnectionConfig.BufferSize = %d, want 8", connection.BufferSize)
	}

	if len(config.NodesConfig) != 1 {
		t.Fatalf("len(Nodes) = %d, want 1", len(config.NodesConfig))
	}
	node := config.NodesConfig[0]
	if node == nil || node.ApiConfig == nil || node.ControllerConfig == nil {
		t.Fatalf("incomplete node config: %#v", node)
	}
	if node.PanelType != "V2board" {
		t.Fatalf("PanelType = %q, want V2board", node.PanelType)
	}
	if node.ApiConfig.Timeout != 5 {
		t.Fatalf("ApiConfig.Timeout = %d, want 5", node.ApiConfig.Timeout)
	}
	if node.ControllerConfig.UpdatePeriodic != 60 {
		t.Fatalf("ControllerConfig.UpdatePeriodic = %d, want 60", node.ControllerConfig.UpdatePeriodic)
	}
	if node.ControllerConfig.CertConfig == nil || node.ControllerConfig.CertConfig.CertMode != "none" {
		t.Fatalf("CertConfig = %#v, want CertMode none", node.ControllerConfig.CertConfig)
	}
	if node.ControllerConfig.DisableUploadTraffic {
		t.Fatal("DisableUploadTraffic must remain false")
	}
	if node.ControllerConfig.DisableGetRule {
		t.Fatal("DisableGetRule must remain false")
	}
	if node.ControllerConfig.DisableSniffing {
		t.Fatal("DisableSniffing must remain false")
	}
	if node.ControllerConfig.DisableIVCheck {
		t.Fatal("DisableIVCheck must remain false")
	}
}
