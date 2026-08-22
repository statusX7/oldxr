package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrLegacyRequired = errors.New("configuration requires LegacyEngine")

func LegacyRequired(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrLegacyRequired, fmt.Sprintf(format, arguments...))
}

type File struct {
	LogConfig          LogConfig         `yaml:"Log"`
	DNSConfigPath      string            `yaml:"DnsConfigPath"`
	InboundConfigPath  string            `yaml:"InboundConfigPath"`
	OutboundConfigPath string            `yaml:"OutboundConfigPath"`
	RouteConfigPath    string            `yaml:"RouteConfigPath"`
	ConnectionConfig   *ConnectionConfig `yaml:"ConnectionConfig"`
	Nodes              []Node            `yaml:"Nodes"`
}

type LogConfig struct {
	Level      string `yaml:"Level"`
	AccessPath string `yaml:"AccessPath"`
	ErrorPath  string `yaml:"ErrorPath"`
}

type ConnectionConfig struct {
	Handshake    uint32 `yaml:"Handshake"`
	ConnIdle     uint32 `yaml:"ConnIdle"`
	UplinkOnly   uint32 `yaml:"UplinkOnly"`
	DownlinkOnly uint32 `yaml:"DownlinkOnly"`
	BufferSize   int32  `yaml:"BufferSize"`
}

type FastEngineFile struct {
	Nodes      []Node
	Connection ConnectionConfig
}

type Node struct {
	PanelType  string           `yaml:"PanelType"`
	API        APIConfig        `yaml:"ApiConfig"`
	Controller ControllerConfig `yaml:"ControllerConfig"`
}

type APIConfig struct {
	APIHost      string  `yaml:"ApiHost"`
	APIKey       string  `yaml:"ApiKey"`
	NodeID       int     `yaml:"NodeID"`
	NodeType     string  `yaml:"NodeType"`
	Timeout      int     `yaml:"Timeout"`
	SpeedLimit   float64 `yaml:"SpeedLimit"`
	DeviceLimit  int     `yaml:"DeviceLimit"`
	RuleListPath string  `yaml:"RuleListPath"`
	EnableVless  bool    `yaml:"EnableVless"`
	EnableXTLS   bool    `yaml:"EnableXTLS"`
}

type ControllerConfig struct {
	ListenIP                string                  `yaml:"ListenIP"`
	SendIP                  string                  `yaml:"SendIP"`
	UpdatePeriodic          int                     `yaml:"UpdatePeriodic"`
	DisableUploadTraffic    bool                    `yaml:"DisableUploadTraffic"`
	DisableGetRule          bool                    `yaml:"DisableGetRule"`
	DisableIVCheck          bool                    `yaml:"DisableIVCheck"`
	DisableSniffing         bool                    `yaml:"DisableSniffing"`
	EnableDNS               bool                    `yaml:"EnableDNS"`
	DNSType                 string                  `yaml:"DNSType"`
	EnableProxyProtocol     bool                    `yaml:"EnableProxyProtocol"`
	EnableFallback          bool                    `yaml:"EnableFallback"`
	AutoSpeedLimitConfig    AutoSpeedLimitConfig    `yaml:"AutoSpeedLimitConfig"`
	GlobalDeviceLimitConfig GlobalDeviceLimitConfig `yaml:"GlobalDeviceLimitConfig"`
	FallBackConfigs         []map[string]any        `yaml:"FallBackConfigs"`
	CertConfig              CertConfig              `yaml:"CertConfig"`
}

type AutoSpeedLimitConfig struct {
	Limit         int `yaml:"Limit"`
	WarnTimes     int `yaml:"WarnTimes"`
	LimitSpeed    int `yaml:"LimitSpeed"`
	LimitDuration int `yaml:"LimitDuration"`
}

type GlobalDeviceLimitConfig struct {
	Enable bool `yaml:"Enable"`
}

type CertConfig struct {
	CertMode string `yaml:"CertMode"`
}

func read(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return File{}, err
	}
	return file, nil
}

func normalize(node Node) (Node, error) {
	if node.API.APIHost == "" || node.API.APIKey == "" || node.API.NodeID <= 0 {
		return Node{}, fmt.Errorf("invalid V2Board %s node: host=%q node_id=%d", node.API.NodeType, node.API.APIHost, node.API.NodeID)
	}
	if node.Controller.ListenIP == "" {
		node.Controller.ListenIP = "0.0.0.0"
	}
	if node.Controller.UpdatePeriodic <= 0 {
		node.Controller.UpdatePeriodic = 60
	}
	if node.API.Timeout <= 0 {
		node.API.Timeout = 5
	}
	return node, nil
}

func Load(path string) ([]Node, error) {
	file, err := read(path)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for _, node := range file.Nodes {
		if !strings.EqualFold(node.PanelType, "V2board") || !strings.EqualFold(node.API.NodeType, "Shadowsocks") {
			continue
		}
		node, err = normalize(node)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no compatible V2Board Shadowsocks nodes in %s", path)
	}
	return nodes, nil
}

// LoadFastEngine loads exactly the V2Board 1.6.0 node types supported by the
// Phase 7 engine. It fails closed when the config needs a legacy engine so a
// caller cannot silently drop a configured node.
func normalizedConnection(input *ConnectionConfig) ConnectionConfig {
	result := ConnectionConfig{Handshake: 4, ConnIdle: 10, BufferSize: 16}
	if input == nil {
		return result
	}
	if input.Handshake != 0 {
		result.Handshake = input.Handshake
	}
	if input.ConnIdle != 0 {
		result.ConnIdle = input.ConnIdle
	}
	result.UplinkOnly = input.UplinkOnly
	result.DownlinkOnly = input.DownlinkOnly
	if input.BufferSize != 0 {
		result.BufferSize = input.BufferSize
	}
	return result
}

func validateFastEngineFile(file File) error {
	if file.DNSConfigPath != "" || file.InboundConfigPath != "" || file.OutboundConfigPath != "" || file.RouteConfigPath != "" {
		return LegacyRequired("custom DNS, inbound, outbound or route files are configured")
	}
	if file.LogConfig.AccessPath != "" || file.LogConfig.ErrorPath != "" {
		return LegacyRequired("custom access or error log paths are configured")
	}
	return nil
}

func validateFastEngineNode(node Node) error {
	if node.API.EnableVless || node.API.EnableXTLS {
		return LegacyRequired("VLESS or XTLS is enabled")
	}
	controller := node.Controller
	if !controller.DisableSniffing {
		return LegacyRequired("payload sniffing is enabled")
	}
	if controller.EnableDNS || controller.EnableProxyProtocol || controller.EnableFallback || controller.DisableIVCheck {
		return LegacyRequired("DNS, PROXY protocol, fallback or DisableIVCheck is enabled")
	}
	if controller.DNSType != "" && !strings.EqualFold(controller.DNSType, "AsIs") {
		return LegacyRequired("DNS strategy %q is not supported by FastEngine", controller.DNSType)
	}
	if controller.SendIP != "" && controller.SendIP != "0.0.0.0" && controller.SendIP != "::" {
		return LegacyRequired("outbound source address %q is configured", controller.SendIP)
	}
	auto := controller.AutoSpeedLimitConfig
	if auto.Limit != 0 || auto.WarnTimes != 0 || auto.LimitSpeed != 0 || auto.LimitDuration != 0 {
		return LegacyRequired("AutoSpeedLimitConfig is enabled")
	}
	if controller.GlobalDeviceLimitConfig.Enable {
		return LegacyRequired("GlobalDeviceLimitConfig is enabled")
	}
	if len(controller.FallBackConfigs) != 0 {
		return LegacyRequired("FallBackConfigs are configured")
	}
	if controller.CertConfig.CertMode != "" && !strings.EqualFold(controller.CertConfig.CertMode, "none") {
		return LegacyRequired("certificate mode %q is configured", controller.CertConfig.CertMode)
	}
	return nil
}

func LoadFastEngine(path string) (FastEngineFile, error) {
	file, err := read(path)
	if err != nil {
		return FastEngineFile{}, err
	}
	if err := validateFastEngineFile(file); err != nil {
		return FastEngineFile{}, err
	}
	nodes := make([]Node, 0, len(file.Nodes))
	for _, node := range file.Nodes {
		if !strings.EqualFold(node.PanelType, "V2board") {
			return FastEngineFile{}, LegacyRequired("node panel type %q is not supported by FastEngine", node.PanelType)
		}
		if !strings.EqualFold(node.API.NodeType, "V2ray") && !strings.EqualFold(node.API.NodeType, "Shadowsocks") {
			return FastEngineFile{}, LegacyRequired("V2Board node type %q is not supported by FastEngine", node.API.NodeType)
		}
		node, err = normalize(node)
		if err != nil {
			return FastEngineFile{}, err
		}
		if err := validateFastEngineNode(node); err != nil {
			return FastEngineFile{}, err
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return FastEngineFile{}, fmt.Errorf("no compatible V2Board VMess or Shadowsocks nodes in %s", path)
	}
	return FastEngineFile{Nodes: nodes, Connection: normalizedConnection(file.ConnectionConfig)}, nil
}
