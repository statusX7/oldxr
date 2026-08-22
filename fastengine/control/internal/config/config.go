package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	Nodes []Node `yaml:"Nodes"`
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
}

type ControllerConfig struct {
	ListenIP             string `yaml:"ListenIP"`
	SendIP               string `yaml:"SendIP"`
	UpdatePeriodic       int    `yaml:"UpdatePeriodic"`
	DisableUploadTraffic bool   `yaml:"DisableUploadTraffic"`
	DisableGetRule       bool   `yaml:"DisableGetRule"`
	DisableIVCheck       bool   `yaml:"DisableIVCheck"`
}

func read(path string) ([]Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Nodes, nil
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
	all, err := read(path)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for _, node := range all {
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
func LoadFastEngine(path string) ([]Node, error) {
	all, err := read(path)
	if err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(all))
	for _, node := range all {
		if !strings.EqualFold(node.PanelType, "V2board") {
			return nil, fmt.Errorf("node panel type %q requires LegacyEngine", node.PanelType)
		}
		if !strings.EqualFold(node.API.NodeType, "V2ray") && !strings.EqualFold(node.API.NodeType, "Shadowsocks") {
			return nil, fmt.Errorf("V2Board node type %q requires LegacyEngine", node.API.NodeType)
		}
		node, err = normalize(node)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no compatible V2Board VMess or Shadowsocks nodes in %s", path)
	}
	return nodes, nil
}
