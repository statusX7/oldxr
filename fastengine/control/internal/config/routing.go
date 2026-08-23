package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	networkTCP uint8 = 1 << iota
	networkUDP

	maxRoutingFileSize = 8 << 20
)

// Protocol bits are a serialized Go-to-Rust ABI and therefore must not share
// the network iota sequence above.
const protocolBitTorrent uint8 = 1

type RoutingPlan struct {
	DomainStrategy  string            `json:"domain_strategy"`
	DefaultOutbound uint16            `json:"default_outbound"`
	Outbounds       []OutboundPlan    `json:"outbounds"`
	Rules           []RoutingRulePlan `json:"rules"`
}

type OutboundPlan struct {
	Tag            string `json:"tag"`
	Action         string `json:"action"`
	DomainStrategy string `json:"domain_strategy"`
}

type RoutingRulePlan struct {
	Outbound          uint16      `json:"outbound"`
	Networks          uint8       `json:"networks"`
	NetworkConstraint bool        `json:"network_constraint"`
	Ports             []PortRange `json:"ports,omitempty"`
	CIDRs             []string    `json:"cidrs,omitempty"`
	Protocols         uint8       `json:"protocols"`
}

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

type rawOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}

type rawFreedomSettings struct {
	DomainStrategy string `json:"domainStrategy"`
}

type rawRouting struct {
	DomainStrategy string           `json:"domainStrategy"`
	Rules          []rawRoutingRule `json:"rules"`
}

type rawRoutingRule struct {
	Type        string          `json:"type"`
	OutboundTag string          `json:"outboundTag"`
	IP          stringList      `json:"ip"`
	Protocol    stringList      `json:"protocol"`
	Port        json.RawMessage `json:"port"`
	Network     stringList      `json:"network"`
}

type stringList []string

func (values *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*values = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("must be a string or string array: %w", err)
	}
	*values = many
	return nil
}

func decodeStrict(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRoutingFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if decoder.More() {
		return fmt.Errorf("parse %s: multiple JSON values", path)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("parse %s: multiple JSON values", path)
		}
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func decodeSettings(raw json.RawMessage, destination any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func unsupportedJSON(path string, err error) error {
	if strings.Contains(err.Error(), "json: unknown field") {
		return LegacyRequired("%s contains a field that FastEngine does not support: %v", path, err)
	}
	return err
}

func compileOutbounds(path string) ([]OutboundPlan, map[string]uint16, error) {
	if path == "" {
		outbounds := []OutboundPlan{{Tag: "__fastengine_direct", Action: "direct", DomainStrategy: "as_is"}}
		return outbounds, map[string]uint16{"__fastengine_direct": 0}, nil
	}
	var raw []rawOutbound
	if err := decodeStrict(path, &raw); err != nil {
		return nil, nil, unsupportedJSON(path, err)
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("custom outbound file %s contains no outbounds", path)
	}
	if len(raw) > int(^uint16(0)) {
		return nil, nil, fmt.Errorf("custom outbound file %s contains too many outbounds", path)
	}
	outbounds := make([]OutboundPlan, 0, len(raw))
	tags := make(map[string]uint16, len(raw))
	for index, item := range raw {
		item.Tag = strings.TrimSpace(item.Tag)
		if item.Tag == "" {
			return nil, nil, fmt.Errorf("custom outbound %d has an empty tag", index)
		}
		if _, exists := tags[item.Tag]; exists {
			return nil, nil, fmt.Errorf("custom outbound tag %q is duplicated", item.Tag)
		}
		compiled := OutboundPlan{Tag: item.Tag, DomainStrategy: "as_is"}
		switch strings.ToLower(strings.TrimSpace(item.Protocol)) {
		case "freedom":
			compiled.Action = "direct"
			var settings rawFreedomSettings
			if err := decodeSettings(item.Settings, &settings); err != nil {
				return nil, nil, LegacyRequired("outbound %q freedom settings are unsupported: %v", item.Tag, err)
			}
			switch strings.ToLower(strings.TrimSpace(settings.DomainStrategy)) {
			case "", "asis":
				compiled.DomainStrategy = "as_is"
			case "useipv6":
				compiled.DomainStrategy = "use_ipv6"
			default:
				return nil, nil, LegacyRequired("outbound %q domainStrategy %q is not supported by FastEngine", item.Tag, settings.DomainStrategy)
			}
		case "blackhole":
			compiled.Action = "blackhole"
			var settings map[string]json.RawMessage
			if err := decodeSettings(item.Settings, &settings); err != nil {
				return nil, nil, fmt.Errorf("outbound %q blackhole settings: %w", item.Tag, err)
			}
			if len(settings) != 0 {
				return nil, nil, LegacyRequired("outbound %q uses unsupported blackhole settings", item.Tag)
			}
		default:
			return nil, nil, LegacyRequired("outbound %q protocol %q is not supported by FastEngine", item.Tag, item.Protocol)
		}
		tags[item.Tag] = uint16(index)
		outbounds = append(outbounds, compiled)
	}
	return outbounds, tags, nil
}

func compileRouting(routePath, outboundPath string) (RoutingPlan, error) {
	outbounds, tags, err := compileOutbounds(outboundPath)
	if err != nil {
		return RoutingPlan{}, err
	}
	plan := RoutingPlan{
		DomainStrategy:  "as_is",
		DefaultOutbound: 0,
		Outbounds:       outbounds,
		Rules:           make([]RoutingRulePlan, 0),
	}
	if routePath == "" {
		return plan, nil
	}
	var raw rawRouting
	if err := decodeStrict(routePath, &raw); err != nil {
		return RoutingPlan{}, unsupportedJSON(routePath, err)
	}
	switch strings.ToLower(strings.TrimSpace(raw.DomainStrategy)) {
	case "", "asis":
		plan.DomainStrategy = "as_is"
	case "ipondemand":
		plan.DomainStrategy = "ip_on_demand"
	default:
		return RoutingPlan{}, LegacyRequired("routing domainStrategy %q is not supported by FastEngine", raw.DomainStrategy)
	}
	if len(raw.Rules) > 4096 {
		return RoutingPlan{}, fmt.Errorf("routing file %s contains too many rules", routePath)
	}
	plan.Rules = make([]RoutingRulePlan, 0, len(raw.Rules))
	for index, rule := range raw.Rules {
		if rule.Type != "" && !strings.EqualFold(rule.Type, "field") {
			return RoutingPlan{}, LegacyRequired("routing rule %d type %q is not supported by FastEngine", index, rule.Type)
		}
		outbound, exists := tags[rule.OutboundTag]
		if !exists {
			return RoutingPlan{}, fmt.Errorf("routing rule %d references unknown outboundTag %q", index, rule.OutboundTag)
		}
		compiled := RoutingRulePlan{
			Outbound:          outbound,
			NetworkConstraint: len(rule.Network) != 0,
		}
		compiled.Networks, err = compileNetworks(rule.Network)
		if err != nil {
			return RoutingPlan{}, fmt.Errorf("routing rule %d network: %w", index, err)
		}
		compiled.Ports, err = compilePorts(rule.Port)
		if err != nil {
			return RoutingPlan{}, fmt.Errorf("routing rule %d port: %w", index, err)
		}
		compiled.CIDRs, err = compileCIDRs(rule.IP)
		if err != nil {
			return RoutingPlan{}, fmt.Errorf("routing rule %d ip: %w", index, err)
		}
		compiled.Protocols, err = compileProtocols(rule.Protocol)
		if err != nil {
			return RoutingPlan{}, fmt.Errorf("routing rule %d protocol: %w", index, err)
		}
		if len(compiled.Ports) == 0 && len(compiled.CIDRs) == 0 && compiled.Protocols == 0 && len(rule.Network) == 0 {
			return RoutingPlan{}, fmt.Errorf("routing rule %d has no match condition", index)
		}
		plan.Rules = append(plan.Rules, compiled)
	}
	return plan, nil
}

func compileNetworks(values []string) (uint8, error) {
	if len(values) == 0 {
		return networkTCP | networkUDP, nil
	}
	var result uint8
	for _, value := range values {
		for _, network := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(network)) {
			case "tcp":
				result |= networkTCP
			case "udp":
				result |= networkUDP
			case "":
			default:
				return 0, LegacyRequired("network %q is not supported by FastEngine", network)
			}
		}
	}
	if result == 0 {
		return 0, fmt.Errorf("network list is empty")
	}
	return result, nil
}

func compileProtocols(values []string) (uint8, error) {
	var result uint8
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "bittorrent":
			result |= protocolBitTorrent
		case "":
		default:
			return 0, LegacyRequired("protocol %q is not supported by FastEngine", value)
		}
	}
	return result, nil
}

func compilePorts(raw json.RawMessage) ([]PortRange, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		var number uint16
		if numberErr := json.Unmarshal(raw, &number); numberErr != nil {
			return nil, fmt.Errorf("must be a port number or comma-separated range string")
		}
		if number == 0 {
			return nil, fmt.Errorf("port must be between 1 and 65535")
		}
		return []PortRange{{From: number, To: number}}, nil
	}
	var ranges []PortRange
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("empty port token")
		}
		fromText, toText, ranged := strings.Cut(token, "-")
		if !ranged {
			toText = fromText
		}
		from, err := strconv.ParseUint(strings.TrimSpace(fromText), 10, 16)
		if err != nil || from == 0 {
			return nil, fmt.Errorf("invalid port %q", fromText)
		}
		to, err := strconv.ParseUint(strings.TrimSpace(toText), 10, 16)
		if err != nil || to == 0 || from > to {
			return nil, fmt.Errorf("invalid port range %q", token)
		}
		ranges = append(ranges, PortRange{From: uint16(from), To: uint16(to)})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].From == ranges[j].From {
			return ranges[i].To < ranges[j].To
		}
		return ranges[i].From < ranges[j].From
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || uint32(current.From) > uint32(merged[len(merged)-1].To)+1 {
			merged = append(merged, current)
			continue
		}
		if current.To > merged[len(merged)-1].To {
			merged[len(merged)-1].To = current.To
		}
	}
	return merged, nil
}

var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/3",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func compileCIDRs(values []string) ([]string, error) {
	var prefixes []netip.Prefix
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.EqualFold(value, "geoip:private") {
			for _, private := range privateCIDRs {
				prefixes = append(prefixes, netip.MustParsePrefix(private))
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(value), "geoip:") || strings.HasPrefix(strings.ToLower(value), "ext:") || strings.HasPrefix(strings.ToLower(value), "ext-ip:") {
			return nil, LegacyRequired("IP matcher %q is not supported by FastEngine", value)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid IP or CIDR %q", value)
			}
			bits := 128
			if address.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(address, bits)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix.String())
	}
	return result, nil
}
