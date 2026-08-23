package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleOutbounds = `[
  {"tag":"IPv4_out","protocol":"freedom","settings":{}},
  {"tag":"IPv6_out","protocol":"freedom","settings":{"domainStrategy":"UseIPv6"}},
  {"protocol":"blackhole","tag":"block"}
]`

const sampleRoute = `{
  "domainStrategy":"IPOnDemand",
  "rules":[
    {"type":"field","outboundTag":"block","ip":["geoip:private"]},
    {"type":"field","outboundTag":"block","protocol":["bittorrent"]},
    {"type":"field","outboundTag":"block","ip":["172.16.0.0/12","127.0.0.1/32","10.0.0.0/8","fc00::/7","fe80::/10"]},
    {"type":"field","outboundTag":"block","port":"22,23,24,25,107,194,445,465,587,992,3389,6665-6669,6679,6697,6881-6999,7000,10000-38887,38889-65535"},
    {"type":"field","outboundTag":"IPv4_out","network":"udp,tcp"}
  ]
}`

func writeRoutingFixture(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompileRoutingExactPhase8Sample(t *testing.T) {
	outbounds := writeRoutingFixture(t, "custom_outbound.json", sampleOutbounds)
	route := writeRoutingFixture(t, "route.json", sampleRoute)
	plan, err := compileRouting(route, outbounds)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DomainStrategy != "ip_on_demand" || plan.DefaultOutbound != 0 {
		t.Fatalf("routing header = %#v", plan)
	}
	wantOutbounds := []OutboundPlan{
		{Tag: "IPv4_out", Action: "direct", DomainStrategy: "as_is"},
		{Tag: "IPv6_out", Action: "direct", DomainStrategy: "use_ipv6"},
		{Tag: "block", Action: "blackhole", DomainStrategy: "as_is"},
	}
	if !reflect.DeepEqual(plan.Outbounds, wantOutbounds) {
		t.Fatalf("outbounds = %#v, want %#v", plan.Outbounds, wantOutbounds)
	}
	if len(plan.Rules) != 5 {
		t.Fatalf("rules = %d, want 5", len(plan.Rules))
	}
	if got := plan.Rules[0]; got.Outbound != 2 || len(got.CIDRs) != len(privateCIDRs) {
		t.Fatalf("private rule = %#v", got)
	}
	if got := plan.Rules[1]; got.Outbound != 2 || got.Protocols != protocolBitTorrent {
		t.Fatalf("bittorrent rule = %#v", got)
	}
	if protocolBitTorrent != 1 {
		t.Fatalf("serialized bittorrent protocol bit = %d, Rust ABI requires 1", protocolBitTorrent)
	}
	if got := plan.Rules[3]; got.Outbound != 2 || len(got.Ports) == 0 {
		t.Fatalf("port rule = %#v", got)
	}
	if got := plan.Rules[4]; got.Outbound != 0 || got.Networks != networkTCP|networkUDP || !got.NetworkConstraint {
		t.Fatalf("catch-all network rule = %#v", got)
	}
}

func TestCompileRoutingRejectsUnknownAndDuplicateOutbounds(t *testing.T) {
	route := writeRoutingFixture(t, "route.json", `{"rules":[{"outboundTag":"missing","network":"tcp"}]}`)
	if _, err := compileRouting(route, ""); err == nil || !strings.Contains(err.Error(), "unknown outboundTag") {
		t.Fatalf("unknown tag error = %v", err)
	}
	duplicate := writeRoutingFixture(t, "outbounds.json", `[
      {"tag":"direct","protocol":"freedom"},
      {"tag":"direct","protocol":"blackhole"}
    ]`)
	if _, err := compileRouting("", duplicate); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate tag error = %v", err)
	}
}

func TestCompileRoutingFallsBackForUnsupportedSemanticFields(t *testing.T) {
	outbounds := writeRoutingFixture(t, "outbounds.json", `[{"tag":"direct","protocol":"freedom"}]`)
	route := writeRoutingFixture(t, "route.json", `{
      "rules":[{"outboundTag":"direct","domain":["example.com"]}]
    }`)
	if _, err := compileRouting(route, outbounds); !errors.Is(err, ErrLegacyRequired) {
		t.Fatalf("unsupported route field error = %v", err)
	}
	route = writeRoutingFixture(t, "route.json", `{
      "rules":[{"outboundTag":"direct","ip":["geoip:cn"]}]
    }`)
	if _, err := compileRouting(route, outbounds); !errors.Is(err, ErrLegacyRequired) {
		t.Fatalf("unsupported geoip error = %v", err)
	}
}

func TestCompileRoutingRejectsInvalidFilesAndEmptyRules(t *testing.T) {
	t.Run("missing route", func(t *testing.T) {
		_, err := compileRouting(filepath.Join(t.TempDir(), "missing-route.json"), "")
		if err == nil || !strings.Contains(err.Error(), "open") {
			t.Fatalf("missing route error = %v", err)
		}
	})
	t.Run("missing outbound", func(t *testing.T) {
		_, err := compileRouting("", filepath.Join(t.TempDir(), "missing-outbound.json"))
		if err == nil || !strings.Contains(err.Error(), "open") {
			t.Fatalf("missing outbound error = %v", err)
		}
	})
	t.Run("invalid route JSON", func(t *testing.T) {
		route := writeRoutingFixture(t, "route.json", `{"rules":[`)
		if _, err := compileRouting(route, ""); err == nil || !strings.Contains(err.Error(), "parse") {
			t.Fatalf("invalid route error = %v", err)
		}
	})
	t.Run("empty outbound array", func(t *testing.T) {
		outbounds := writeRoutingFixture(t, "outbounds.json", `[]`)
		if _, err := compileRouting("", outbounds); err == nil || !strings.Contains(err.Error(), "contains no outbounds") {
			t.Fatalf("empty outbounds error = %v", err)
		}
	})
	t.Run("unknown outbound protocol", func(t *testing.T) {
		outbounds := writeRoutingFixture(t, "outbounds.json", `[{"tag":"proxy","protocol":"socks"}]`)
		if _, err := compileRouting("", outbounds); !errors.Is(err, ErrLegacyRequired) {
			t.Fatalf("unknown outbound protocol error = %v", err)
		}
	})
	t.Run("unknown outbound field", func(t *testing.T) {
		outbounds := writeRoutingFixture(t, "outbounds.json", `[{"tag":"direct","protocol":"freedom","unexpected":true}]`)
		if _, err := compileRouting("", outbounds); !errors.Is(err, ErrLegacyRequired) {
			t.Fatalf("unknown outbound field error = %v", err)
		}
	})
	t.Run("rule without match condition", func(t *testing.T) {
		route := writeRoutingFixture(t, "route.json", `{"rules":[{"outboundTag":"__fastengine_direct"}]}`)
		if _, err := compileRouting(route, ""); err == nil || !strings.Contains(err.Error(), "no match condition") {
			t.Fatalf("empty routing rule error = %v", err)
		}
	})
}

func TestCompilePortsMergesOnlyEquivalentIntervals(t *testing.T) {
	ranges, err := compilePorts([]byte(`"22,23-25,24,100-200"`))
	if err != nil {
		t.Fatal(err)
	}
	want := []PortRange{{From: 22, To: 25}, {From: 100, To: 200}}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("ranges = %#v, want %#v", ranges, want)
	}
}

func TestDisabledFallbackTemplateDoesNotRejectFastEngine(t *testing.T) {
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	contents = []byte(strings.Replace(string(contents), "DisableSniffing: true", "DisableSniffing: true\n      EnableFallback: false\n      FallBackConfigs:\n        - Dest: 80", 1))
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFastEngine(path); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateCIDRsMatchPackagedPhase8GeoData(t *testing.T) {
	want := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10",
	}
	if !reflect.DeepEqual(privateCIDRs, want) {
		t.Fatalf("private CIDRs changed: %#v", privateCIDRs)
	}
}

func FuzzCompilePortsNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`"22,23-25,443"`),
		[]byte(`65535`),
		[]byte(`"0-65536"`),
		[]byte(`null`),
		[]byte(`{"unexpected":true}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		_, _ = compilePorts(raw)
	})
}

func FuzzCompileCIDRsNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"geoip:private",
		"10.0.0.0/8",
		"2001:db8::/32",
		"127.0.0.1",
		"not-a-prefix",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		_, _ = compileCIDRs([]string{value})
	})
}
