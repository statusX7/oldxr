package rule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

func mustRule(t testing.TB, id int, pattern string) api.DetectRule {
	t.Helper()
	rule, err := api.CompileDetectRule(id, pattern)
	if err != nil {
		t.Fatalf("CompileDetectRule(%q): %v", pattern, err)
	}
	return rule
}

func TestUpdateRuleClearsEmptyList(t *testing.T) {
	manager := New()
	if err := manager.UpdateRule("node-1", []api.DetectRule{mustRule(t, -1, `blocked`)}); err != nil {
		t.Fatalf("UpdateRule non-empty: %v", err)
	}
	if !manager.Detect("node-1", "blocked.example", "node-1|user@example.com|42") {
		t.Fatal("non-empty rule did not reject")
	}
	if err := manager.UpdateRule("node-1", nil); err != nil {
		t.Fatalf("UpdateRule empty: %v", err)
	}
	if manager.Detect("node-1", "blocked.example", "node-1|user@example.com|42") {
		t.Fatal("old rule survived an empty update")
	}
	if _, exists := manager.InboundRule.Load("node-1"); exists {
		t.Fatal("empty rule entry was retained")
	}
}

func TestUpdateRulePublishesImmutableSnapshot(t *testing.T) {
	manager := New()
	rules := make([]api.DetectRule, 1, 2)
	rules[0] = mustRule(t, -1, `^blocked$`)
	if err := manager.UpdateRule("node-1", rules); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	rules[0] = mustRule(t, -1, `^changed$`)
	rules = append(rules, mustRule(t, -1, `^also-changed$`))
	if !manager.Detect("node-1", "blocked", "node-1|user@example.com|42") {
		t.Fatal("published rule changed with caller-owned slice")
	}
	if manager.Detect("node-1", "changed", "node-1|user@example.com|42") {
		t.Fatal("caller mutation leaked into published rules")
	}
}

func TestDetectHandlesNilPatternAndMalformedEmail(t *testing.T) {
	manager := New()
	if err := manager.UpdateRule("node-1", []api.DetectRule{{ID: 1, Pattern: nil}}); err != nil {
		t.Fatalf("UpdateRule nil pattern: %v", err)
	}
	if manager.Detect("node-1", "anything", "malformed") {
		t.Fatal("nil pattern rejected traffic")
	}

	if err := manager.UpdateRule("node-1", []api.DetectRule{mustRule(t, 1, `anything`)}); err != nil {
		t.Fatalf("UpdateRule valid: %v", err)
	}
	if !manager.Detect("node-1", "anything", "malformed") {
		t.Fatal("matching rule must reject even when UID cannot be recorded")
	}
	results, err := manager.GetDetectResult("node-1")
	if err != nil {
		t.Fatalf("GetDetectResult: %v", err)
	}
	if len(*results) != 0 {
		t.Fatalf("malformed email produced results: %#v", *results)
	}
}

func TestDetectRecordsLastUIDSegment(t *testing.T) {
	manager := New()
	if err := manager.UpdateRule("node-1", []api.DetectRule{mustRule(t, 9, `blocked`)}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if !manager.Detect("node-1", "blocked.example", "node-1|email|with|separator|42") {
		t.Fatal("rule did not reject")
	}
	results, err := manager.GetDetectResult("node-1")
	if err != nil {
		t.Fatalf("GetDetectResult: %v", err)
	}
	if len(*results) != 1 || (*results)[0].UID != 42 || (*results)[0].RuleID != 9 {
		t.Fatalf("unexpected detect results: %#v", *results)
	}
}

func TestResetDetectResultClearsLegacyNoopReport(t *testing.T) {
	manager := New()
	if err := manager.UpdateRule("node-1", []api.DetectRule{mustRule(t, 9, `blocked`)}); err != nil {
		t.Fatal(err)
	}
	if !manager.Detect("node-1", "blocked.example", "node-1|user@example.com|42") {
		t.Fatal("fixture rule did not match")
	}
	manager.ResetDetectResult("node-1")
	results, err := manager.GetDetectResult("node-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(*results) != 0 {
		t.Fatalf("results after reset: %#v", *results)
	}
}

func TestDetectConcurrentRulePublication(t *testing.T) {
	manager := New()
	first := []api.DetectRule{mustRule(t, -1, `first`)}
	second := []api.DetectRule{mustRule(t, -1, `second`)}
	const iterations = 10_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				_ = manager.UpdateRule("node-1", first)
			} else {
				_ = manager.UpdateRule("node-1", second)
			}
		}
	}()
	for reader := 0; reader < 2; reader++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				_ = manager.Detect("node-1", "first-or-second", "node-1|user@example.com|42")
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestDetectDoesNotReadCallerSliceDuringMutation(t *testing.T) {
	manager := New()
	first := mustRule(t, -1, `first`)
	second := mustRule(t, -1, `second`)
	callerOwned := []api.DetectRule{first}
	if err := manager.UpdateRule("node-1", callerOwned); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	const iterations = 10_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				callerOwned[0] = second
			} else {
				callerOwned[0] = first
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if !manager.Detect("node-1", "first", "node-1|user@example.com|42") {
				t.Errorf("published snapshot changed at iteration %d", i)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}

func BenchmarkRegexpMatch(b *testing.B) {
	destination := "www.blocked.example:443"
	pattern := regexp.MustCompile(`(^|\.)blocked\.example(:\d+)?$`)
	b.Run("bytes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !pattern.Match([]byte(destination)) {
				b.Fatal("pattern did not match")
			}
		}
	})
	b.Run("string", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !pattern.MatchString(destination) {
				b.Fatal("pattern did not match")
			}
		}
	})
}

func BenchmarkManagerDetect(b *testing.B) {
	for _, ruleCount := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("rules=%d", ruleCount), func(b *testing.B) {
			manager := New()
			rules := make([]api.DetectRule, ruleCount)
			for i := range rules {
				rules[i] = mustRule(b, -1, fmt.Sprintf(`^unmatched-%d$`, i))
			}
			rules[len(rules)-1] = mustRule(b, -1, `blocked`)
			if err := manager.UpdateRule("node-1", rules); err != nil {
				b.Fatalf("UpdateRule: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !manager.Detect("node-1", "blocked.example", "node-1|user@example.com|42") {
					b.Fatal("rule did not reject")
				}
			}
		})
	}
}

func BenchmarkRuleUIDParse(b *testing.B) {
	email := "node-1|email|with|separator|42"
	b.Run("split", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			parts := strings.Split(email, "|")
			uid, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil || uid != 42 {
				b.Fatal("unexpected UID")
			}
		}
	})
	b.Run("last-index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			separator := strings.LastIndexByte(email, '|')
			uid, err := strconv.Atoi(email[separator+1:])
			if err != nil || uid != 42 {
				b.Fatal("unexpected UID")
			}
		}
	})
}
