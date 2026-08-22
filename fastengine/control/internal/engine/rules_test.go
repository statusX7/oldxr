package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRulesExactAndRegexp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("blocked.example\nregexp:^bad-[0-9]+\\.example$\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"blocked.example", "BLOCKED.EXAMPLE.", "bad-42.example"} {
		if !rules.Blocked(host) {
			t.Fatalf("%q was not blocked", host)
		}
	}
	if rules.Blocked("allowed.example") {
		t.Fatal("allowed host was blocked")
	}
}
