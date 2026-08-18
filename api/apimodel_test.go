package api

import "testing"

func TestCompileDetectRule(t *testing.T) {
	rule, err := CompileDetectRule(7, `^blocked\.example$`)
	if err != nil {
		t.Fatalf("CompileDetectRule valid pattern: %v", err)
	}
	if rule.ID != 7 || !rule.Pattern.MatchString("blocked.example") {
		t.Fatalf("unexpected compiled rule: %#v", rule)
	}
	if _, err := CompileDetectRule(8, `[`); err == nil {
		t.Fatal("invalid regexp must return an error")
	}
}
