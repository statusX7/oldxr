package newV2board

import "testing"

func TestReadLocalRuleListMissingFileDoesNotPanic(t *testing.T) {
	if rules := readLocalRuleList(t.TempDir() + "/missing.list"); len(rules) != 0 {
		t.Fatalf("missing file returned rules: %#v", rules)
	}
}
