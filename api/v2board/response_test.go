package v2board

import (
	"net/http"
	"os"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestParseResponseRejectsHTTP400(t *testing.T) {
	client := &APIClient{APIHost: "http://panel.example"}
	response := &resty.Response{RawResponse: &http.Response{StatusCode: http.StatusBadRequest}}
	if _, err := client.parseResponse(response, "/test", nil); err == nil {
		t.Fatal("HTTP 400 was accepted as a successful response")
	}
}

func TestReadLocalRuleListSkipsInvalidRegexp(t *testing.T) {
	path := t.TempDir() + "/rules.list"
	if err := os.WriteFile(path, []byte("[\n^allowed$\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rules := readLocalRuleList(path)
	if len(rules) != 1 || !rules[0].Pattern.MatchString("allowed") {
		t.Fatalf("unexpected local rules: %#v", rules)
	}
}
