package proxypanel

import (
	"net/http"
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
