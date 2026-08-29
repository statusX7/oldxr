package owner

import "testing"

func TestEnabledDefaultsOnAndHonorsExplicitDisable(t *testing.T) {
	for _, testCase := range []struct {
		value string
		want  bool
	}{
		{"", true},
		{"1", true},
		{"true", true},
		{"on", true},
		{"0", false},
		{"false", false},
		{"off", false},
	} {
		t.Run(testCase.value, func(t *testing.T) {
			t.Setenv("XRAYR_SOCKET_OWNER", testCase.value)
			if got := Enabled(); got != testCase.want {
				t.Fatalf("Enabled()=%v, want %v", got, testCase.want)
			}
		})
	}
}
