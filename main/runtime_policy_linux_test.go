//go:build linux

package main

import "testing"

func TestSelectOwnerGOMAXPROCS(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		owner     bool
		explicit  string
		effective int
		want      int
	}{
		{"owner four CPUs", true, "", 4, 3},
		{"explicit override", true, "4", 4, 0},
		{"owner disabled", false, "", 4, 0},
		{"three CPUs", true, "", 3, 0},
		{"eight CPUs", true, "", 8, 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := selectOwnerGOMAXPROCS(testCase.owner, testCase.explicit, testCase.effective); got != testCase.want {
				t.Fatalf("selectOwnerGOMAXPROCS()=%d, want %d", got, testCase.want)
			}
		})
	}
}

func TestParseCPUQuotaV2(t *testing.T) {
	for _, testCase := range []struct {
		contents string
		quota    int64
		period   int64
		ok       bool
	}{
		{"400000 100000\n", 400000, 100000, true},
		{"150000 100000", 150000, 100000, true},
		{"max 100000", 0, 0, false},
		{"invalid", 0, 0, false},
	} {
		quota, period, ok := parseCPUQuotaV2(testCase.contents)
		if quota != testCase.quota || period != testCase.period || ok != testCase.ok {
			t.Fatalf("parseCPUQuotaV2(%q)=(%d,%d,%v), want (%d,%d,%v)", testCase.contents, quota, period, ok, testCase.quota, testCase.period, testCase.ok)
		}
	}
}
