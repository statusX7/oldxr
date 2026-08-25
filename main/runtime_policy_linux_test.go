//go:build linux

package main

import "testing"

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
