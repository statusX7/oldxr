//go:build linux

package owner

import "testing"

func TestHybridOwnerSelectionIsInterleavedAndBounded(t *testing.T) {
	gnetCount := 0
	for sequence := uint64(0); sequence < 500; sequence++ {
		got := hybridUsesGnet(sequence)
		want := sequence%hybridOwnerStride == 0
		if got != want {
			t.Fatalf("hybridUsesGnet(%d) = %v, want %v", sequence, got, want)
		}
		if got {
			gnetCount++
		}
	}
	if gnetCount != 100 {
		t.Fatalf("gnet assignments = %d, want 100", gnetCount)
	}
}
