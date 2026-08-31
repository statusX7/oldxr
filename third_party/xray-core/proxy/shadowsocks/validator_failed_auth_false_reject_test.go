package shadowsocks

import (
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func assertNoAdmissionRejects(t *testing.T, validator *Validator) {
	t.Helper()
	if got := validator.authMetrics.snapshot().admissionRejects; got != 0 {
		t.Fatalf("valid authentication was admission-rejected: rejects=%d", got)
	}
}

func TestValidatorFailedAuthValidTopologiesHaveNoFalseRejects(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 1000, 1024)
	sequence := uint64(20000)

	// Unique household sources.
	for index := 0; index < 20; index++ {
		source := sourceCacheTestAddress(t, fmt.Sprintf("198.18.0.%d", index+1))
		authenticateSSUserWithSource(t, validator, users[index], source, sequence)
		sequence++
	}

	// Five users behind each small NAT source.
	for group := 0; group < 4; group++ {
		source := sourceCacheTestAddress(t, fmt.Sprintf("198.18.1.%d", group+1))
		for member := 0; member < 5; member++ {
			index := 20 + group*5 + member
			authenticateSSUserWithSource(t, validator, users[index], source, sequence)
			sequence++
		}
	}

	// Fifty users behind one large CGNAT source. Source hints are bounded, so
	// users outside the MRU set must continue through active/cold verification.
	cgnat := sourceCacheTestAddress(t, "198.18.2.1")
	for index := 40; index < 90; index++ {
		authenticateSSUserWithSource(t, validator, users[index], cgnat, sequence)
		sequence++
	}

	assertNoAdmissionRejects(t, validator)
}

func TestValidatorFailedAuthSourceAndCredentialChangesHaveNoFalseRejects(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	target := users[250]
	oldSource := sourceCacheTestAddress(t, "2001:db8:1::10")
	newSource := sourceCacheTestAddress(t, "2001:db8:2::10")

	authenticateSSUserWithSource(t, validator, target, oldSource, 21000)
	authenticateSSUserWithSource(t, validator, target, newSource, 21001)

	oldWire := benchmarkSSDeterministicTCPAuthWire(t, target, 21002)
	if err := validator.Del(target.Email); err != nil {
		t.Fatal(err)
	}
	replacement := &protocol.MemoryUser{
		Email:   target.Email,
		Account: mustSSBenchmarkAccount(t, "failed-auth-replacement"),
	}
	if err := validator.Add(replacement); err != nil {
		t.Fatal(err)
	}
	authenticateSSUserWithSource(t, validator, replacement, newSource, 21003)
	if got, _, _, _, err := validator.GetWithSource(oldWire, protocol.RequestCommandTCP, newSource); err != ErrNotFound || got != nil {
		t.Fatalf("old credential matched after replacement: got=%v err=%v", got, err)
	}
	assertNoAdmissionRejects(t, validator)
}

func TestValidatorFailedAuthCrossValidatorActiveUserHasNoFalseReject(t *testing.T) {
	processColdScanBudget.resetForTest()
	attacked, _ := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	healthy, healthyUsers := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	target := healthyUsers[250]

	// Promote the healthy-site user into its immutable active prefix before a
	// different validator reaches the process-wide failure cooldown.
	authenticateSSUserWithSource(t, healthy, target, sourceCacheTestAddress(t, "192.0.2.1"), 22000)
	healthy.rebuildHotSnapshot(time.Now())

	for attempt := 0; attempt < defaultGlobalFailureBurst; attempt++ {
		source := sourceCacheTestAddress(t, fmt.Sprintf("203.0.113.%d", attempt+1))
		got, _, _, _, err := attacked.GetWithSource(failedAuthTestWire(t, uint64(22010+attempt)), protocol.RequestCommandTCP, source)
		if err != ErrNotFound || got != nil {
			t.Fatalf("invalid request %d unexpectedly matched: got=%v err=%v", attempt, got, err)
		}
	}

	before := healthy.authMetrics.snapshot()
	authenticateSSUserWithSource(t, healthy, target, sourceCacheTestAddress(t, "192.0.2.200"), 22020)
	after := healthy.authMetrics.snapshot()
	if after.admissionRejects != before.admissionRejects {
		t.Fatalf("active user on another validator was rejected: before=%+v after=%+v", before, after)
	}
}
