package shadowsocks

import (
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func failedAuthTestWire(tb testing.TB, sequence uint64) []byte {
	tb.Helper()
	wrongUser := &protocol.MemoryUser{Account: mustSSBenchmarkAccount(tb, fmt.Sprintf("failed-auth-%d", sequence))}
	return benchmarkSSDeterministicTCPAuthWire(tb, wrongUser, sequence)
}

func TestValidatorFailedAuthSingleSourceAndColdProbation(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	validator.sourceFailureCooldown = 10 * time.Millisecond
	source := sourceCacheTestAddress(t, "198.51.100.120")
	authenticateSSUserWithSource(t, validator, users[10], source, 9000)

	for attempt := 0; attempt < defaultSourceFailureBurst; attempt++ {
		got, _, _, _, err := validator.GetWithSource(failedAuthTestWire(t, uint64(9010+attempt)), protocol.RequestCommandTCP, source)
		if err != ErrNotFound || got != nil {
			t.Fatalf("invalid attempt %d unexpectedly matched: got=%v err=%v", attempt, got, err)
		}
	}
	beforeReject := validator.authMetrics.snapshot()
	got, _, _, _, err := validator.GetWithSource(failedAuthTestWire(t, 9020), protocol.RequestCommandTCP, source)
	if err != ErrNotFound || got != nil {
		t.Fatalf("admission-rejected request unexpectedly matched: got=%v err=%v", got, err)
	}
	afterReject := validator.authMetrics.snapshot()
	if afterReject.coldScans != beforeReject.coldScans || afterReject.admissionRejects != beforeReject.admissionRejects+1 {
		t.Fatalf("source admission metrics: before=%+v after=%+v", beforeReject, afterReject)
	}

	// A previously authenticated user is still tried before admission.
	authenticateSSUserWithSource(t, validator, users[10], source, 9021)

	// A cold user may be delayed, but the bounded cooldown is not permanent.
	coldWire := benchmarkSSDeterministicTCPAuthWire(t, users[250], 9022)
	if got, _, _, _, err := validator.GetWithSource(coldWire, protocol.RequestCommandTCP, source); err != ErrNotFound || got != nil {
		t.Fatalf("cold user should be temporarily admission-rejected: got=%v err=%v", got, err)
	}
	time.Sleep(15 * time.Millisecond)
	got, _, _, _, err = validator.GetWithSource(coldWire, protocol.RequestCommandTCP, source)
	if err != nil || got != users[250] {
		t.Fatalf("cold user did not recover after cooldown: got=%v err=%v", got, err)
	}
}

func TestValidatorFailedAuthRotatingSourcesAndHotBypass(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	hotUser := users[250]
	authenticateSSUserWithSource(t, validator, hotUser, sourceCacheTestAddress(t, "192.0.2.1"), 9100)
	validator.rebuildHotSnapshot(time.Now())

	for attempt := 0; attempt < defaultGlobalFailureBurst; attempt++ {
		source := sourceCacheTestAddress(t, fmt.Sprintf("192.0.2.%d", attempt+10))
		got, _, _, _, err := validator.GetWithSource(failedAuthTestWire(t, uint64(9110+attempt)), protocol.RequestCommandTCP, source)
		if err != ErrNotFound || got != nil {
			t.Fatalf("rotating invalid attempt %d unexpectedly matched: got=%v err=%v", attempt, got, err)
		}
	}
	metrics := validator.authMetrics.snapshot()
	source := sourceCacheTestAddress(t, "192.0.2.100")
	got, _, _, _, err := validator.GetWithSource(failedAuthTestWire(t, 9200), protocol.RequestCommandTCP, source)
	if err != ErrNotFound || got != nil {
		t.Fatalf("global admission request unexpectedly matched: got=%v err=%v", got, err)
	}
	afterReject := validator.authMetrics.snapshot()
	if afterReject.coldScans != metrics.coldScans || afterReject.admissionRejects != metrics.admissionRejects+1 {
		t.Fatalf("global admission metrics: before=%+v after=%+v", metrics, afterReject)
	}

	// Global-active users are authenticated before the shared resource gate.
	authenticateSSUserWithSource(t, validator, hotUser, source, 9201)
}

func TestValidatorFailedAuthColdStartAcceptsFirstWave(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 1000, 1024)
	for index, user := range users {
		source := sourceCacheTestAddress(t, fmt.Sprintf("198.18.%d.%d", index/256, index%256))
		authenticateSSUserWithSource(t, validator, user, source, uint64(9300+index))
	}
	metrics := validator.authMetrics.snapshot()
	if metrics.admissionRejects != 0 || metrics.coldScans != uint64(len(users)) {
		t.Fatalf("cold-start metrics: got=%+v want coldScans=%d rejects=0", metrics, len(users))
	}
}

func TestValidatorFailedAuthCGNATActiveUsersBypassPenalty(t *testing.T) {
	processColdScanBudget.resetForTest()
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 128)
	snapshot := validator.authSnapshot.Load()
	for _, user := range users[:50] {
		snapshot.counters[user].successes.Add(1)
	}
	validator.rebuildHotSnapshot(time.Now())
	source := sourceCacheTestAddress(t, "203.0.113.200")
	for attempt := 0; attempt < defaultSourceFailureBurst; attempt++ {
		got, _, _, _, err := validator.GetWithSource(failedAuthTestWire(t, uint64(10400+attempt)), protocol.RequestCommandTCP, source)
		if err != ErrNotFound || got != nil {
			t.Fatalf("CGNAT invalid attempt %d unexpectedly matched: got=%v err=%v", attempt, got, err)
		}
	}
	before := validator.authMetrics.snapshot()
	for index, user := range users[:50] {
		authenticateSSUserWithSource(t, validator, user, source, uint64(10500+index))
	}
	after := validator.authMetrics.snapshot()
	if after.admissionRejects != before.admissionRejects {
		t.Fatalf("CGNAT active users were admission-rejected: before=%+v after=%+v", before, after)
	}
}
