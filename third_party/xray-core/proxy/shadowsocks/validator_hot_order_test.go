package shadowsocks

import (
	"crypto/cipher"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func assertHotSnapshotUnique(t *testing.T, validator *Validator, wantUsers int) *authSnapshot {
	t.Helper()
	snapshot := validator.authSnapshot.Load()
	if snapshot == nil {
		t.Fatal("authentication snapshot is nil")
	}
	if len(snapshot.ordered) != wantUsers {
		t.Fatalf("snapshot user count: got=%d want=%d", len(snapshot.ordered), wantUsers)
	}
	seen := make(map[*protocol.MemoryUser]struct{}, len(snapshot.ordered))
	for _, user := range snapshot.ordered {
		if _, found := seen[user]; found {
			t.Fatalf("user %q occurs more than once", user.Email)
		}
		seen[user] = struct{}{}
	}
	return snapshot
}

func authenticateSSUser(t *testing.T, validator *Validator, user *protocol.MemoryUser, sequence uint64) {
	t.Helper()
	wire := benchmarkSSDeterministicTCPAuthWire(t, user, sequence)
	got, _, _, _, err := validator.Get(wire, protocol.RequestCommandTCP)
	if err != nil || got != user {
		t.Fatalf("authenticate %q: got=%v err=%v", user.Email, got, err)
	}
}

func TestValidatorHotOrderingAndFullFallback(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 1000, 32)
	for i := 0; i < 9; i++ {
		authenticateSSUser(t, validator, users[900], uint64(i))
	}
	for i := 0; i < 3; i++ {
		authenticateSSUser(t, validator, users[800], uint64(100+i))
	}
	validator.rebuildHotSnapshot(time.Now())

	snapshot := assertHotSnapshotUnique(t, validator, len(users))
	if snapshot.hotCount != 2 {
		t.Fatalf("hot count: got=%d want=2", snapshot.hotCount)
	}
	if snapshot.ordered[0] != users[900] || snapshot.ordered[1] != users[800] {
		t.Fatalf("unexpected hot order: %q, %q", snapshot.ordered[0].Email, snapshot.ordered[1].Email)
	}

	attempts := 0
	for _, user := range users {
		aeadCipher := user.Account.(*MemoryAccount).Cipher.(*AEADCipher)
		creator := aeadCipher.AEADAuthCreator
		aeadCipher.AEADAuthCreator = func(key []byte) cipher.AEAD {
			attempts++
			return creator(key)
		}
	}
	hotWire := benchmarkSSDeterministicTCPAuthWire(t, users[900], 1000)
	attempts = 0
	got, _, _, _, err := validator.Get(hotWire, protocol.RequestCommandTCP)
	if err != nil || got != users[900] {
		t.Fatalf("hot authentication: got=%v err=%v", got, err)
	}
	if attempts != 1 {
		t.Fatalf("hot user attempts: got=%d want=1", attempts)
	}
	coldWire := benchmarkSSDeterministicTCPAuthWire(t, users[0], 1001)
	attempts = 0
	got, _, _, _, err = validator.Get(coldWire, protocol.RequestCommandTCP)
	if err != nil || got != users[0] {
		t.Fatalf("cold authentication: got=%v err=%v", got, err)
	}
	if attempts != 3 {
		t.Fatalf("cold fallback attempts: got=%d want=3", attempts)
	}
	invalid := benchmarkSSDeterministicTCPAuthWire(t, &protocol.MemoryUser{Account: mustSSBenchmarkAccount(t, "hot-invalid")}, 1002)
	attempts = 0
	got, _, _, _, err = validator.Get(invalid, protocol.RequestCommandTCP)
	if err != ErrNotFound || got != nil {
		t.Fatalf("invalid request unexpectedly matched: user=%v err=%v", got, err)
	}
	if attempts != len(users) {
		t.Fatalf("invalid attempts: got=%d want=%d", attempts, len(users))
	}
}

func mustSSBenchmarkAccount(t testing.TB, password string) protocol.Account {
	t.Helper()
	account, err := (&Account{Password: password, CipherType: CipherType_AES_128_GCM}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func TestValidatorHotOrderingOnlyCountsSuccessfulReplayCheck(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 32)
	replayAccount, err := (&Account{
		Password:   "hot-replay-user",
		CipherType: CipherType_AES_128_GCM,
		IvCheck:    true,
	}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Del(users[250].Email); err != nil {
		t.Fatal(err)
	}
	replayUser := &protocol.MemoryUser{Email: users[250].Email, Account: replayAccount}
	if err := validator.Add(replayUser); err != nil {
		t.Fatal(err)
	}

	wire := benchmarkSSDeterministicTCPAuthWire(t, replayUser, 4000)
	got, _, _, _, err := validator.Get(wire, protocol.RequestCommandTCP)
	if err != nil || got != replayUser {
		t.Fatalf("first authentication: got=%v err=%v", got, err)
	}
	snapshot := validator.authSnapshot.Load()
	counter := snapshot.counters[replayUser]
	if got := counter.successes.Load(); got != 1 {
		t.Fatalf("success count after first authentication: got=%d want=1", got)
	}
	got, _, _, _, err = validator.Get(wire, protocol.RequestCommandTCP)
	if err != ErrIVNotUnique || got != replayUser {
		t.Fatalf("replayed authentication: got=%v err=%v", got, err)
	}
	if got := counter.successes.Load(); got != 1 {
		t.Fatalf("replay changed success count: got=%d want=1", got)
	}
}

func TestValidatorHotOrderingUserLifecycle(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 32)
	target := users[275]
	oldWire := benchmarkSSDeterministicTCPAuthWire(t, target, 5000)
	authenticateSSUser(t, validator, target, 5001)
	validator.rebuildHotSnapshot(time.Now())
	if validator.authSnapshot.Load().ordered[0] != target {
		t.Fatal("target was not promoted")
	}
	if err := validator.Del(target.Email); err != nil {
		t.Fatal(err)
	}
	snapshot := assertHotSnapshotUnique(t, validator, 299)
	for _, user := range snapshot.ordered {
		if user == target {
			t.Fatal("deleted user remains in snapshot")
		}
	}
	if got, _, _, _, err := validator.Get(oldWire, protocol.RequestCommandTCP); err != ErrNotFound || got != nil {
		t.Fatalf("old credential remained valid: user=%v err=%v", got, err)
	}

	replacement := &protocol.MemoryUser{
		Email:   target.Email,
		Account: mustSSBenchmarkAccount(t, "replacement-password"),
	}
	if err := validator.Add(replacement); err != nil {
		t.Fatal(err)
	}
	snapshot = assertHotSnapshotUnique(t, validator, 300)
	if snapshot.ordered[len(snapshot.ordered)-1] != replacement {
		t.Fatal("new credential did not enter cold remainder")
	}
	authenticateSSUser(t, validator, replacement, 5002)
	if got, _, _, _, err := validator.Get(oldWire, protocol.RequestCommandTCP); err != ErrNotFound || got != nil {
		t.Fatalf("old credential matched after replacement: user=%v err=%v", got, err)
	}
}

func TestValidatorHotOrderingDecay(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 32)
	authenticateSSUser(t, validator, users[299], 6000)
	validator.rebuildHotSnapshot(time.Now())
	if snapshot := validator.authSnapshot.Load(); snapshot.hotCount != 1 || snapshot.ordered[0] != users[299] {
		t.Fatal("initial hot snapshot mismatch")
	}
	validator.rebuildHotSnapshot(time.Now().Add(defaultHotUserRebuildInterval))
	snapshot := validator.authSnapshot.Load()
	if snapshot.hotCount != 0 {
		t.Fatalf("inactive hot user did not decay: hotCount=%d", snapshot.hotCount)
	}
	if snapshot.ordered[0] != users[0] {
		t.Fatal("cold order was not restored after decay")
	}
}

func TestValidatorHotOrderingUDP(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 32)
	wire := benchmarkSSUDPWire(t, users[250])
	got, _, _, _, err := validator.Get(wire, protocol.RequestCommandUDP)
	if err != nil || got != users[250] {
		t.Fatalf("UDP authentication: got=%v err=%v", got, err)
	}
	validator.rebuildHotSnapshot(time.Now())
	if validator.authSnapshot.Load().ordered[0] != users[250] {
		t.Fatal("successful UDP user was not promoted")
	}
}

func TestValidatorHotOrderingConcurrentUpdate(t *testing.T) {
	validator, users := benchmarkSSUsersWithHotCapacity(t, 300, 32)
	wire := benchmarkSSDeterministicTCPAuthWire(t, users[0], 7000)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 100; i++ {
				got, _, _, _, err := validator.Get(wire, protocol.RequestCommandTCP)
				if err != nil || got != users[0] {
					t.Errorf("concurrent authentication: got=%v err=%v", got, err)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		user := &protocol.MemoryUser{
			Email:   fmt.Sprintf("hot-concurrent-%d@example.invalid", i),
			Account: mustSSBenchmarkAccount(t, fmt.Sprintf("hot-concurrent-%d", i)),
		}
		if err := validator.Add(user); err != nil {
			t.Fatal(err)
		}
		if err := validator.Del(user.Email); err != nil {
			t.Fatal(err)
		}
		validator.rebuildHotSnapshot(time.Now())
	}
	workers.Wait()
	assertHotSnapshotUnique(t, validator, 300)
}

func TestValidatorSmallPopulationKeepsLegacyPath(t *testing.T) {
	validator, _ := benchmarkSSUsersWithHotCapacity(t, hotUserMinimumPopulation-1, 32)
	if snapshot := validator.authSnapshot.Load(); snapshot != nil {
		t.Fatalf("small population unexpectedly enabled hot snapshot: users=%d", len(snapshot.ordered))
	}
}

func TestValidatorActiveSnapshotDefaults(t *testing.T) {
	validator := new(Validator)
	if got := validator.effectiveHotCapacity(); got != 1024 {
		t.Fatalf("default active-user capacity: got=%d want=1024", got)
	}
	if got := validator.effectiveHotRebuildInterval(); got != 15*time.Second {
		t.Fatalf("default active-user rebuild interval: got=%s want=15s", got)
	}
}
