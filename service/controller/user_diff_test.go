package controller

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

func baseUser() api.UserInfo {
	return api.UserInfo{
		UID:           1,
		Email:         "user@example.com",
		Passwd:        "password",
		Port:          8388,
		Method:        "aes-128-gcm",
		SpeedLimit:    125_000,
		DeviceLimit:   2,
		Protocol:      "auth_aes128_md5",
		ProtocolParam: "protocol-param",
		Obfs:          "http_simple",
		ObfsParam:     "obfs-param",
		UUID:          "11111111-1111-1111-1111-111111111111",
		AlterID:       4,
	}
}

func assertUserDiff(t *testing.T, oldUsers, newUsers, wantDeleted, wantAdded, wantLimitUpdated []api.UserInfo) {
	t.Helper()
	deleted, added, limitUpdated := compareUserList(&oldUsers, &newUsers)
	if !reflect.DeepEqual(deleted, wantDeleted) {
		t.Fatalf("deleted = %#v, want %#v", deleted, wantDeleted)
	}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Fatalf("added = %#v, want %#v", added, wantAdded)
	}
	if !reflect.DeepEqual(limitUpdated, wantLimitUpdated) {
		t.Fatalf("limitUpdated = %#v, want %#v", limitUpdated, wantLimitUpdated)
	}
}

func TestCompareUserListNoChange(t *testing.T) {
	user := baseUser()
	assertUserDiff(t, []api.UserInfo{user}, []api.UserInfo{user}, nil, nil, nil)
}

func TestCompareUserListAddedAndDeleted(t *testing.T) {
	deletedUser := baseUser()
	addedUser := deletedUser
	addedUser.UID = 2
	addedUser.Email = "new@example.com"
	assertUserDiff(
		t,
		[]api.UserInfo{deletedUser},
		[]api.UserInfo{addedUser},
		[]api.UserInfo{deletedUser},
		[]api.UserInfo{addedUser},
		nil,
	)
}

func TestCompareUserListReplacesRuntimeIdentityChanges(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*api.UserInfo)
	}{
		{name: "email", mutate: func(user *api.UserInfo) { user.Email = "changed@example.com" }},
		{name: "password", mutate: func(user *api.UserInfo) { user.Passwd = "changed-password" }},
		{name: "port", mutate: func(user *api.UserInfo) { user.Port++ }},
		{name: "method", mutate: func(user *api.UserInfo) { user.Method = "aes-256-gcm" }},
		{name: "protocol", mutate: func(user *api.UserInfo) { user.Protocol = "origin" }},
		{name: "protocol_param", mutate: func(user *api.UserInfo) { user.ProtocolParam = "changed-protocol-param" }},
		{name: "obfs", mutate: func(user *api.UserInfo) { user.Obfs = "tls1.2_ticket_auth" }},
		{name: "obfs_param", mutate: func(user *api.UserInfo) { user.ObfsParam = "changed-obfs-param" }},
		{name: "uuid", mutate: func(user *api.UserInfo) { user.UUID = "22222222-2222-2222-2222-222222222222" }},
		{name: "alter_id", mutate: func(user *api.UserInfo) { user.AlterID++ }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			oldUser := baseUser()
			newUser := oldUser
			testCase.mutate(&newUser)
			assertUserDiff(
				t,
				[]api.UserInfo{oldUser},
				[]api.UserInfo{newUser},
				[]api.UserInfo{oldUser},
				[]api.UserInfo{newUser},
				nil,
			)
		})
	}
}

func TestCompareUserListUpdatesLimitsWithoutRuntimeReplacement(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*api.UserInfo)
	}{
		{name: "speed_limit", mutate: func(user *api.UserInfo) { user.SpeedLimit *= 2 }},
		{name: "device_limit", mutate: func(user *api.UserInfo) { user.DeviceLimit++ }},
		{name: "both_limits", mutate: func(user *api.UserInfo) {
			user.SpeedLimit *= 2
			user.DeviceLimit++
		}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			oldUser := baseUser()
			newUser := oldUser
			testCase.mutate(&newUser)
			assertUserDiff(
				t,
				[]api.UserInfo{oldUser},
				[]api.UserInfo{newUser},
				nil,
				nil,
				[]api.UserInfo{newUser},
			)
		})
	}
}

func TestCompareUserListIdentityAndLimitChangeUsesReplacement(t *testing.T) {
	oldUser := baseUser()
	newUser := oldUser
	newUser.UUID = "22222222-2222-2222-2222-222222222222"
	newUser.SpeedLimit *= 2
	newUser.DeviceLimit++
	assertUserDiff(
		t,
		[]api.UserInfo{oldUser},
		[]api.UserInfo{newUser},
		[]api.UserInfo{oldUser},
		[]api.UserInfo{newUser},
		nil,
	)
}

func TestCompareUserListOnePercentMixedChurn(t *testing.T) {
	oldUsers, newUsers := benchmarkUserLists(1_000, 0)
	for i := 0; i < 10; i++ {
		newUsers[i].UUID += "-changed"
	}
	for i := 10; i < 20; i++ {
		newUsers[i].SpeedLimit++
	}

	deleted, added, limitUpdated := compareUserList(&oldUsers, &newUsers)
	if len(deleted) != 10 || len(added) != 10 || len(limitUpdated) != 10 {
		t.Fatalf("unexpected churn: deleted=%d added=%d limitUpdated=%d", len(deleted), len(added), len(limitUpdated))
	}
}

var (
	benchmarkDeletedUsers      []api.UserInfo
	benchmarkAddedUsers        []api.UserInfo
	benchmarkLimitUpdatedUsers []api.UserInfo
)

func benchmarkUserLists(size int, churnPercent int) ([]api.UserInfo, []api.UserInfo) {
	oldUsers := make([]api.UserInfo, size)
	newUsers := make([]api.UserInfo, size)
	for i := 0; i < size; i++ {
		user := api.UserInfo{
			UID:         i + 1,
			Email:       fmt.Sprintf("user-%d@example.com", i+1),
			UUID:        fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1),
			Passwd:      fmt.Sprintf("password-%d", i+1),
			SpeedLimit:  uint64((i%10)+1) * 125_000,
			DeviceLimit: (i % 5) + 1,
		}
		oldUsers[i] = user
		newUsers[i] = user
	}

	changed := size * churnPercent / 100
	for i := 0; i < changed; i++ {
		newUsers[i].UUID += "-changed"
	}
	return oldUsers, newUsers
}

func BenchmarkCompareUserList(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 50_000} {
		for _, churn := range []int{0, 1} {
			oldUsers, newUsers := benchmarkUserLists(size, churn)
			name := fmt.Sprintf("users_%d/churn_%d_percent", size, churn)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchmarkDeletedUsers, benchmarkAddedUsers, benchmarkLimitUpdatedUsers = compareUserList(&oldUsers, &newUsers)
				}
			})
		}
	}
}
