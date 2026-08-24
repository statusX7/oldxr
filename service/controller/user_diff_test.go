package controller

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

func testRuntimeUser() api.UserInfo {
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

func TestCompareUserListLimitOnlyDoesNotReplaceRuntime(t *testing.T) {
	oldUser := testRuntimeUser()
	newUser := oldUser
	newUser.SpeedLimit *= 2
	newUser.DeviceLimit++
	oldUsers := []api.UserInfo{oldUser}
	newUsers := []api.UserInfo{newUser}

	deleted, added, limitUpdated := compareUserList(&oldUsers, &newUsers)
	if !reflect.DeepEqual(deleted, []api.UserInfo(nil)) || !reflect.DeepEqual(added, []api.UserInfo(nil)) {
		t.Fatalf("limit-only update replaced runtime identity: deleted=%#v added=%#v", deleted, added)
	}
	if !reflect.DeepEqual(limitUpdated, []api.UserInfo{newUser}) {
		t.Fatalf("limit updates = %#v, want %#v", limitUpdated, []api.UserInfo{newUser})
	}
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
		{name: "protocol_param", mutate: func(user *api.UserInfo) { user.ProtocolParam += "-changed" }},
		{name: "obfs", mutate: func(user *api.UserInfo) { user.Obfs = "tls1.2_ticket_auth" }},
		{name: "obfs_param", mutate: func(user *api.UserInfo) { user.ObfsParam += "-changed" }},
		{name: "uuid", mutate: func(user *api.UserInfo) { user.UUID = "22222222-2222-2222-2222-222222222222" }},
		{name: "alter_id", mutate: func(user *api.UserInfo) { user.AlterID++ }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			oldUser := testRuntimeUser()
			newUser := oldUser
			testCase.mutate(&newUser)
			oldUsers := []api.UserInfo{oldUser}
			newUsers := []api.UserInfo{newUser}
			deleted, added, limitUpdated := compareUserList(&oldUsers, &newUsers)
			if !reflect.DeepEqual(deleted, []api.UserInfo{oldUser}) || !reflect.DeepEqual(added, []api.UserInfo{newUser}) || limitUpdated != nil {
				t.Fatalf("unexpected identity diff: deleted=%#v added=%#v limitUpdated=%#v", deleted, added, limitUpdated)
			}
		})
	}
}

func TestCompareUserListAddedDeletedAndUnchanged(t *testing.T) {
	unchanged := testRuntimeUser()
	deletedUser := unchanged
	deletedUser.UID = 2
	deletedUser.Email = "deleted@example.com"
	addedUser := unchanged
	addedUser.UID = 3
	addedUser.Email = "added@example.com"
	oldUsers := []api.UserInfo{unchanged, deletedUser}
	newUsers := []api.UserInfo{unchanged, addedUser}

	deleted, added, limitUpdated := compareUserList(&oldUsers, &newUsers)
	if !reflect.DeepEqual(deleted, []api.UserInfo{deletedUser}) || !reflect.DeepEqual(added, []api.UserInfo{addedUser}) || limitUpdated != nil {
		t.Fatalf("unexpected membership diff: deleted=%#v added=%#v limitUpdated=%#v", deleted, added, limitUpdated)
	}
}

var (
	benchmarkDeletedUsers      []api.UserInfo
	benchmarkAddedUsers        []api.UserInfo
	benchmarkLimitUpdatedUsers []api.UserInfo
)

func benchmarkUserLists(size, churnPercent int) ([]api.UserInfo, []api.UserInfo) {
	oldUsers := make([]api.UserInfo, size)
	newUsers := make([]api.UserInfo, size)
	for index := range oldUsers {
		user := api.UserInfo{
			UID:         index + 1,
			Email:       fmt.Sprintf("user-%d@example.com", index+1),
			Passwd:      fmt.Sprintf("password-%d", index+1),
			SpeedLimit:  uint64(index%10+1) * 125_000,
			DeviceLimit: index%5 + 1,
			UUID:        fmt.Sprintf("00000000-0000-0000-0000-%012d", index+1),
		}
		oldUsers[index] = user
		newUsers[index] = user
	}
	changed := size * churnPercent / 100
	for index := 0; index < changed; index++ {
		newUsers[index].UUID += "-changed"
	}
	return oldUsers, newUsers
}

func BenchmarkCompareUserList(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 50_000} {
		for _, churn := range []int{0, 1} {
			oldUsers, newUsers := benchmarkUserLists(size, churn)
			b.Run(fmt.Sprintf("users_%d/churn_%d_percent", size, churn), func(b *testing.B) {
				b.ReportAllocs()
				for iteration := 0; iteration < b.N; iteration++ {
					benchmarkDeletedUsers, benchmarkAddedUsers, benchmarkLimitUpdatedUsers = compareUserList(&oldUsers, &newUsers)
				}
			})
		}
	}
}
