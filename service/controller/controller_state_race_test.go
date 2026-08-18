package controller

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XrayR-project/XrayR/api"
)

func TestControllerStateSnapshotConcurrentPublication(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "initial@example.com"}}
	c := &Controller{
		config: &Config{ListenIP: "127.0.0.1"},
	}
	c.publishState(controllerSnapshot{
		clientInfo: api.ClientInfo{APIHost: "http://panel.example"},
		nodeInfo:   &api.NodeInfo{NodeID: 1, NodeType: "V2ray", Port: 443},
		tag:        "V2ray_127.0.0.1_443",
		userList:   &users,
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10_000; i++ {
			nextUsers := []api.UserInfo{{UID: i + 2, Email: strconv.Itoa(i) + "@example.com"}}
			c.publishState(controllerSnapshot{
				clientInfo: api.ClientInfo{APIHost: "http://panel.example"},
				nodeInfo:   &api.NodeInfo{NodeID: i + 2, NodeType: "V2ray", Port: uint32(i + 1)},
				tag:        "V2ray_127.0.0.1_" + strconv.Itoa(i+1),
				userList:   &nextUsers,
			})
		}
	}()

	for reader := 0; reader < 2; reader++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 10_000; i++ {
				state := c.snapshot()
				if state.nodeInfo == nil || state.userList == nil {
					t.Errorf("published an incomplete snapshot: %#v", state)
					return
				}
				wantTag := fmt.Sprintf("V2ray_127.0.0.1_%d", state.nodeInfo.Port)
				if state.tag != wantTag {
					t.Errorf("inconsistent tag %q, want %q", state.tag, wantTag)
					return
				}
				if state.nodeInfo.NodeID != (*state.userList)[0].UID {
					t.Errorf("inconsistent node/user snapshot: node=%d user=%d", state.nodeInfo.NodeID, (*state.userList)[0].UID)
					return
				}
				_ = c.logPrefix()
				_ = c.buildUserTag(&api.UserInfo{UID: i, Email: "reader@example.com"})
				_ = c.buildNodeTag()
			}
		}()
	}

	close(start)
	wg.Wait()
}

func TestControllerCloseWaitsForInFlightTask(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	c := &Controller{
		tasks: []periodicTask{{
			tag:      "slow monitor",
			interval: time.Hour,
			execute: func() error {
				if atomic.AddInt32(&calls, 1) == 1 {
					close(started)
				}
				<-release
				return nil
			},
		}},
	}
	if err := c.startPeriodicTasks(); err != nil {
		t.Fatalf("startPeriodicTasks: %v", err)
	}
	<-started

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the in-flight task completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for the task to exit")
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("task executed %d times after cancellation, want 1", got)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func BenchmarkControllerStateSnapshot(b *testing.B) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	c := &Controller{}
	c.publishState(controllerSnapshot{
		clientInfo: api.ClientInfo{APIHost: "http://panel.example"},
		nodeInfo:   &api.NodeInfo{NodeID: 1, NodeType: "V2ray", Port: 443},
		tag:        "V2ray_127.0.0.1_443",
		userList:   &users,
	})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			state := c.snapshot()
			if state.nodeInfo == nil {
				b.Fatal("missing node info")
			}
		}
	})
}
