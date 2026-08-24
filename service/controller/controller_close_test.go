package controller

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

func TestControllerCloseWaitsForInFlightMonitor(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	c := &Controller{}
	c.tasks = []periodicTask{{
		tag: "blocked monitor",
		Periodic: &task.Periodic{
			Interval: time.Hour,
			Execute: func() error {
				c.monitorMu.Lock()
				defer c.monitorMu.Unlock()
				close(started)
				<-release
				return nil
			},
		},
	}}

	startDone := make(chan error, 1)
	go func() { startDone <- c.tasks[0].Start() }()
	<-started

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while a monitor was still running: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the monitor completed")
	}
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
}
