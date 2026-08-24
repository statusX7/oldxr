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
				return c.runMonitor(func() error {
					close(started)
					<-release
					return nil
				})
			},
		},
	}}

	startDone := make(chan error, 1)
	c.taskStartWG.Add(1)
	go func() {
		defer c.taskStartWG.Done()
		startDone <- c.tasks[0].Start()
	}()
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

func TestControllerCloseRejectsLateMonitor(t *testing.T) {
	c := &Controller{}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	ran := false
	if err := c.runMonitor(func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("monitor executed after Close returned")
	}
}
