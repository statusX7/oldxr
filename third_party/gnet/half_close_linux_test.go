// Copyright (c) 2026 The gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package gnet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type halfCloseEvents struct {
	BuiltinEventEngine

	response []byte

	mu         sync.Mutex
	request    []byte
	conn       chan Conn
	readClosed chan struct{}
	closed     chan error
	readOnce   sync.Once
	closeOnce  sync.Once
}

type ownerReadControl interface {
	SuspendRead() error
	ResumeRead() error
}

type ownerWriteControl interface {
	TryWrite([]byte) (int, error)
	ArmWrite() error
	DisarmWrite() error
}

type pausedReadEvents struct {
	BuiltinEventEngine

	mu       sync.Mutex
	reads    [][]byte
	paused   chan Conn
	resumed  chan struct{}
	closed   chan error
	pauseOne sync.Once
}

type writableEvents struct {
	BuiltinEventEngine

	pending   []byte
	armed     chan struct{}
	done      chan struct{}
	closed    chan error
	armOnce   sync.Once
	doneOnce  sync.Once
	callbacks int
}

func (h *writableEvents) pump(c Conn) Action {
	controlled, ok := c.(ownerWriteControl)
	if !ok {
		return Close
	}
	for len(h.pending) > 0 {
		n, err := controlled.TryWrite(h.pending)
		if err != nil {
			return Close
		}
		h.pending = h.pending[n:]
		if n == 0 {
			if err := controlled.ArmWrite(); err != nil {
				return Close
			}
			h.armOnce.Do(func() { close(h.armed) })
			return None
		}
	}
	if err := controlled.DisarmWrite(); err != nil {
		return Close
	}
	h.doneOnce.Do(func() { close(h.done) })
	return None
}

func (h *writableEvents) OnOpen(c Conn) ([]byte, Action) {
	return nil, h.pump(c)
}

func (h *writableEvents) OnWritable(c Conn) Action {
	h.callbacks++
	return h.pump(c)
}

func (h *writableEvents) OnClose(_ Conn, err error) Action {
	h.closed <- err
	return None
}

func (h *pausedReadEvents) OnTraffic(c Conn) Action {
	data, err := c.Next(-1)
	if err != nil {
		return Close
	}
	if len(data) == 0 {
		return None
	}
	h.mu.Lock()
	h.reads = append(h.reads, append([]byte(nil), data...))
	readCount := len(h.reads)
	h.mu.Unlock()
	if readCount == 1 {
		controlled, ok := c.(ownerReadControl)
		if !ok || controlled.SuspendRead() != nil {
			return Close
		}
		h.pauseOne.Do(func() { h.paused <- c })
	} else if readCount == 2 {
		close(h.resumed)
	}
	return None
}

func (h *pausedReadEvents) OnClose(_ Conn, err error) Action {
	h.closed <- err
	return None
}

func (h *halfCloseEvents) OnTraffic(c Conn) Action {
	data, err := c.Next(-1)
	if err != nil {
		return Close
	}
	h.mu.Lock()
	h.request = append(h.request, data...)
	h.mu.Unlock()
	return None
}

func (h *halfCloseEvents) OnReadClosed(c Conn) Action {
	h.readOnce.Do(func() { close(h.readClosed) })
	if _, err := c.Write(h.response); err != nil {
		return Close
	}
	h.conn <- c
	return None
}

func (h *halfCloseEvents) OnClose(_ Conn, err error) Action {
	h.closeOnce.Do(func() { h.closed <- err })
	return None
}

func TestClientPreservesWriteHalfAfterReadClose(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	clientConn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close() //nolint:errcheck

	var serverConn *net.TCPConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out accepting TCP connection")
	}

	request := []byte("request-before-half-close")
	response := bytes.Repeat([]byte("half-close-response"), 64)
	events := &halfCloseEvents{
		response:   response,
		conn:       make(chan Conn, 1),
		readClosed: make(chan struct{}),
		closed:     make(chan error, 1),
	}
	gnetClient, err := NewClient(
		events,
		WithNumEventLoop(1),
		WithEdgeTriggeredIO(false),
		WithSocketSendBuffer(4*1024),
		WithReadBufferCap(4*1024),
		WithWriteBufferCap(4*1024),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := gnetClient.Start(); err != nil {
		t.Fatal(err)
	}
	defer gnetClient.Stop() //nolint:errcheck

	if _, err := gnetClient.Enroll(serverConn); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-events.readClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("read-half-close callback did not fire")
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("response mismatch: got %d bytes, want %d", len(got), len(response))
	}

	var owned Conn
	select {
	case owned = <-events.conn:
	case <-time.After(time.Second):
		t.Fatal("owned connection was not published")
	}
	select {
	case err := <-events.closed:
		t.Fatalf("connection closed before the write half was explicitly closed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-events.closed:
		if err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not close")
	}

	events.mu.Lock()
	gotRequest := append([]byte(nil), events.request...)
	events.mu.Unlock()
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("request mismatch: got %q, want %q", gotRequest, request)
	}
}

func TestClientSuspendAndResumeReadInterest(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close() //nolint:errcheck

	var enrolled *net.TCPConn
	select {
	case enrolled = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out accepting TCP connection")
	}

	events := &pausedReadEvents{
		paused:  make(chan Conn, 1),
		resumed: make(chan struct{}),
		closed:  make(chan error, 1),
	}
	client, err := NewClient(events, WithNumEventLoop(1), WithEdgeTriggeredIO(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Stop() //nolint:errcheck

	if _, err := client.Enroll(enrolled); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}

	var owned Conn
	select {
	case owned = <-events.paused:
	case err := <-events.closed:
		t.Fatalf("connection closed while pausing reads: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("read interest was not suspended")
	}
	if _, err := peer.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events.resumed:
		t.Fatal("traffic was delivered while readable interest was suspended")
	case <-time.After(100 * time.Millisecond):
	}

	resumeDone := make(chan error, 1)
	if err := owned.Wake(func(c Conn, err error) error {
		if err == nil {
			controlled, ok := c.(ownerReadControl)
			if !ok {
				err = errors.New("connection does not expose owner read control")
			} else {
				err = controlled.ResumeRead()
			}
		}
		resumeDone <- err
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-resumeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read interest was not resumed")
	}
	select {
	case <-events.resumed:
	case err := <-events.closed:
		t.Fatalf("connection closed after resuming reads: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("queued traffic was not delivered after resuming reads")
	}

	events.mu.Lock()
	defer events.mu.Unlock()
	if len(events.reads) != 2 || string(events.reads[0]) != "first" || string(events.reads[1]) != "second" {
		t.Fatalf("reads = %q, want [first second]", events.reads)
	}
}

func TestClientOwnerWritableCallbackFlushesPartialSocketWrite(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close() //nolint:errcheck

	var enrolled *net.TCPConn
	select {
	case enrolled = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out accepting TCP connection")
	}

	payload := bytes.Repeat([]byte("owner-partial-write"), 128*1024)
	events := &writableEvents{
		pending: append([]byte(nil), payload...),
		armed:   make(chan struct{}),
		done:    make(chan struct{}),
		closed:  make(chan error, 1),
	}
	client, err := NewClient(
		events,
		WithNumEventLoop(1),
		WithEdgeTriggeredIO(false),
		WithSocketSendBuffer(4*1024),
		WithWriteBufferCap(4*1024),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Stop() //nolint:errcheck

	if _, err := client.Enroll(enrolled); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events.armed:
	case err := <-events.closed:
		t.Fatalf("connection closed before writable interest armed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("partial socket write did not arm writable interest")
	}

	readDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		_, err := io.ReadFull(peer, got)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("payload mismatch")
		}
		readDone <- err
	}()
	select {
	case <-events.done:
	case err := <-events.closed:
		t.Fatalf("connection closed during writable flush: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("writable callback did not flush pending bytes")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer did not receive the complete payload")
	}
	if events.callbacks == 0 {
		t.Fatal("owner writable callback was not invoked")
	}
}
