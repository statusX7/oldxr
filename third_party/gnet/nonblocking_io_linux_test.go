// Copyright (c) 2019 The Gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func newNonblockingStreamSocketpair(t testing.TB) [2]int {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return fds
}

func TestNonblockingIOPayload(t *testing.T) {
	fds := newNonblockingStreamSocketpair(t)
	payload := bytes.Repeat([]byte{0x5a}, 4096)

	written, err := writeNonblocking(fds[0], payload)
	if err != nil || written != len(payload) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", written, err, len(payload))
	}
	received := make([]byte, len(payload))
	read, err := readNonblocking(fds[1], received)
	if err != nil || read != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("read = (%d, %v), equal=%v", read, err, bytes.Equal(received, payload))
	}
}

func TestReadNonblockingSemantics(t *testing.T) {
	fds := newNonblockingStreamSocketpair(t)
	buffer := make([]byte, 16)

	if read, err := readNonblocking(fds[0], nil); read != 0 || err != nil {
		t.Fatalf("empty read = (%d, %v), want (0, nil)", read, err)
	}
	if read, err := readNonblocking(fds[0], buffer); read != -1 || !(errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)) {
		t.Fatalf("empty socket read = (%d, %v), want (-1, EAGAIN)", read, err)
	}
	if err := unix.Shutdown(fds[1], unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if read, err := readNonblocking(fds[0], buffer); read != 0 || err != nil {
		t.Fatalf("EOF read = (%d, %v), want (0, nil)", read, err)
	}
	if read, err := readNonblocking(-1, buffer); read != -1 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid fd read = (%d, %v), want (-1, EBADF)", read, err)
	}
}

func TestWriteNonblockingSemantics(t *testing.T) {
	fds := newNonblockingStreamSocketpair(t)
	payload := make([]byte, 4096)

	if written, err := writeNonblocking(fds[0], nil); written != 0 || err != nil {
		t.Fatalf("empty write = (%d, %v), want (0, nil)", written, err)
	}
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	for attempts := 0; ; attempts++ {
		if attempts > 1<<16 {
			t.Fatal("nonblocking write never reached EAGAIN")
		}
		_, err := writeNonblocking(fds[0], payload)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if err != nil {
			t.Fatalf("fill send buffer: %v", err)
		}
	}
	if written, err := writeNonblocking(-1, payload); written != -1 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid fd write = (%d, %v), want (-1, EBADF)", written, err)
	}
}

func TestWriteNonblockingClosedPeer(t *testing.T) {
	fds := newNonblockingStreamSocketpair(t)
	if err := unix.Close(fds[1]); err != nil {
		t.Fatal(err)
	}
	fds[1] = -1

	written, err := writeNonblocking(fds[0], make([]byte, 64))
	if written != -1 || err == nil {
		t.Fatalf("closed peer write = (%d, %v), want (-1, error)", written, err)
	}
}

func benchmarkReadEAGAIN(b *testing.B, raw bool) {
	fds := newNonblockingStreamSocketpair(b)
	buffer := make([]byte, 4096)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		var err error
		if raw {
			_, err = readNonblocking(fds[0], buffer)
		} else {
			_, err = unix.Read(fds[0], buffer)
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			b.Fatalf("read error = %v, want EAGAIN", err)
		}
	}
}

func benchmarkWrite(b *testing.B, raw bool) {
	fds := newNonblockingStreamSocketpair(b)
	payload := make([]byte, 4096)
	received := make([]byte, len(payload))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		var (
			written int
			err     error
		)
		if raw {
			written, err = writeNonblocking(fds[0], payload)
		} else {
			written, err = unix.Write(fds[0], payload)
		}
		if err != nil || written != len(payload) {
			b.Fatalf("write = (%d, %v)", written, err)
		}
		read, err := readNonblocking(fds[1], received)
		if err != nil || read != len(received) {
			b.Fatalf("read = (%d, %v)", read, err)
		}
	}
}

func benchmarkWriteEAGAIN(b *testing.B, raw bool) {
	fds := newNonblockingStreamSocketpair(b)
	payload := make([]byte, 4096)
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		b.Fatal(err)
	}
	for attempts := 0; ; attempts++ {
		if attempts > 1<<16 {
			b.Fatal("nonblocking write never reached EAGAIN")
		}
		_, err := unix.Write(fds[0], payload)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if err != nil {
			b.Fatalf("fill send buffer: %v", err)
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		var err error
		if raw {
			_, err = writeNonblocking(fds[0], payload)
		} else {
			_, err = unix.Write(fds[0], payload)
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			b.Fatalf("write error = %v, want EAGAIN", err)
		}
	}
}

func BenchmarkNonblockingUnixReadEAGAIN(b *testing.B) {
	benchmarkReadEAGAIN(b, false)
}

func BenchmarkNonblockingRawReadEAGAIN(b *testing.B) {
	benchmarkReadEAGAIN(b, true)
}

func BenchmarkNonblockingUnixWrite(b *testing.B) {
	benchmarkWrite(b, false)
}

func BenchmarkNonblockingRawWrite(b *testing.B) {
	benchmarkWrite(b, true)
}

func BenchmarkNonblockingUnixWriteEAGAIN(b *testing.B) {
	benchmarkWriteEAGAIN(b, false)
}

func BenchmarkNonblockingRawWriteEAGAIN(b *testing.B) {
	benchmarkWriteEAGAIN(b, true)
}
