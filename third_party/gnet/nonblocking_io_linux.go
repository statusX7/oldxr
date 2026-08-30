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

//go:build linux && !race

package gnet

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readNonblocking is only used with sockets owned by a gnet event loop. Those
// sockets are created with SOCK_NONBLOCK, so the raw syscall cannot pin a P
// while waiting for input.
func readNonblocking(fd int, payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}

	read, _, errno := unix.RawSyscall(
		unix.SYS_READ,
		uintptr(fd),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
	)
	runtime.KeepAlive(payload)
	if errno != 0 {
		return int(read), errno
	}
	return int(read), nil
}

// writeNonblocking is only used with sockets owned by a gnet event loop. Those
// sockets are created with SOCK_NONBLOCK, so the raw syscall cannot pin a P
// while waiting for output. SYS_WRITE preserves the existing unix.Write
// operation and its Go runtime SIGPIPE handling.
func writeNonblocking(fd int, payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}

	written, _, errno := unix.RawSyscall(
		unix.SYS_WRITE,
		uintptr(fd),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
	)
	runtime.KeepAlive(payload)
	if errno != 0 {
		return int(written), errno
	}
	return int(written), nil
}
