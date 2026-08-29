//go:build linux

package owner

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendmsgNonblockingRaw is only valid for an owner-controlled nonblocking
// socket. MSG_DONTWAIT makes that precondition explicit so the raw syscall
// cannot pin a P while waiting for socket capacity.
func sendmsgNonblockingRaw(fd int, payload []byte, flags int) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}

	iov := unix.Iovec{Base: &payload[0]}
	iov.SetLen(len(payload))
	msg := unix.Msghdr{Iov: &iov}
	msg.SetIovlen(1)

	written, _, errno := unix.RawSyscall(
		unix.SYS_SENDMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msg)),
		uintptr(flags|unix.MSG_DONTWAIT),
	)
	runtime.KeepAlive(payload)
	runtime.KeepAlive(&iov)
	runtime.KeepAlive(&msg)
	if errno != 0 {
		return 0, errno
	}
	return int(written), nil
}
