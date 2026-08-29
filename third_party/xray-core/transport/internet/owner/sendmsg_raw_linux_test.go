//go:build linux

package owner

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func newNonblockingDatagramSocketpair(t testing.TB) [2]int {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return fds
}

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

func recvNonblockingRaw(fd int, payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	read, _, errno := unix.RawSyscall6(
		unix.SYS_RECVFROM,
		uintptr(fd),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unix.MSG_DONTWAIT),
		0,
		0,
	)
	runtime.KeepAlive(payload)
	if errno != 0 {
		return 0, errno
	}
	return int(read), nil
}

func TestSendmsgNonblockingRaw(t *testing.T) {
	fds := newNonblockingDatagramSocketpair(t)
	for _, size := range []int{1, 4096, 64 * 1024} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		written, err := sendmsgNonblockingRaw(fds[0], payload, unix.MSG_NOSIGNAL)
		if err != nil {
			t.Fatalf("send %d bytes: %v", size, err)
		}
		if written != len(payload) {
			t.Fatalf("send %d bytes: wrote %d", size, written)
		}
		received := make([]byte, len(payload))
		read, err := recvNonblockingRaw(fds[1], received)
		if err != nil {
			t.Fatalf("receive %d bytes: %v", size, err)
		}
		if read != len(payload) || !bytes.Equal(received, payload) {
			t.Fatalf("receive %d bytes: read=%d equal=%v", size, read, bytes.Equal(received, payload))
		}
	}
}

func TestSendmsgNonblockingRawErrors(t *testing.T) {
	fds := newNonblockingDatagramSocketpair(t)
	payload := make([]byte, 4096)
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	for attempts := 0; ; attempts++ {
		if attempts > 1<<16 {
			t.Fatal("nonblocking send never reached EAGAIN")
		}
		_, err := sendmsgNonblockingRaw(fds[0], payload, unix.MSG_NOSIGNAL)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if err != nil {
			t.Fatalf("fill send buffer: %v", err)
		}
	}

	if written, err := sendmsgNonblockingRaw(-1, payload, unix.MSG_NOSIGNAL); written != 0 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid fd = (%d, %v); want (0, EBADF)", written, err)
	}
	if written, err := sendmsgNonblockingRaw(-1, nil, unix.MSG_NOSIGNAL); written != 0 || err != nil {
		t.Fatalf("empty payload = (%d, %v); want (0, nil)", written, err)
	}
}

func TestSendmsgNonblockingRawStream(t *testing.T) {
	fds := newNonblockingStreamSocketpair(t)
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	written, err := sendmsgNonblockingRaw(fds[0], payload, unix.MSG_NOSIGNAL)
	if err != nil || written != len(payload) {
		t.Fatalf("stream send = (%d, %v)", written, err)
	}
	received := make([]byte, len(payload))
	read, err := recvNonblockingRaw(fds[1], received)
	if err != nil || read != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("stream receive = (%d, %v), equal=%v", read, err, bytes.Equal(received, payload))
	}

	if err := unix.Close(fds[1]); err != nil {
		t.Fatal(err)
	}
	if written, err = sendmsgNonblockingRaw(fds[0], payload, unix.MSG_NOSIGNAL); written != 0 || err == nil {
		t.Fatalf("closed peer send = (%d, %v); want an error without SIGPIPE", written, err)
	}
}

func benchmarkAdvancedUringOwnerSendmsg(b *testing.B, raw bool) {
	fds := newNonblockingDatagramSocketpair(b)
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
			written, err = sendmsgNonblockingRaw(fds[0], payload, unix.MSG_NOSIGNAL)
		} else {
			written, err = unix.SendmsgN(fds[0], payload, nil, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
		}
		if err != nil || written != len(payload) {
			b.Fatalf("send = (%d, %v)", written, err)
		}
		read, err := recvNonblockingRaw(fds[1], received)
		if err != nil || read != len(payload) {
			b.Fatalf("receive = (%d, %v)", read, err)
		}
	}
}

func BenchmarkAdvancedUringOwnerSendmsgN(b *testing.B) {
	benchmarkAdvancedUringOwnerSendmsg(b, false)
}

func BenchmarkAdvancedUringOwnerRawSendmsg(b *testing.B) {
	benchmarkAdvancedUringOwnerSendmsg(b, true)
}
