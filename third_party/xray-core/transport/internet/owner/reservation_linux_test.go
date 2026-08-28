//go:build linux

package owner

import (
	"testing"
	"time"
)

type reservationFlow struct {
	requests []int
	delay    time.Duration
	ok       bool
}

func (f *reservationFlow) Acquire(bytes int) (time.Duration, bool) {
	f.requests = append(f.requests, bytes)
	return f.delay, f.ok
}

func TestReservationAmortizesSharedLimiter(t *testing.T) {
	flow := &reservationFlow{ok: true}
	var reservation Reservation
	for index := 0; index < 16; index++ {
		if delay, ok := reservation.Acquire(flow, 4096); !ok || delay != 0 {
			t.Fatalf("Acquire() = (%v, %v), want (0, true)", delay, ok)
		}
	}
	if len(flow.requests) != 1 || flow.requests[0] != reservationQuantum {
		t.Fatalf("shared requests = %v, want [%d]", flow.requests, reservationQuantum)
	}
	if _, ok := reservation.Acquire(flow, 1); !ok {
		t.Fatal("Acquire() rejected a valid refill")
	}
	if len(flow.requests) != 2 || flow.requests[1] != reservationQuantum {
		t.Fatalf("shared requests after refill = %v", flow.requests)
	}
}

func TestReservationPreservesDelayAndReject(t *testing.T) {
	flow := &reservationFlow{delay: 25 * time.Millisecond, ok: true}
	var reservation Reservation
	delay, ok := reservation.Acquire(flow, 4096)
	if !ok || delay != flow.delay {
		t.Fatalf("Acquire() = (%v, %v), want (%v, true)", delay, ok, flow.delay)
	}

	rejected := &reservationFlow{ok: false}
	var empty Reservation
	if _, ok := empty.Acquire(rejected, 4096); ok {
		t.Fatal("Acquire() accepted a rejected shared reservation")
	}
}

func TestReservationUsesExactOversizedRequest(t *testing.T) {
	flow := &reservationFlow{ok: true}
	var reservation Reservation
	request := reservationQuantum + 1
	if _, ok := reservation.Acquire(flow, request); !ok {
		t.Fatal("Acquire() rejected an oversized request")
	}
	if len(flow.requests) != 1 || flow.requests[0] != request {
		t.Fatalf("shared requests = %v, want [%d]", flow.requests, request)
	}
}
