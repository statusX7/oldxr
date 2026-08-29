//go:build linux

package owner

import "time"

const reservationQuantum = 64 * 1024

// Reservable is the connection-bound view of a shared traffic limiter.
type Reservable interface {
	Acquire(int) (time.Duration, bool)
}

// Reservation amortizes shared-limiter clock and lock work while preserving
// the limiter's aggregate token accounting. Credits are obtained from the
// shared bucket before they can be consumed by this connection.
type Reservation struct {
	credit int
}

// Acquire obtains bytes from already-reserved connection-local credit or
// reserves another bounded quantum from the shared limiter.
func (r *Reservation) Acquire(flow Reservable, bytes int) (time.Duration, bool) {
	if bytes <= 0 {
		return 0, true
	}
	if r.credit >= bytes {
		r.credit -= bytes
		return 0, true
	}

	request := reservationQuantum
	if bytes > request {
		request = bytes
	}
	delay, ok := flow.Acquire(request)
	if !ok {
		return 0, false
	}
	r.credit += request - bytes
	return delay, true
}
