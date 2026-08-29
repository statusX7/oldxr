package owner

import (
	"os"
	"strings"
)

// Enabled reports whether the experimental socket-owner fast path may be
// attempted. Stable releases keep the stock Xray socket lifecycle unless an
// operator explicitly opts in while validating the fast path for that host.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XRAYR_SOCKET_OWNER"))) {
	case "1", "true", "on":
		return true
	default:
		return false
	}
}
