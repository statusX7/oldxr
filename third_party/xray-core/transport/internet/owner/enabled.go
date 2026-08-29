package owner

import (
	"os"
	"strings"
)

// Enabled reports whether the socket-owner fast path may be attempted. The
// path performs per-connection capability checks and falls back losslessly;
// users can still disable every attempt explicitly for diagnostics.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XRAYR_SOCKET_OWNER"))) {
	case "0", "false", "off":
		return false
	default:
		return true
	}
}
