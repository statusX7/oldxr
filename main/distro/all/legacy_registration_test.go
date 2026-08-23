package all

import (
	"testing"

	"github.com/xtls/xray-core/common/serial"
)

func TestLegacyTypesRegistered(t *testing.T) {
	for _, messageType := range []string{
		"xray.proxy.mtproto.ServerConfig",
		"xray.transport.internet.xtls.Config",
	} {
		if _, err := serial.GetInstance(messageType); err != nil {
			t.Fatalf("legacy message type %q is not registered: %v", messageType, err)
		}
	}
}
