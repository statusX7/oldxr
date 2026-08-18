package mydispatcher

import (
	"context"
	"testing"

	statsapp "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/limiter"
)

type benchmarkPolicyManager struct {
	session policy.Session
}

func (*benchmarkPolicyManager) Type() interface{}                { return policy.ManagerType() }
func (*benchmarkPolicyManager) Start() error                     { return nil }
func (*benchmarkPolicyManager) Close() error                     { return nil }
func (m *benchmarkPolicyManager) ForLevel(uint32) policy.Session { return m.session }
func (*benchmarkPolicyManager) ForSystem() policy.System         { return policy.System{} }

func BenchmarkDispatcherGetLink(b *testing.B) {
	for _, test := range []struct {
		name       string
		auth       bool
		stats      bool
		speedLimit uint64
	}{
		{name: "anonymous"},
		{name: "stats-off/limiter-off", auth: true},
		{name: "stats-on/limiter-off", auth: true, stats: true},
		{name: "stats-off/limiter-on", auth: true, speedLimit: 1_000_000},
		{name: "stats-on/limiter-on", auth: true, stats: true, speedLimit: 1_000_000},
	} {
		b.Run(test.name, func(b *testing.B) {
			manager, err := statsapp.NewManager(context.Background(), &statsapp.Config{})
			if err != nil {
				b.Fatalf("NewManager: %v", err)
			}
			userList := []api.UserInfo{{UID: 42, Email: "user@example.com", SpeedLimit: test.speedLimit}}
			connectionLimiter := limiter.New()
			if err := connectionLimiter.AddInboundLimiter("node-1", 0, &userList, nil); err != nil {
				b.Fatalf("AddInboundLimiter: %v", err)
			}
			dispatcher := &DefaultDispatcher{
				policy: &benchmarkPolicyManager{session: policy.Session{Stats: policy.Stats{
					UserUplink:   test.stats,
					UserDownlink: test.stats,
				}}},
				Limiter:         connectionLimiter,
				trafficCounters: newUserTrafficCounterIndex(manager),
			}
			inboundSession := &session.Inbound{
				Source: xnet.TCPDestination(xnet.IPAddress([]byte{192, 0, 2, 1}), 12345),
				Tag:    "node-1",
			}
			if test.auth {
				inboundSession.User = &protocol.MemoryUser{Email: "node-1|user@example.com|42"}
			}
			ctx := session.ContextWithInbound(context.Background(), inboundSession)

			// Prime device, rate and stats state outside the timer.
			inbound, outbound, err := dispatcher.getLink(ctx, xnet.Network_TCP, session.SniffingRequest{})
			if err != nil {
				b.Fatalf("prime getLink: %v", err)
			}
			closeBenchmarkLink(inbound)
			closeBenchmarkLink(outbound)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				inbound, outbound, err := dispatcher.getLink(ctx, xnet.Network_TCP, session.SniffingRequest{})
				if err != nil {
					b.Fatalf("getLink: %v", err)
				}
				closeBenchmarkLink(inbound)
				closeBenchmarkLink(outbound)
			}
		})
	}
}

func closeBenchmarkLink(link *transport.Link) {
	common.Close(link.Writer)
	common.Interrupt(link.Reader)
}
