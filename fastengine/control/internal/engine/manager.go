package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"oldxr.local/phase6/fastss/internal/config"
	"oldxr.local/phase6/fastss/internal/panel"
)

type managedNode struct {
	config config.Node
	panel  *panel.Client
	engine *Node
}

type Manager struct {
	nodes []*managedNode
}

func NewManager(nodes []config.Node, features Features, replayCapacity int) (*Manager, error) {
	replay := NewReplayFilter(replayCapacity)
	manager := &Manager{}
	for nodeIndex, nodeConfig := range nodes {
		rules, err := LoadRules(nodeConfig.API.RuleListPath)
		if err != nil {
			return nil, fmt.Errorf("node %d rules: %w", nodeConfig.API.NodeID, err)
		}
		speedBytes := int64(nodeConfig.API.SpeedLimit * 1_000_000 / 8)
		manager.nodes = append(manager.nodes, &managedNode{
			config: nodeConfig,
			panel:  panel.New(nodeConfig.API.APIHost, nodeConfig.API.APIKey, nodeConfig.API.NodeID, nodeConfig.API.Timeout),
			engine: NewNode(NodeOptions{
				NodeID: nodeConfig.API.NodeID, ReplayScope: uint64(nodeIndex + 1), ListenIP: nodeConfig.Controller.ListenIP, SendIP: nodeConfig.Controller.SendIP,
				SpeedBytes: speedBytes, DeviceLimit: nodeConfig.API.DeviceLimit, Features: features, Rules: rules, Replay: replay,
			}),
		})
	}
	return manager, nil
}

func (m *Manager) Start(ctx context.Context) error {
	for _, managed := range m.nodes {
		users, _, err := managed.panel.FetchUsers(ctx)
		if err != nil {
			return fmt.Errorf("node %d initial users: %w", managed.config.API.NodeID, err)
		}
		if err := managed.engine.UpdateUsers(users); err != nil {
			return fmt.Errorf("node %d build users: %w", managed.config.API.NodeID, err)
		}
	}

	if os.Getenv("FASTSS_IO_ENGINE") == "legacy" {
		return m.startLegacy(ctx)
	}
	engines := make([]*Node, 0, len(m.nodes))
	for _, managed := range m.nodes {
		go m.controlLoop(ctx, managed)
		engines = append(engines, managed.engine)
	}
	return runGnetNodes(ctx, engines)
}

func (m *Manager) startLegacy(ctx context.Context) error {
	errCh := make(chan error, len(m.nodes))
	for _, managed := range m.nodes {
		managed := managed
		go func() { errCh <- managed.engine.Start(ctx) }()
		go m.controlLoop(ctx, managed)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (m *Manager) controlLoop(ctx context.Context, managed *managedNode) {
	interval := time.Duration(managed.config.Controller.UpdatePeriodic) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.flushTraffic(context.Background(), managed)
			return
		case <-ticker.C:
			users, unchanged, err := managed.panel.FetchUsers(ctx)
			if err != nil {
				log.Printf("node %d user refresh failed: %v", managed.config.API.NodeID, err)
			} else if !unchanged {
				if err := managed.engine.UpdateUsers(users); err != nil {
					log.Printf("node %d user update rejected: %v", managed.config.API.NodeID, err)
				}
			}
			m.flushTraffic(ctx, managed)
		}
	}
}

func (m *Manager) flushTraffic(ctx context.Context, managed *managedNode) {
	if !managed.engine.options.Features.Traffic || managed.config.Controller.DisableUploadTraffic {
		return
	}
	traffic := managed.engine.TrafficSnapshot()
	if len(traffic) == 0 {
		return
	}
	if err := managed.panel.SubmitTraffic(ctx, traffic); err != nil {
		managed.engine.RestoreTraffic(traffic)
		log.Printf("node %d traffic submit failed: %v", managed.config.API.NodeID, err)
	}
}

func (m *Manager) Stats() []NodeStats {
	stats := make([]NodeStats, len(m.nodes))
	for i, node := range m.nodes {
		stats[i] = node.engine.Stats()
	}
	return stats
}

func (m *Manager) Registered() int {
	total := 0
	for _, stat := range m.Stats() {
		total += stat.Registered
	}
	return total
}

func (m *Manager) WaitReady(ctx context.Context) error {
	for {
		ready := true
		for _, node := range m.nodes {
			if node.engine.live.Load() == nil {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
