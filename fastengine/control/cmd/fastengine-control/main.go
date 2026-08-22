package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/statusX7/oldxr/fastengine/control/internal/config"
	"github.com/statusX7/oldxr/fastengine/control/internal/fastengine"
	"github.com/statusX7/oldxr/fastengine/control/internal/v2board"
)

type engineProtocolConfig struct {
	Type    string   `json:"type"`
	UserIDs []string `json:"user_ids"`
}

type engineListenerConfig struct {
	Address  string               `json:"address"`
	Protocol engineProtocolConfig `json:"protocol"`
}

type managedNode struct {
	engineSite int
	protocol   v2board.Protocol
	config     config.Node
	panel      *v2board.Client
	users      []v2board.User
	port       int
	rules      []string
	localRules []string
	engine     *fastengine.Client
	mu         sync.Mutex
}

func normalizeVMessUsers(users []v2board.User) ([]fastengine.VMessUser, error) {
	normalized := make([]fastengine.VMessUser, 0, len(users))
	seenUID := make(map[uint64]struct{}, len(users))
	seenID := make(map[string]struct{}, len(users))
	for _, user := range users {
		id := strings.ToLower(strings.TrimSpace(user.UUID))
		if user.UID == 0 || id == "" {
			return nil, fmt.Errorf("VMess user has an empty UID or UUID")
		}
		if user.AlterID != 0 {
			return nil, fmt.Errorf("VMess user %d uses alter_id=%d; FastVMess currently requires AEAD alter_id=0", user.UID, user.AlterID)
		}
		if _, exists := seenUID[user.UID]; exists {
			return nil, fmt.Errorf("VMess user list has duplicate UID %d", user.UID)
		}
		if _, exists := seenID[id]; exists {
			return nil, fmt.Errorf("VMess user list has duplicate UUID %q", id)
		}
		seenUID[user.UID] = struct{}{}
		seenID[id] = struct{}{}
		normalized = append(normalized, fastengine.VMessUser{UID: user.UID, ID: id})
	}
	return normalized, nil
}

func normalizeShadowsocksUsers(users []v2board.User) ([]fastengine.ShadowsocksUser, int, error) {
	if len(users) == 0 {
		return nil, 0, errors.New("V2Board cannot describe a Shadowsocks listen port with an empty legacy user response")
	}
	port := users[0].Port
	normalized := make([]fastengine.ShadowsocksUser, 0, len(users))
	seenUID := make(map[uint64]struct{}, len(users))
	seenPassword := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user.UID == 0 || user.Password == "" || user.Port != port || !strings.EqualFold(user.Cipher, "aes-128-gcm") {
			return nil, 0, fmt.Errorf("unsupported Shadowsocks user uid=%d port=%d cipher=%q", user.UID, user.Port, user.Cipher)
		}
		if _, exists := seenUID[user.UID]; exists {
			return nil, 0, fmt.Errorf("Shadowsocks user list has duplicate UID %d", user.UID)
		}
		if _, exists := seenPassword[user.Password]; exists {
			return nil, 0, fmt.Errorf("Shadowsocks user list has duplicate credentials for UID %d", user.UID)
		}
		seenUID[user.UID] = struct{}{}
		seenPassword[user.Password] = struct{}{}
		normalized = append(normalized, fastengine.ShadowsocksUser{UID: user.UID, Password: user.Password})
	}
	if port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid Shadowsocks listen port %d", port)
	}
	return normalized, port, nil
}

func validateVMessNode(info v2board.NodeInfo) error {
	if !strings.EqualFold(info.Network, "tcp") {
		return fmt.Errorf("VMess transport %q requires LegacyEngine", info.Network)
	}
	if info.Security != "" && !strings.EqualFold(info.Security, "none") {
		return fmt.Errorf("VMess transport security %q requires LegacyEngine", info.Security)
	}
	if info.HeaderType != "" && !strings.EqualFold(info.HeaderType, "none") {
		return fmt.Errorf("VMess TCP header %q requires LegacyEngine", info.HeaderType)
	}
	return nil
}

func readLocalRules(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		// Preserve the legacy V2Board adapter behavior: a missing optional
		// local rule file is logged but does not prevent the node from starting.
		log.Printf("打开本地审计规则失败：%v", err)
		return nil, nil
	}
	defer file.Close()
	rules := make([]string, 0, 16)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pattern := scanner.Text()
		if _, err := regexp.Compile(pattern); err != nil {
			log.Printf("忽略无效的本地审计规则：%v", err)
			continue
		}
		rules = append(rules, pattern)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func discover(ctx context.Context, nodes []config.Node, engine *fastengine.Client) ([]*managedNode, error) {
	managed := make([]*managedNode, 0, len(nodes))
	vmessSite := 0
	ssSite := 0
	for _, node := range nodes {
		protocol, err := v2board.ProtocolFromNodeType(node.API.NodeType)
		if err != nil {
			return nil, err
		}
		client := v2board.New(node.API.APIHost, node.API.APIKey, node.API.NodeID, node.API.Timeout, protocol)
		current := &managedNode{protocol: protocol, config: node, panel: client, engine: engine}
		if protocol == v2board.VMess {
			vmessSite++
			current.engineSite = vmessSite
			info, err := client.FetchNode(ctx)
			if err != nil {
				return nil, fmt.Errorf("VMess site %d node config: %w", vmessSite, err)
			}
			if err := validateVMessNode(info); err != nil {
				return nil, fmt.Errorf("VMess site %d: %w", vmessSite, err)
			}
			current.port = info.Port
			current.rules = info.Rules
		} else {
			ssSite++
			current.engineSite = ssSite
		}
		current.localRules, err = readLocalRules(node.API.RuleListPath)
		if err != nil {
			return nil, fmt.Errorf("%s site %d local rules: %w", protocol, current.engineSite, err)
		}
		users, _, err := client.FetchUsers(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s site %d initial users: %w", protocol, current.engineSite, err)
		}
		if protocol == v2board.VMess {
			if _, err := normalizeVMessUsers(users); err != nil {
				return nil, fmt.Errorf("VMess site %d: %w", current.engineSite, err)
			}
		} else {
			_, port, err := normalizeShadowsocksUsers(users)
			if err != nil {
				return nil, fmt.Errorf("Shadowsocks site %d: %w", current.engineSite, err)
			}
			current.port = port
		}
		current.users = users
		managed = append(managed, current)
	}
	return managed, nil
}

func (node *managedNode) pushUsers(ctx context.Context, users []v2board.User) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.protocol == v2board.VMess {
		normalized, err := normalizeVMessUsers(users)
		if err != nil {
			return err
		}
		if err := node.engine.ReplaceVMessUsers(ctx, node.engineSite, normalized); err != nil {
			return err
		}
	} else {
		normalized, port, err := normalizeShadowsocksUsers(users)
		if err != nil {
			return err
		}
		if port != node.port {
			return fmt.Errorf("Shadowsocks site %d listen port changed from %d to %d; transactional listener replacement requires LegacyEngine", node.engineSite, node.port, port)
		}
		if err := node.engine.ReplaceShadowsocksUsers(ctx, node.engineSite, normalized); err != nil {
			return err
		}
	}
	node.users = append(node.users[:0], users...)
	return nil
}

func (node *managedNode) normalizedRules() ([]string, error) {
	if node.config.Controller.DisableGetRule {
		return nil, nil
	}
	rules := append(make([]string, 0, len(node.localRules)+len(node.rules)), node.localRules...)
	for _, rule := range node.rules {
		rules = append(rules, strings.TrimPrefix(rule, "regexp:"))
	}
	return rules, nil
}

func (node *managedNode) pushPolicy(ctx context.Context) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.pushPolicyLocked(ctx)
}

func (node *managedNode) pushPolicyLocked(ctx context.Context) error {
	rules, err := node.normalizedRules()
	if err != nil {
		return err
	}
	speedBytesPerSecond := uint64(node.config.API.SpeedLimit * 1_000_000 / 8)
	if node.protocol == v2board.VMess {
		return node.engine.UpdateVMessPolicy(ctx, node.engineSite, speedBytesPerSecond, node.config.API.DeviceLimit, rules)
	}
	return node.engine.UpdateShadowsocksPolicy(ctx, node.engineSite, speedBytesPerSecond, node.config.API.DeviceLimit, rules)
}

func (node *managedNode) refreshVMessPolicy(ctx context.Context) error {
	if node.protocol != v2board.VMess {
		return nil
	}
	info, err := node.panel.FetchNode(ctx)
	if err != nil {
		return err
	}
	if err := validateVMessNode(info); err != nil {
		return err
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if info.Port != node.port {
		return fmt.Errorf("listen port changed from %d to %d; transactional listener replacement requires LegacyEngine", node.port, info.Port)
	}
	previous := node.rules
	node.rules = append([]string(nil), info.Rules...)
	if err := node.pushPolicyLocked(ctx); err != nil {
		node.rules = previous
		return err
	}
	return nil
}

func (node *managedNode) takeTraffic(ctx context.Context) ([]fastengine.Traffic, error) {
	if node.protocol == v2board.VMess {
		return node.engine.TakeVMessTraffic(ctx, node.engineSite)
	}
	return node.engine.TakeShadowsocksTraffic(ctx, node.engineSite)
}

func (node *managedNode) restoreTraffic(ctx context.Context, traffic []fastengine.Traffic) error {
	if node.protocol == v2board.VMess {
		return node.engine.RestoreVMessTraffic(ctx, node.engineSite, traffic)
	}
	return node.engine.RestoreShadowsocksTraffic(ctx, node.engineSite, traffic)
}

func (node *managedNode) flushTraffic(ctx context.Context) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	traffic, err := node.takeTraffic(ctx)
	if err != nil || len(traffic) == 0 {
		return err
	}
	panelTraffic := make([]v2board.Traffic, 0, len(traffic))
	for _, item := range traffic {
		panelTraffic = append(panelTraffic, v2board.Traffic{UID: item.UID, Upload: item.Upload, Download: item.Download})
	}
	if err := node.panel.SubmitTraffic(ctx, panelTraffic); err == nil {
		return nil
	} else {
		restoreContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if restoreErr := node.restoreTraffic(restoreContext, traffic); restoreErr != nil {
			return fmt.Errorf("submit traffic: %v; restore traffic: %w", err, restoreErr)
		}
		return err
	}
}

func engineInputs(nodes []*managedNode) ([]engineListenerConfig, string, []string, error) {
	var vmess []engineListenerConfig
	var ssAddress string
	var ssPorts []string
	for _, node := range nodes {
		if node.config.API.SpeedLimit < 0 || node.config.API.DeviceLimit < 0 {
			return nil, "", nil, errors.New("negative SpeedLimit or DeviceLimit is invalid")
		}
		if node.protocol == v2board.VMess {
			users, err := normalizeVMessUsers(node.users)
			if err != nil {
				return nil, "", nil, err
			}
			ids := make([]string, 0, len(users))
			for _, user := range users {
				ids = append(ids, user.ID)
			}
			vmess = append(vmess, engineListenerConfig{
				Address:  net.JoinHostPort(node.config.Controller.ListenIP, strconv.Itoa(node.port)),
				Protocol: engineProtocolConfig{Type: "vmess", UserIDs: ids},
			})
			continue
		}
		if ssAddress == "" {
			ssAddress = node.config.Controller.ListenIP
		} else if ssAddress != node.config.Controller.ListenIP {
			return nil, "", nil, errors.New("multiple Shadowsocks ListenIP values require LegacyEngine")
		}
		ssPorts = append(ssPorts, strconv.Itoa(node.port))
	}
	if ssAddress == "" {
		ssAddress = "127.0.0.1"
	}
	return vmess, ssAddress, ssPorts, nil
}

func writeEngineConfig(configs []engineListenerConfig) (string, error) {
	file, err := os.CreateTemp("", "oldxr-fastengine-*.json")
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := func(result error) (string, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return "", result
	}
	if err := file.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if err := json.NewEncoder(file).Encode(configs); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func waitForEngine(ctx context.Context, client *fastengine.Client, exited <-chan error) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		probeContext, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		err := client.Ping(probeContext)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case exitErr := <-exited:
			return fmt.Errorf("FastEngine exited before admin became ready: %w", exitErr)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("FastEngine admin did not become ready: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func runNode(ctx context.Context, node *managedNode, offset, total int) {
	interval := time.Duration(node.config.Controller.UpdatePeriodic) * time.Second
	initialDelay := interval * time.Duration(offset) / time.Duration(total)
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := node.refreshVMessPolicy(ctx); err != nil {
				log.Printf("%s site %d node/rule refresh: %v", node.protocol, node.engineSite, err)
			}
			users, unchanged, err := node.panel.FetchUsers(ctx)
			if err != nil {
				log.Printf("%s site %d user refresh: %v", node.protocol, node.engineSite, err)
			} else if !unchanged {
				if err := node.pushUsers(ctx, users); err != nil {
					log.Printf("%s site %d engine update: %v", node.protocol, node.engineSite, err)
				}
			}
			if !node.config.Controller.DisableUploadTraffic {
				if err := node.flushTraffic(ctx); err != nil {
					log.Printf("%s site %d traffic flush: %v", node.protocol, node.engineSite, err)
				}
			}
			timer.Reset(interval)
		}
	}
}

func main() {
	configPath := flag.String("config", "config.yml", "oldxr config.yml path")
	engineBinary := flag.String("engine", "../fastvmess-uring/target/release/oldxr-phase7-fastvmess-uring", "FastEngine binary")
	adminSocket := flag.String("engine-admin", "/tmp/oldxr-phase7-fastengine.sock", "FastEngine Unix admin socket")
	metricsAddress := flag.String("metrics", "127.0.0.1:6062", "control-plane metrics address")
	debugStatus := flag.String("engine-debug-status", "", "optional FastEngine debug status JSON")
	flag.Parse()

	nodes, err := config.LoadFastEngine(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	engine := fastengine.New(*adminSocket)
	managed, err := discover(ctx, nodes, engine)
	if err != nil {
		log.Fatal(err)
	}
	vmessConfigs, ssAddress, ssPorts, err := engineInputs(managed)
	if err != nil {
		log.Fatal(err)
	}
	engineConfigPath, err := writeEngineConfig(vmessConfigs)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(engineConfigPath)

	args := []string{
		"--config", engineConfigPath,
		"--supervised",
		"--features", "full",
		"--speed-mbps", "0",
		"--device-limit", "0",
		"--ss-listen-address", ssAddress,
		"--ss-ports", strings.Join(ssPorts, ","),
		"--ss-sites", strconv.Itoa(len(ssPorts)),
		"--ss-users", "1",
		"--ss-revision", "0",
		"--admin-socket", *adminSocket,
	}
	if *debugStatus != "" {
		args = append(args, "--debug-status-path", *debugStatus)
	}
	engineContext, stopEngine := context.WithCancel(context.Background())
	defer stopEngine()
	command := exec.CommandContext(engineContext, *engineBinary, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		log.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	if err := waitForEngine(ctx, engine, exited); err != nil {
		stopEngine()
		log.Fatal(err)
	}
	for _, node := range managed {
		if err := node.pushPolicy(ctx); err != nil {
			stopEngine()
			log.Fatalf("%s site %d initial policy update: %v", node.protocol, node.engineSite, err)
		}
		if err := node.pushUsers(ctx, node.users); err != nil {
			stopEngine()
			log.Fatalf("%s site %d initial engine update: %v", node.protocol, node.engineSite, err)
		}
	}

	var ready atomic.Bool
	ready.Store(true)
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.Handle("/debug/pprof/profile", http.DefaultServeMux)
	mux.HandleFunc("/phase7/ready", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"ready": ready.Load(), "nodes": len(managed), "vmess": len(vmessConfigs), "shadowsocks": len(ssPorts)})
	})
	mux.HandleFunc("/phase7/stats", func(writer http.ResponseWriter, request *http.Request) {
		result := make(map[string]any)
		for _, protocol := range []string{"vmess", "shadowsocks"} {
			var status map[string]any
			if err := engine.Status(request.Context(), protocol, &status); err != nil {
				http.Error(writer, err.Error(), http.StatusBadGateway)
				return
			}
			result[protocol] = status
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(result)
	})
	metrics := &http.Server{Addr: *metricsAddress, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("control-plane metrics stopped: %v", err)
		}
	}()
	for index, node := range managed {
		go runNode(ctx, node, index+1, len(managed)+1)
	}

	log.Printf("oldxr Phase 7 normalized dual control plane ready: nodes=%d VMess=%d Shadowsocks=%d", len(managed), len(vmessConfigs), len(ssPorts))
	select {
	case <-ctx.Done():
		ready.Store(false)
		flushContext, flushCancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, node := range managed {
			if !node.config.Controller.DisableUploadTraffic {
				if err := node.flushTraffic(flushContext); err != nil {
					log.Printf("%s site %d final traffic flush: %v", node.protocol, node.engineSite, err)
				}
			}
		}
		flushCancel()
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		_ = metrics.Shutdown(shutdownContext)
		shutdownCancel()
		stopEngine()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
		}
	case err := <-exited:
		ready.Store(false)
		if ctx.Err() == nil {
			log.Fatalf("FastEngine exited: %v", err)
		}
	}
}
