package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"oldxr.local/phase6/fastss/internal/config"
	"oldxr.local/phase6/fastss/internal/panel"
)

type normalizedUser struct {
	UID      int    `json:"uid"`
	Password string `json:"password"`
}

type userUpdate struct {
	Site  int              `json:"site"`
	Users []normalizedUser `json:"users"`
}

type trafficRecord struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type trafficRequest struct {
	Site    int             `json:"site"`
	Traffic []trafficRecord `json:"traffic,omitempty"`
}

type trafficResponse struct {
	Site    int             `json:"site"`
	Traffic []trafficRecord `json:"traffic"`
}

type engineClient struct {
	base string
	http *http.Client
}

func (c *engineClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *engineClient) post(ctx context.Context, path string, request, response any) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	body, err := c.do(req)
	if err != nil {
		return err
	}
	if response != nil {
		if err := json.Unmarshal(body, response); err != nil {
			return fmt.Errorf("decode engine response: %w", err)
		}
	}
	return nil
}

func (c *engineClient) do(req *http.Request) ([]byte, error) {
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("engine %s %s: status=%d body=%q", req.Method, req.URL.Path, res.StatusCode, body)
	}
	return body, nil
}

type managedSite struct {
	site   int
	node   config.Node
	panel  *panel.Client
	users  []panel.User
	port   int
	engine *engineClient
}

func normalizeUsers(site int, users []panel.User) (userUpdate, int, error) {
	if len(users) == 0 {
		return userUpdate{}, 0, errors.New("panel returned no Shadowsocks users")
	}
	port := users[0].Port
	update := userUpdate{Site: site, Users: make([]normalizedUser, 0, len(users))}
	seen := make(map[int]struct{}, len(users))
	for _, user := range users {
		if user.UID <= 0 || user.Password == "" || user.Port != port || !strings.EqualFold(user.Cipher, "aes-128-gcm") {
			return userUpdate{}, 0, fmt.Errorf("site %d has unsupported Shadowsocks user uid=%d port=%d cipher=%q", site, user.UID, user.Port, user.Cipher)
		}
		if _, exists := seen[user.UID]; exists {
			return userUpdate{}, 0, fmt.Errorf("site %d has duplicate UID %d", site, user.UID)
		}
		seen[user.UID] = struct{}{}
		update.Users = append(update.Users, normalizedUser{UID: user.UID, Password: user.Password})
	}
	return update, port, nil
}

func (s *managedSite) pushUsers(ctx context.Context, users []panel.User) error {
	update, port, err := normalizeUsers(s.site, users)
	if err != nil {
		return err
	}
	if port != s.port {
		return fmt.Errorf("site %d listen port changed from %d to %d; transactional listener replacement is not implemented", s.site, s.port, port)
	}
	if err := s.engine.post(ctx, "/phase7/users", update, nil); err != nil {
		return err
	}
	s.users = users
	return nil
}

func (s *managedSite) flushTraffic(ctx context.Context) error {
	var snapshot trafficResponse
	if err := s.engine.post(ctx, "/phase7/traffic/take", trafficRequest{Site: s.site}, &snapshot); err != nil {
		return err
	}
	if len(snapshot.Traffic) == 0 {
		return nil
	}
	traffic := make([]panel.Traffic, 0, len(snapshot.Traffic))
	for _, item := range snapshot.Traffic {
		traffic = append(traffic, panel.Traffic{UID: item.UID, Upload: item.Upload, Download: item.Download})
	}
	if err := s.panel.SubmitTraffic(ctx, traffic); err != nil {
		restoreContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if restoreErr := s.engine.post(restoreContext, "/phase7/traffic/restore", trafficRequest{Site: s.site, Traffic: snapshot.Traffic}, nil); restoreErr != nil {
			return fmt.Errorf("submit traffic: %v; restore traffic: %w", err, restoreErr)
		}
		return err
	}
	return nil
}

func featureName(traffic, limiter, device, rules bool) string {
	switch {
	case traffic && limiter && device && rules:
		return "full"
	case traffic && limiter && device:
		return "traffic-limiter-device"
	case traffic && limiter:
		return "traffic-limiter"
	case traffic:
		return "traffic"
	default:
		return "none"
	}
}

func main() {
	configPath := flag.String("config", "config.yml", "oldxr config.yml path")
	engineBinary := flag.String("engine", "./oldxr-fastss-engine", "FastSS Monoio engine binary")
	engineAdmin := flag.String("engine-admin", "127.0.0.1:6063", "FastSS engine admin listen address")
	metricsAddress := flag.String("metrics", "127.0.0.1:6062", "control-plane metrics listen address")
	traffic := flag.Bool("traffic", true, "enable traffic accounting and panel submit")
	limiter := flag.Bool("limiter", true, "enable SpeedLimit")
	device := flag.Bool("device", true, "enable DeviceLimit")
	rules := flag.Bool("rules", true, "enable rules")
	coalesceUS := flag.Int("coalesce-us", 0, "legacy driver frame coalescing window in microseconds")
	flag.Parse()
	if *coalesceUS < 0 || *coalesceUS > 1000 {
		log.Fatal("coalesce-us must be between 0 and 1000")
	}

	nodes, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	engine := &engineClient{base: "http://" + *engineAdmin, http: &http.Client{Timeout: 5 * time.Second}}
	sites := make([]*managedSite, 0, len(nodes))
	ports := make([]string, 0, len(nodes))
	for index, node := range nodes {
		client := panel.New(node.API.APIHost, node.API.APIKey, node.API.NodeID, node.API.Timeout)
		users, _, err := client.FetchUsers(ctx)
		if err != nil {
			log.Fatalf("site %d initial users: %v", index+1, err)
		}
		_, port, err := normalizeUsers(index+1, users)
		if err != nil {
			log.Fatal(err)
		}
		ports = append(ports, strconv.Itoa(port))
		sites = append(sites, &managedSite{site: index + 1, node: node, panel: client, users: users, port: port, engine: engine})
	}

	listenIP := nodes[0].Controller.ListenIP
	speedMbps := nodes[0].API.SpeedLimit
	deviceLimit := nodes[0].API.DeviceLimit
	for _, node := range nodes[1:] {
		if node.Controller.ListenIP != listenIP || node.API.SpeedLimit != speedMbps || node.API.DeviceLimit != deviceLimit {
			log.Fatal("Monoio prototype currently requires identical ListenIP, SpeedLimit, and DeviceLimit across SS nodes")
		}
	}
	args := []string{
		"--listen-address", listenIP,
		"--ports", strings.Join(ports, ","),
		"--sites", strconv.Itoa(len(sites)),
		"--users", "1",
		"--revision", "0",
		"--features", featureName(*traffic, *limiter, *device, *rules),
		"--stats", *engineAdmin,
		"--speed-mbps", strconv.Itoa(int(speedMbps)),
		"--device-limit", strconv.Itoa(deviceLimit),
		"--coalesce-us", strconv.Itoa(*coalesceUS),
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
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		probeContext, probeCancel := context.WithTimeout(ctx, 250*time.Millisecond)
		_, probeErr := engine.get(probeContext, "/phase7/stats")
		probeCancel()
		if probeErr == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			log.Fatalf("FastSS engine admin did not become ready: %v", probeErr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	for _, site := range sites {
		if err := site.pushUsers(ctx, site.users); err != nil {
			cancel()
			log.Fatalf("site %d initial engine update: %v", site.site, err)
		}
	}

	var ready atomic.Bool
	ready.Store(true)
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.Handle("/debug/pprof/profile", http.DefaultServeMux)
	mux.HandleFunc("/phase7/stats", func(w http.ResponseWriter, request *http.Request) {
		body, err := engine.get(request.Context(), "/phase7/stats")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/phase7/ready", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": ready.Load(), "sites": len(sites)})
	})
	go func() {
		if err := http.ListenAndServe(*metricsAddress, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("control-plane metrics stopped: %v", err)
		}
	}()

	for _, site := range sites {
		site := site
		go func() {
			interval := time.Duration(site.node.Controller.UpdatePeriodic) * time.Second
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					users, unchanged, err := site.panel.FetchUsers(ctx)
					if err != nil {
						log.Printf("site %d user refresh: %v", site.site, err)
					} else if !unchanged {
						if err := site.pushUsers(ctx, users); err != nil {
							log.Printf("site %d engine update: %v", site.site, err)
						}
					}
					if *traffic && !site.node.Controller.DisableUploadTraffic {
						if err := site.flushTraffic(ctx); err != nil {
							log.Printf("site %d traffic flush: %v", site.site, err)
						}
					}
				}
			}
		}()
	}

	log.Printf("oldxr FastSS normalized control plane ready: sites=%d engine=%s", len(sites), *engineBinary)
	select {
	case <-ctx.Done():
		if *traffic {
			flushContext, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, site := range sites {
				if !site.node.Controller.DisableUploadTraffic {
					if err := site.flushTraffic(flushContext); err != nil {
						log.Printf("site %d final traffic flush: %v", site.site, err)
					}
				}
			}
			flushCancel()
		}
		stopEngine()
		select {
		case <-wait:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
		}
	case err := <-wait:
		if ctx.Err() == nil {
			log.Fatalf("FastSS engine exited: %v", err)
		}
	}
}
