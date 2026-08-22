package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"oldxr.local/phase6/fastss/internal/config"
	"oldxr.local/phase6/fastss/internal/engine"
)

func main() {
	configPath := flag.String("config", "config.yml", "oldxr config.yml path")
	pprofAddr := flag.String("pprof", "127.0.0.1:6062", "pprof and prototype metrics listen address")
	replayCapacity := flag.Int("replay-capacity", 1_000_000, "shared replay entries")
	traffic := flag.Bool("traffic", true, "enable direct traffic counters and panel submit")
	limiter := flag.Bool("limiter", true, "enable per-user SpeedLimit")
	device := flag.Bool("device", true, "enable DeviceLimit admission")
	rules := flag.Bool("rules", true, "enable local rule checks")
	flag.Parse()

	nodes, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	manager, err := engine.NewManager(nodes, engine.Features{Traffic: *traffic, Limiter: *limiter, Device: *device, Rule: *rules}, *replayCapacity)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.Handle("/debug/pprof/profile", http.DefaultServeMux)
	mux.HandleFunc("/phase6/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"registered": manager.Registered(), "nodes": manager.Stats()})
	})
	go func() {
		if err := http.ListenAndServe(*pprofAddr, mux); err != nil {
			log.Printf("metrics server stopped: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fmt.Printf("oldxr Phase 6 FastSS prototype: nodes=%d traffic=%t limiter=%t device=%t rules=%t\n", len(nodes), *traffic, *limiter, *device, *rules)
	if err := manager.Start(ctx); err != nil {
		log.Fatal(err)
	}
}
