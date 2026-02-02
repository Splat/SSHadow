package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sshmon/monitor"
	"sshmon/proxy"
)

func main() {
	// Mode selection
	mode := flag.String("mode", "proxy", "Operating mode: proxy, logmon, or hybrid")

	// Proxy mode options
	listenAddr := flag.String("listen", ":2222", "SSH proxy listen address (proxy/hybrid mode)")
	targetAddr := flag.String("target", "localhost:22", "Target SSH server address (proxy/hybrid mode)")
	hostKey := flag.String("hostkey", "", "Path to SSH host private key (proxy/hybrid mode)")

	// Log monitor options
	logSource := flag.String("log", "/var/log/auth.log", "Log source: file path or 'journald' (logmon/hybrid mode)")

	// Common options
	metricsAddr := flag.String("metrics", ":9090", "Metrics HTTP server address")

	flag.Parse()

	// Validate mode
	if *mode != "proxy" && *mode != "logmon" && *mode != "hybrid" {
		log.Fatalf("Invalid mode: %s. Must be 'proxy', 'logmon', or 'hybrid'", *mode)
	}

	// Validate required options based on mode
	if (*mode == "proxy" || *mode == "hybrid") && *hostKey == "" {
		log.Fatal("Host key is required for proxy/hybrid mode (-hostkey flag)")
	}

	// Create shared connection tracker
	tracker := monitor.NewTracker()

	// Start metrics server
	go monitor.ServeMetrics(*metricsAddr, tracker)
	log.Printf("Metrics server listening on %s", *metricsAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	// Start components based on mode
	switch *mode {
	case "proxy":
		runProxyMode(ctx, *listenAddr, *targetAddr, *hostKey, tracker)

	case "logmon":
		runLogMonMode(ctx, *logSource, tracker)

	case "hybrid":
		// Run both proxy and log monitor
		go func() {
			runProxyMode(ctx, *listenAddr, *targetAddr, *hostKey, tracker)
		}()
		runLogMonMode(ctx, *logSource, tracker)
	}
}

func runProxyMode(ctx context.Context, listenAddr, targetAddr, hostKey string, tracker *monitor.Tracker) {
	srv, err := proxy.NewServer(listenAddr, targetAddr, hostKey, tracker)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	log.Printf("[proxy] SSH proxy listening on %s, forwarding to %s", listenAddr, targetAddr)
	log.Printf("[proxy] Note: Public key/certificate auth forwarding requires -A flag (future enhancement)")

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Printf("[proxy] Server error: %v", err)
	}
}

func runLogMonMode(ctx context.Context, logSource string, tracker *monitor.Tracker) {
	watcher := monitor.NewLogWatcher(logSource, tracker)

	log.Printf("[logmon] Monitoring sshd logs from: %s", logSource)

	if err := watcher.Watch(ctx); err != nil {
		log.Printf("[logmon] Watcher error: %v", err)
	}
}
